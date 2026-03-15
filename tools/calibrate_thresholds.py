#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from typing import Any, Iterable
from datetime import datetime, timezone


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _is_positive_label(raw: Any) -> bool:
    text = str(raw).strip().lower()
    return text in {"1", "true", "yes", "pos", "positive", "poc_valid", "valid"}


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    k = (len(values) - 1) * pct
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return values[int(k)]
    d0 = values[int(f)] * (c - k)
    d1 = values[int(c)] * (k - f)
    return d0 + d1


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def _evaluate(rows: list[dict[str, float]], min_sens: float, min_body_diff: float, max_baseline: float) -> dict[str, float]:
    tp = fp = tn = fn = 0
    for row in rows:
        label = row["label"]
        sens = row["sensitivity_score"]
        body_diff = row["body_diff_ratio"]
        baseline = row["baseline_score"]
        pred = sens >= min_sens and body_diff >= min_body_diff and baseline <= max_baseline
        if label and pred:
            tp += 1
        elif label and not pred:
            fn += 1
        elif not label and pred:
            fp += 1
        else:
            tn += 1
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fpr = _safe_div(fp, fp + tn)
    return {
        "tp": float(tp),
        "fp": float(fp),
        "tn": float(tn),
        "fn": float(fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def _minimal_pdf(path: Path, lines: list[str]) -> None:
    # Minimal PDF with a single page and simple text content.
    # Avoids external dependencies.
    text = "\n".join(lines).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = f"BT /F1 10 Tf 50 750 Td ({text}) Tj ET"
    objects = []
    objects.append("1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj")
    objects.append("2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj")
    objects.append("3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj")
    objects.append(f"4 0 obj << /Length {len(content)} >> stream\n{content}\nendstream endobj")
    objects.append("5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj")

    xref = ["0000000000 65535 f "]
    offset = 0
    body = "%PDF-1.4\n"
    offset += len(body.encode("utf-8"))
    for obj in objects:
        xref.append(f"{offset:010d} 00000 n ")
        obj_str = obj + "\n"
        body += obj_str
        offset += len(obj_str.encode("utf-8"))
    xref_offset = offset
    xref_table = "xref\n0 {count}\n".format(count=len(xref)) + "\n".join(xref) + "\n"
    trailer = f"trailer << /Size {len(xref)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
    body += xref_table + trailer
    path.write_bytes(body.encode("utf-8"))


def calibrate(input_path: Path, report_path: Path, pdf_path: Path) -> dict[str, float]:
    rows: list[dict[str, float]] = []
    with input_path.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for raw in reader:
            label = _is_positive_label(raw.get("label"))
            sens = raw.get("sensitivity_score")
            signal = raw.get("signal_strength")
            baseline = _as_float(raw.get("baseline_score"), 0.0)
            body_diff = raw.get("body_diff_ratio")
            body_sim = raw.get("body_similarity_score")

            if sens is not None and str(sens).strip() != "":
                sensitivity_score = _as_float(sens, 0.0)
            elif signal is not None and str(signal).strip() != "":
                sensitivity_score = _as_float(signal, 0.0)
            elif body_diff is not None and str(body_diff).strip() != "":
                sensitivity_score = _as_float(body_diff, 0.0)
            else:
                sensitivity_score = 1.0 - _as_float(body_sim, 0.0)

            if body_diff is not None and str(body_diff).strip() != "":
                body_diff_ratio = _as_float(body_diff, 0.0)
            else:
                body_diff_ratio = 1.0 - _as_float(body_sim, 0.0)

            rows.append(
                {
                    "label": 1.0 if label else 0.0,
                    "sensitivity_score": max(0.0, min(1.0, sensitivity_score)),
                    "baseline_score": max(0.0, min(1.0, baseline)),
                    "body_diff_ratio": max(0.0, min(1.0, body_diff_ratio)),
                }
            )

    positives = [r for r in rows if r["label"] == 1.0]
    negatives = [r for r in rows if r["label"] == 0.0]
    sens_pos = [r["sensitivity_score"] for r in positives]
    body_pos = [r["body_diff_ratio"] for r in positives]
    baseline_neg = [r["baseline_score"] for r in negatives]

    min_sens = _percentile(sens_pos, 0.2) if sens_pos else 0.5
    min_body = _percentile(body_pos, 0.2) if body_pos else 0.2
    max_base = _percentile(baseline_neg, 0.8) if baseline_neg else 0.5

    candidates = []
    for s in {_percentile(sens_pos, p) for p in [0.1, 0.2, 0.3, 0.4, 0.5] if sens_pos} or {min_sens}:
        for b in {_percentile(body_pos, p) for p in [0.1, 0.2, 0.3, 0.4] if body_pos} or {min_body}:
            for base in {_percentile(baseline_neg, p) for p in [0.6, 0.7, 0.8, 0.9] if baseline_neg} or {max_base}:
                metrics = _evaluate(rows, s, b, base)
                candidates.append((metrics["f1"], s, b, base, metrics))
    ranked: list[tuple[float, float, float, float, dict[str, float]]] = []
    if candidates:
        ranked = sorted(candidates, key=lambda x: (x[0], -x[2], -x[1]), reverse=True)
        best = ranked[0]
        min_sens, min_body, max_base, best_metrics = best[1], best[2], best[3], best[4]
    else:
        best_metrics = _evaluate(rows, min_sens, min_body, max_base)

    report_lines = [
        "# Threshold Calibration Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}",
        "",
        "## Dataset",
        f"Total samples: {len(rows)}",
        f"Positives: {len(positives)}",
        f"Negatives: {len(negatives)}",
        "",
        "## Recommended Thresholds",
        f"- min_sensitivity_score: {min_sens:.2f}",
        f"- min_body_diff_ratio: {min_body:.2f}",
        f"- baseline_score_threshold (max): {max_base:.2f}",
        "",
        "## Metrics (approx)",
        f"- precision: {best_metrics['precision']:.2f}",
        f"- recall: {best_metrics['recall']:.2f}",
        f"- f1: {best_metrics['f1']:.2f}",
        f"- false_positive_rate: {best_metrics['fpr']:.2f}",
        "",
        "## Top Candidate Thresholds",
    ]

    if ranked:
        report_lines.extend(
            [
                "| rank | min_sens | min_body_diff | max_baseline | precision | recall | f1 | fpr |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for idx, (_, s, b, base, metrics) in enumerate(ranked[:5], start=1):
            report_lines.append(
                "| {rank} | {s:.2f} | {b:.2f} | {base:.2f} | {p:.2f} | {r:.2f} | {f1:.2f} | {fpr:.2f} |".format(
                    rank=idx,
                    s=s,
                    b=b,
                    base=base,
                    p=metrics["precision"],
                    r=metrics["recall"],
                    f1=metrics["f1"],
                    fpr=metrics["fpr"],
                )
            )
    else:
        report_lines.append("No candidate grid generated; using percentile defaults.")

    report_lines.extend(
        [
            "",
            "## Notes",
            "Values are derived from percentile heuristics and simple F1 optimization. Review results and adjust per program.",
        ]
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(report_lines), encoding="utf-8")

    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    _minimal_pdf(pdf_path, [line.strip("# ") for line in report_lines if line.strip()])

    return {
        "min_sensitivity_score": float(min_sens),
        "min_body_diff_ratio": float(min_body),
        "baseline_score_threshold": float(max_base),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Calibrate thresholds from labeled results")
    parser.add_argument("input_csv")
    parser.add_argument("--report", default="reports/threshold_recommendation.md")
    parser.add_argument("--pdf", default="reports/threshold_recommendation.pdf")
    args = parser.parse_args()

    result = calibrate(Path(args.input_csv), Path(args.report), Path(args.pdf))
    print("thresholds:", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
