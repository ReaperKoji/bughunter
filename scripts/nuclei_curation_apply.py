#!/usr/bin/env python3
"""Apply nuclei curation results to build a curated templates directory."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Any

import yaml


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _iter_template_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    files = list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
    return sorted({f for f in files if f.is_file()})


def _symlink_or_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        os.symlink(src, dst)
    except Exception:
        shutil.copy2(src, dst)


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply curated nuclei templates")
    parser.add_argument("--curation-json", default="data/reports/nuclei_curation.json")
    parser.add_argument("--templates-root", default="templates/nuclei")
    parser.add_argument("--out-dir", default="templates/nuclei-curated")
    parser.add_argument("--high-out", default="data/processed/nuclei_templates_high.txt")
    parser.add_argument("--missing-out", default="data/processed/nuclei_templates_missing.txt")
    parser.add_argument("--curation-config", default="config/nuclei-curation.yaml")
    parser.add_argument("--bootstrap-tags", action="store_true")
    args = parser.parse_args()

    curation_path = Path(args.curation_json)
    data = _load_json(curation_path)
    high = data.get("high_signal", []) if isinstance(data, dict) else []
    high_ids = [str(item.get("template_id", "")).strip() for item in high if isinstance(item, dict)]
    high_ids = [x for x in high_ids if x]

    root = Path(args.templates_root)
    curated_dir = Path(args.out_dir)
    templates = _iter_template_files(root)
    id_map: dict[str, Path] = {}
    tag_map: dict[str, set[str]] = {}
    for path in templates:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        tid = str(doc.get("id", "")).strip()
        if not tid or tid in id_map:
            continue
        id_map[tid] = path
        info = doc.get("info", {}) if isinstance(doc.get("info"), dict) else {}
        tags = info.get("tags", [])
        tag_set: set[str] = set()
        if isinstance(tags, list):
            tag_set = {str(t).strip().lower() for t in tags if str(t).strip()}
        elif isinstance(tags, str):
            tag_set = {t.strip().lower() for t in tags.split(",") if t.strip()}
        tag_map[tid] = tag_set

    if not high_ids and args.bootstrap_tags:
        cfg = yaml.safe_load(Path(args.curation_config).read_text(encoding="utf-8")) or {}
        high_tags = {str(t).strip().lower() for t in cfg.get("high_signal_tags", []) if str(t).strip()}
        noise_tags = {str(t).strip().lower() for t in cfg.get("noise_tags", []) if str(t).strip()}
        for tid, tags in tag_map.items():
            if tags & high_tags and not (tags & noise_tags):
                high_ids.append(tid)

    if not high_ids:
        print("[nuclei-curation-apply] no_high_signal_templates")
        return 2

    if curated_dir.exists():
        shutil.rmtree(curated_dir)
    curated_dir.mkdir(parents=True, exist_ok=True)

    missing: list[str] = []
    applied = 0
    for tid in high_ids:
        src = id_map.get(tid)
        if not src:
            missing.append(tid)
            continue
        rel = src.relative_to(root)
        dst = curated_dir / rel
        _symlink_or_copy(src, dst)
        applied += 1

    Path(args.high_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.high_out).write_text("\n".join(high_ids) + "\n", encoding="utf-8")
    Path(args.missing_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.missing_out).write_text("\n".join(missing) + "\n", encoding="utf-8")

    print(f"[nuclei-curation-apply] templates={applied} missing={len(missing)} out={curated_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
