from __future__ import annotations

import html
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hunterops.async_io import read_json, write_json, write_text
from hunterops.plugin_base import Plugin
from hunterops.templating import render_template
from hunterops.types import Finding, Task
import yaml

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

FASTLANE_MARKERS = (
    "information_disclosure",
    "info_leak",
    "open_redirect",
    "cors",
    "misconfiguration",
    "source_map",
    "path_disclosure",
    "idor_response_discrepancy",
)


async def _load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        doc = await read_json(path)
    except Exception:
        return []
    rows = doc.get("findings", []) if isinstance(doc, dict) else doc
    return [x for x in rows if isinstance(x, dict)]


def _report_username() -> str:
    direct = os.getenv("HUNTEROPS_BUG_BOUNTY_USERNAME", "").strip()
    if direct:
        return direct
    legacy = os.getenv("BUG_BOUNTY_USERNAME", "").strip()
    if legacy:
        return legacy
    return "researcher"


def _load_templates(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def _curl_from_request(request_data: dict[str, Any]) -> str:
    method = str(request_data.get("method", "GET")).upper()
    url = str(request_data.get("url", ""))
    headers = request_data.get("headers", {}) if isinstance(request_data.get("headers"), dict) else {}
    body = request_data.get("body", None)
    cmd = f"curl -i -X {method} \"{url}\""
    for hk, hv in headers.items():
        cmd += f" -H \"{str(hk)}: {str(hv)}\""
    if isinstance(body, (dict, list)):
        cmd += f" --data '{json.dumps(body, ensure_ascii=True)}'"
    elif isinstance(body, str) and body.strip():
        cmd += f" --data '{body}'"
    return cmd


def _impact_first_text(category: str, endpoint: str) -> str:
    c = str(category or "").lower()
    if any(k in c for k in ("idor", "bac", "access")):
        if any(k in endpoint.lower() for k in ("trade", "trading", "payment", "wallet", "transaction", "portfolio")):
            return "Potential unauthorized access to financial trading/payment data path with risk of account intelligence leakage and fraud enablement."
        return "Potential unauthorized object-level access that can expose sensitive user data and trust-boundary violations."
    if "leak" in c:
        return "Potential sensitive information exposure useful for account takeover chaining or targeted abuse."
    return "Potential security control weakness with direct business risk depending on affected trust boundary."


def _endpoint_url(target: str, endpoint: str) -> str:
    value = str(endpoint or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return value
    host = str(target or "").strip()
    if host.startswith("http://") or host.startswith("https://"):
        base = host
    else:
        base = f"https://{host}"
    if not value.startswith("/"):
        value = "/" + value
    parsed = urlparse(base)
    return f"{parsed.scheme}://{parsed.netloc}{value}"


def _sev(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


def _severity_rank(value: str) -> int:
    return int(SEVERITY_RANK.get(str(value or "").strip().lower(), 0))


def _builder_priority(row: dict[str, Any]) -> float:
    score = float(row.get("risk_score", 0) or 0)
    severity = str(row.get("severity", "")).strip().lower()
    category = str(row.get("category", "")).strip().lower()
    title = str(row.get("title", "")).strip().lower()
    text = f"{category} {title}"
    score += float(_severity_rank(severity) * 8)
    if any(marker in text for marker in FASTLANE_MARKERS):
        score += 40.0
    if any(marker in text for marker in ("payment", "trading", "wallet", "transaction", "financial", "idor", "bac")):
        score += 25.0
    return score


class PluginImpl(Plugin):
    name = "security_report_builder"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        payload = task.payload if isinstance(task.payload, dict) else {}
        source = Path(cfg.get("findings_source", "data/reports/engine/findings.json"))
        source_fallback_raw = str(cfg.get("findings_source_fallback", "")).strip()
        include_min_severity = str(cfg.get("include_min_severity", "low")).strip().lower() or "low"
        out_dir = Path(cfg.get("out_dir", "data/reports/engine/security_reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        session_guardian = context.get("session_guardian")
        include_screenshots = bool(cfg.get("include_screenshots", True))
        ready_program_handle = str(cfg.get("intigriti_program_handle", "capital-com")).strip() or "capital-com"
        platform = str(cfg.get("platform", "intigriti")).strip().lower() or "intigriti"
        templates_path = Path(cfg.get("templates_path", "config/report_templates.yaml"))
        rows: list[dict[str, Any]] = []
        payload_rows = payload.get("findings", [])
        if isinstance(payload_rows, list):
            rows = [r for r in payload_rows if isinstance(r, dict) and str(r.get("target", "")).strip() == str(task.target).strip()]
        if not rows:
            rows = [r for r in await _load(source) if str(r.get("target", "")).strip() == str(task.target).strip()]
        if not rows and source_fallback_raw:
            source_fallback = Path(source_fallback_raw)
            rows = [r for r in await _load(source_fallback) if str(r.get("target", "")).strip() == str(task.target).strip()]
        rows = [r for r in rows if _severity_rank(str(r.get("severity", "info"))) >= _severity_rank(include_min_severity)]
        rows = sorted(rows, key=_builder_priority, reverse=True)
        if not rows:
            return []

        items: list[dict[str, Any]] = []
        ready_items: list[dict[str, Any]] = []
        for r in rows[:120]:
            ev = r.get("evidence", {}) if isinstance(r.get("evidence"), dict) else {}
            meta = r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {}
            endpoint = str(ev.get("base_url") or ev.get("url") or ev.get("modified_url") or ev.get("variant_url") or "")
            endpoint_for_browser = _endpoint_url(task.target, endpoint)
            request_owner = ev.get("request_auth_a", {}) if isinstance(ev.get("request_auth_a"), dict) else {}
            request_attacker = ev.get("request_auth_b", {}) if isinstance(ev.get("request_auth_b"), dict) else {}
            if not request_owner:
                request_owner = ev.get("request", {}) if isinstance(ev.get("request"), dict) else {}
            if not request_attacker:
                request_attacker = ev.get("request", {}) if isinstance(ev.get("request"), dict) else {}
            curl_owner = _curl_from_request(request_owner) if request_owner else ""
            curl_attacker = _curl_from_request(request_attacker) if request_attacker else ""
            reproduction_steps: list[str] = []
            if curl_owner:
                reproduction_steps.append(f"1. Baseline owner request:\n{curl_owner}")
            if curl_attacker:
                reproduction_steps.append(f"2. Cross-context request:\n{curl_attacker}")
            if not reproduction_steps:
                reproduction_steps = [str(x) for x in [ev.get("base_url"), ev.get("variant_url"), ev.get("modified_url")] if x]
            screenshot_path = ""
            if include_screenshots and session_guardian and endpoint_for_browser:
                try:
                    screenshot_path = await session_guardian.capture_endpoint_screenshot(
                        target=task.target,
                        url=endpoint_for_browser,
                        label=f"report_{str(r.get('category', 'finding'))}",
                        session_name=str(cfg.get("screenshot_session", "user")).strip() or "user",
                    )
                except Exception:
                    screenshot_path = ""
            score = float(r.get("risk_score", 0) or 0)
            items.append(
                {
                    "title": str(r.get("title", "")),
                    "severity_estimation": _sev(score),
                    "description": f"Potential issue detected by {r.get('plugin', '')} during safe automated analysis.",
                    "endpoint": endpoint,
                    "category": str(r.get("category", "")),
                    "reproduction_steps": reproduction_steps,
                    "curl_owner": curl_owner,
                    "curl_attacker": curl_attacker,
                    "evidence": {"request": ev.get("request", {}), "response": ev.get("response", {}), "diff": ev.get("diff") or ev.get("response_diff") or {}},
                    "impact_explanation": _impact_first_text(str(r.get("category", "")), endpoint),
                    "remediation_suggestion": "Review authorization checks, input validation, and endpoint access controls for this route.",
                    "discovery_source": meta.get("discovery_source", ev.get("discovery_source", r.get("plugin", ""))),
                    "screenshot_path": screenshot_path,
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                }
            )
            ready_items.append(
                {
                    "program_handle": ready_program_handle,
                    "target": task.target,
                    "title": str(r.get("title", "")),
                    "severity": _sev(score).lower(),
                    "category": str(r.get("category", "")),
                    "endpoint": endpoint,
                    "impact": _impact_first_text(str(r.get("category", "")), endpoint),
                    "reproduction_steps": reproduction_steps,
                    "curl_owner": curl_owner,
                    "curl_attacker": curl_attacker,
                    "evidence_screenshot": screenshot_path,
                    "discovery_source": meta.get("discovery_source", ev.get("discovery_source", r.get("plugin", ""))),
                }
            )

        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        json_path = out_dir / f"security_report_{platform}_{task.target.replace('.', '_')}_{ts}.json"
        ready_path = out_dir / f"{platform}_ready_{task.target.replace('.', '_')}_{ts}.json"
        md_path = out_dir / f"security_report_{platform}_{task.target.replace('.', '_')}_{ts}.md"
        html_path = out_dir / f"security_report_{platform}_{task.target.replace('.', '_')}_{ts}.html"

        await write_json(json_path, {"target": task.target, "platform": platform, "count": len(items), "items": items})
        await write_json(
            ready_path,
            {
                "platform": platform,
                "program_handle": ready_program_handle,
                "target": task.target,
                "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "count": len(ready_items),
                "reports": ready_items,
            },
        )

        templates = _load_templates(templates_path)
        template_cfg = templates.get("platforms", {}).get(platform, templates.get("platforms", {}).get("generic", {}))
        md_template = str(template_cfg.get("markdown", "")).strip()
        html_template = str(template_cfg.get("html", "")).strip()
        required_headers = template_cfg.get("required_headers", []) if isinstance(template_cfg.get("required_headers", []), list) else []
        username = _report_username()

        items_md = []
        for it in items:
            steps = "\n".join([f"- {step}" for step in it["reproduction_steps"]]) if it["reproduction_steps"] else ""
            items_md.append(
                "\n".join(
                    [
                        f"## {it['title']}",
                        f"- Severity: {it['severity_estimation']}",
                        f"- Endpoint: {it['endpoint']}",
                        f"- Discovery source: {it['discovery_source']}",
                        f"- Impact: {it['impact_explanation']}",
                        "- Reproduction Steps:",
                        steps or "- (none)",
                        "",
                    ]
                )
            )
        md_body = "\n".join(items_md)
        if not md_template:
            md_template = (
                "# Security Report - {{target}}\n\n"
                "Platform: {{platform}}\n\n"
                "Generated: {{generated_at}}\n\n"
                "Required Headers:\n{{required_headers}}\n\n"
                "{{items_md}}\n"
            )
        md_rendered = render_template(
            md_template,
            {
                "program": ready_program_handle,
                "target": task.target,
                "platform": platform,
                "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "required_headers": "\n".join([render_template(x, {"username": username}) for x in required_headers]) or "- none",
                "items_md": md_body,
                "username": username,
            },
            strict=False,
        )
        await write_text(md_path, md_rendered)

        rows_html = []
        items_html = []
        for it in items:
            rows_html.append(
                "<tr>"
                f"<td>{html.escape(it['title'])}</td>"
                f"<td>{html.escape(it['severity_estimation'])}</td>"
                f"<td>{html.escape(it['endpoint'])}</td>"
                f"<td>{html.escape(it['discovery_source'])}</td>"
                "</tr>"
            )
            steps_html = "".join([f"<li>{html.escape(step)}</li>" for step in it["reproduction_steps"]]) or "<li>(none)</li>"
            items_html.append(
                "<section>"
                f"<h2>{html.escape(it['title'])}</h2>"
                f"<p><strong>Severity:</strong> {html.escape(it['severity_estimation'])}</p>"
                f"<p><strong>Endpoint:</strong> {html.escape(it['endpoint'])}</p>"
                f"<p><strong>Impact:</strong> {html.escape(it['impact_explanation'])}</p>"
                "<p><strong>Reproduction:</strong></p>"
                f"<ul>{steps_html}</ul>"
                "</section>"
            )
        if not html_template:
            html_template = (
                "<!doctype html><html><head><meta charset='utf-8'><title>Security Report</title>"
                "<style>"
                "body{font-family:Arial;background:#0b0f14;color:#e6edf3;padding:24px}"
                "table{border-collapse:collapse;width:100%}"
                "th,td{border:1px solid #1e2630;padding:8px}"
                "th{background:#111827}a{color:#7dd3fc}"
                "</style></head><body>"
                "<h1>Security Report - {{target}}</h1>"
                "<p>Platform: {{platform}}</p>"
                "<p>Generated: {{generated_at}}</p>"
                "<p>Required Headers: {{required_headers_html}}</p>"
                "<table><thead><tr><th>Title</th><th>Severity</th><th>Endpoint</th><th>Discovery Source</th></tr></thead>"
                "<tbody>{{rows_html}}</tbody></table></body></html>"
            )
        html_rendered = render_template(
            html_template,
            {
                "program": ready_program_handle,
                "target": html.escape(task.target),
                "platform": platform,
                "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "required_headers_html": html.escape(
                    ", ".join([render_template(x, {"username": username}) for x in required_headers]) or "none"
                ),
                "rows_html": "".join(rows_html),
                "items_html": "".join(items_html),
                "username": username,
            },
            strict=False,
        )
        await write_text(html_path, html_rendered)

        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="security_report_generation",
                severity="info",
                title=f"Security report package generated ({len(items)} items)",
                evidence={
                    "json_report": str(json_path),
                    "platform_ready_json": str(ready_path),
                    "markdown_report": str(md_path),
                    "html_report": str(html_path),
                },
                metadata={"novelty": 62, "confidence": 92, "impact": 50, "discovery_source": "security_report_builder"},
            )
        ]
