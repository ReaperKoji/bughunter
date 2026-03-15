from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.secrets import read_secret
from hunterops.types import Finding


def _extract_between(text: str, start_marker: str, end_marker: str) -> str:
    start = text.find(start_marker)
    if start < 0:
        return ""
    start += len(start_marker)
    end = text.find(end_marker, start)
    if end < 0:
        return text[start:].strip()
    return text[start:end].strip()


def _normalize_endpoint(url_or_path: str) -> str:
    raw = str(url_or_path or "").strip()
    if not raw:
        return "/"
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        path = parsed.path or "/"
        return path if path.startswith("/") else f"/{path}"
    parsed = urlparse(raw)
    path = parsed.path or raw
    return path if path.startswith("/") else f"/{path}"


def _sanitize_token_line(value: str) -> str:
    raw = str(value or "").strip()
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


class ReportEngine:
    """Monitors ADE evidence files and generates submit-ready technical reports."""

    def __init__(self, cfg: dict[str, Any], *, logger: Any | None = None, storage: Any | None = None) -> None:
        self.cfg = cfg or {}
        self.logger = logger
        self.storage = storage
        self.enabled = bool(self.cfg.get("enabled", True))
        self.evidence_dir = resolve_path(str(self.cfg.get("evidence_dir", "data/evidence/ade")), prefer_existing=False)
        self.ready_dir = ensure_directory(resolve_path(str(self.cfg.get("ready_dir", "data/ready_to_submit")), prefer_existing=False), mode=0o755)
        self.state_file = resolve_path(str(self.cfg.get("state_file", "data/processed/report_engine_state.json")), prefer_existing=False)
        ensure_directory(self.state_file.parent, mode=0o755)
        self.auto_submit = bool(self.cfg.get("auto_submit_h1_draft", False))
        self.draft_endpoint = str(self.cfg.get("draft_endpoint", "https://api.hackerone.com/v1/reports/drafts")).strip()
        self.identifier_env = str(self.cfg.get("identifier_env", "H1_API_IDENTIFIER")).strip()
        self.token_env = str(self.cfg.get("token_env", "H1_API_TOKEN")).strip()

    def _log(self, level: str, message: str) -> None:
        if not self.logger:
            return
        try:
            getattr(self.logger, level)(message)
        except Exception:
            return

    def _load_state(self) -> dict[str, Any]:
        if not self.state_file.exists():
            return {"processed_files": []}
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            return {"processed_files": []}
        if not isinstance(data, dict):
            return {"processed_files": []}
        processed = data.get("processed_files", [])
        if not isinstance(processed, list):
            processed = []
        return {"processed_files": [str(x).strip() for x in processed if str(x).strip()]}

    def _save_state(self, state: dict[str, Any]) -> None:
        payload = {
            "processed_files": sorted(list({str(x).strip() for x in state.get("processed_files", []) if str(x).strip()})),
        }
        self.state_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _parse_evidence_file(path: Path) -> dict[str, str]:
        text = path.read_text(encoding="utf-8")
        url_line = _extract_between(text, "## URL Afetada", "## Parametro Vulneravel")
        param_line = _extract_between(text, "## Parametro Vulneravel", "## Requisicao (CURL)")
        curl_line = _extract_between(text, "## Requisicao (CURL)", "## Prova de Vazamento (Impacto)")
        impact_line = _extract_between(text, "## Prova de Vazamento (Impacto)", "\n## ")
        url_value = url_line.replace("`", "").strip()
        param_value = param_line.replace("`", "").strip()
        curl_value = (
            curl_line.replace("```bash", "")
            .replace("```", "")
            .strip()
        )
        return {
            "url": url_value,
            "parameter": param_value,
            "curl": curl_value,
            "impact": impact_line.strip(),
            "raw": text,
        }

    def _identifier(self) -> str:
        return read_secret(self.identifier_env) or "reaperk0ji"

    def _token(self) -> str:
        return read_secret(self.token_env)

    def _enrich_curl(self, curl_cmd: str) -> str:
        cmd = str(curl_cmd or "").strip()
        if not cmd:
            return cmd
        identifier = self._identifier()
        user_agent = f"Mozilla/5.0 (HunterOps/3.0; BugBounty; {identifier})."
        if "X-H1-Client-Identifier" not in cmd:
            cmd += f" -H 'X-H1-Client-Identifier: {identifier}'"
        if "User-Agent" not in cmd:
            cmd += f" -H 'User-Agent: {user_agent}'"
        return cmd

    def _entity_pool_context(self, target: str, endpoint: str, round_findings: list[Finding]) -> str:
        endpoint_norm = _normalize_endpoint(endpoint)
        plugin_hits: set[str] = set()
        for finding in round_findings:
            if finding.plugin == "deep_js_intelligence":
                ev = finding.evidence if isinstance(finding.evidence, dict) else {}
                endpoints = ev.get("endpoints", [])
                if isinstance(endpoints, list):
                    for item in endpoints:
                        if _normalize_endpoint(str(item)) == endpoint_norm:
                            plugin_hits.add("Deep JS Intelligence")
                            break
        entities_count = 0
        if self.storage and bool(getattr(self.storage, "enabled", False)):
            try:
                entities = self.storage.list_recent_entities(target=target, limit=500)
                for row in entities:
                    source_ep = _normalize_endpoint(str(row.get("source_endpoint", "/")))
                    if source_ep == endpoint_norm:
                        entities_count += 1
                        source_plugin = str(row.get("source_plugin", "")).strip()
                        if source_plugin:
                            plugin_hits.add(source_plugin)
            except Exception:
                entities_count = 0
        if not plugin_hits and entities_count <= 0:
            return "No additional EntityPool context available for this endpoint."
        sources = ", ".join(sorted(list(plugin_hits))) if plugin_hits else "EntityPool"
        return (
            f"This endpoint was observed via {sources}. "
            f"EntityPool currently tracks {entities_count} related entities for this route."
        )

    @staticmethod
    def _build_title(endpoint: str) -> str:
        ep = _normalize_endpoint(endpoint)
        return f"IDOR on {ep} leading to Sensitive Data Exposure"

    def _build_report_markdown(
        self,
        *,
        target: str,
        run_id: str,
        evidence_file: Path,
        parsed: dict[str, str],
        round_findings: list[Finding],
    ) -> tuple[str, str]:
        url = str(parsed.get("url", "")).strip()
        parameter = str(parsed.get("parameter", "")).strip() or "id"
        endpoint = _normalize_endpoint(url or "/")
        curl_cmd = self._enrich_curl(str(parsed.get("curl", "")))
        impact = str(parsed.get("impact", "")).strip() or "Unauthorized cross-user data access was observed."
        context_line = self._entity_pool_context(target=target, endpoint=endpoint, round_findings=round_findings)
        title = self._build_title(endpoint)
        summary = (
            f"HunterOps identified an object-level authorization weakness on `{endpoint}`. "
            f"Manipulating `{parameter}` produced a response consistent with unauthorized data access."
        )
        lines = [
            f"# {title}",
            "",
            "## Summary",
            summary,
            "",
            "## Steps to Reproduce",
            "1. Send the crafted request below against the affected endpoint.",
            "2. Observe that the server returns unauthorized object data with HTTP 200 semantics.",
            "3. Compare results across identities and confirm cross-account leakage.",
            "",
            "```bash",
            curl_cmd,
            "```",
            "",
            "## Impact",
            impact,
            "",
            "## Markdown Enrichment",
            context_line,
            f"- Evidence source file: `{evidence_file}`",
            f"- Run ID: `{run_id}`",
            f"- Target: `{target}`",
            "",
        ]
        return title, "\n".join(lines)

    def create_h1_draft(self, report_data: dict[str, Any]) -> dict[str, Any]:
        if not self.auto_submit:
            return {"submitted": False, "reason": "auto_submit_disabled"}
        identifier = self._identifier()
        token = self._token()
        if not identifier or not token:
            return {"submitted": False, "reason": "missing_h1_credentials"}
        try:
            import requests  # type: ignore
        except Exception:
            return {"submitted": False, "reason": "requests_not_available"}

        payload = {
            "title": str(report_data.get("title", "")).strip(),
            "summary": str(report_data.get("summary", "")).strip(),
            "vulnerability_information": str(report_data.get("markdown", "")).strip(),
            "impact": str(report_data.get("impact", "")).strip(),
        }
        try:
            resp = requests.post(
                self.draft_endpoint,
                json=payload,
                auth=(identifier, token),
                timeout=12,
                headers={"Accept": "application/json"},
            )
        except Exception as err:
            self._log("warning", f"report_engine_h1_draft_submit_failed err={type(err).__name__}")
            return {"submitted": False, "reason": "request_error"}
        if int(resp.status_code) in {200, 201, 202}:
            return {"submitted": True, "status_code": int(resp.status_code)}
        self._log("warning", f"report_engine_h1_draft_rejected status={int(resp.status_code)}")
        return {"submitted": False, "reason": f"status_{int(resp.status_code)}"}

    async def process_round(self, *, target: str, run_id: str, round_findings: list[Finding]) -> list[Finding]:
        if not self.enabled:
            return []
        ensure_directory(self.evidence_dir, mode=0o755)
        state = self._load_state()
        processed = set(state.get("processed_files", []))
        evidence_files = sorted(self.evidence_dir.glob("evidence_*.md"))
        if not evidence_files:
            return []

        out_findings: list[Finding] = []
        for evidence_file in evidence_files:
            evidence_key = str(evidence_file.resolve())
            if evidence_key in processed:
                continue
            try:
                parsed = self._parse_evidence_file(evidence_file)
            except Exception as err:
                self._log("warning", f"report_engine_evidence_parse_failed file={evidence_file.name} err={type(err).__name__}")
                processed.add(evidence_key)
                continue

            title, markdown = self._build_report_markdown(
                target=target,
                run_id=run_id,
                evidence_file=evidence_file,
                parsed=parsed,
                round_findings=round_findings,
            )
            slug = evidence_file.stem.replace("evidence_", "report_")
            out_file = self.ready_dir / f"{slug}.md"
            out_file.write_text(markdown, encoding="utf-8")
            draft_result = self.create_h1_draft(
                {
                    "title": title,
                    "summary": markdown.split("## Summary", 1)[1].split("## Steps to Reproduce", 1)[0].strip() if "## Summary" in markdown else "",
                    "impact": str(parsed.get("impact", "")).strip(),
                    "markdown": markdown,
                }
            )
            out_findings.append(
                Finding(
                    plugin="report_engine",
                    target=target,
                    category="submission_draft_ready",
                    severity="info",
                    title=f"Submission draft generated for {title}",
                    evidence={
                        "source_evidence": str(evidence_file),
                        "report_path": str(out_file),
                        "h1_draft_submitted": bool(draft_result.get("submitted", False)),
                        "h1_draft_reason": str(draft_result.get("reason", "")),
                    },
                    metadata={
                        "novelty": 78.0,
                        "confidence": 90.0,
                        "confidence_score": 90.0,
                        "impact": 70.0,
                        "discovery_source": "report_engine",
                    },
                )
            )
            processed.add(evidence_key)

        state["processed_files"] = sorted(list(processed))
        self._save_state(state)
        return out_findings
