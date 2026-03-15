from __future__ import annotations

import os
import re
import shutil
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task

SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
API_RE = re.compile(r"""['"](/api/[A-Za-z0-9_/\-?=&{}]+)['"]""")
LINUX_BIN_DIR = Path("/usr/local/bin")
CRITICAL_RECON_BINARIES = ("subfinder", "httpx", "nuclei")
DEFAULT_MASS_PINGER_PATHS = (
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.production",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/actuator/env",
)


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.forms: list[dict[str, object]] = []
        self._form: dict[str, object] | None = None
        self.scripts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        amap = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "a" and amap.get("href"):
            self.links.add(amap["href"])
        if t == "script" and amap.get("src"):
            self.scripts.add(amap["src"])
        if t == "form":
            self._form = {"action": amap.get("action", ""), "method": (amap.get("method", "GET") or "GET").upper(), "fields": []}
        if t in {"input", "select", "textarea"} and self._form is not None:
            n = amap.get("name", "").strip()
            if n:
                fields = self._form.get("fields", [])
                if isinstance(fields, list):
                    fields.append(n)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _path(value: str):
    from pathlib import Path

    return Path(value)


def _resolve_binary(tool: str) -> str:
    name = str(tool or "").strip()
    if not name:
        return ""
    preferred = LINUX_BIN_DIR / name
    if preferred.exists() and os.access(preferred, os.X_OK):
        return str(preferred)
    found = shutil.which(name)
    return str(found) if found else ""


def _extract_host(raw: str) -> str:
    item = str(raw or "").strip()
    if not item:
        return ""
    if "://" in item:
        item = str(urlparse(item).hostname or "").strip()
    item = item.strip().strip(".")
    if not item or " " in item or "/" in item:
        return ""
    return item.lower()


def _host_in_scope(host: str, suffixes: set[str]) -> bool:
    value = str(host or "").strip().lower()
    if not value:
        return False
    for suffix in suffixes:
        sfx = str(suffix or "").strip().lower()
        if sfx and (value == sfx or value.endswith("." + sfx)):
            return True
    return False


class PluginImpl(Plugin):
    name = "recon_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        logger = context.get("logger")
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        seed_paths = cfg.get("seed_paths", ["/", "/login", "/api", "/docs"])
        max_pages = int(cfg.get("max_pages", 15))
        use_auth = bool(cfg.get("authenticated_crawling", False))
        recursive_commands = cfg.get("recursive_discovery_commands", [])
        recursive_suffixes = {str(x).strip().lower() for x in cfg.get("recursive_suffix_allowlist", []) if str(x).strip()}
        recursive_max_hosts = max(1, int(cfg.get("recursive_max_hosts", 40)))
        misconfig_probe_paths = [str(x).strip() for x in cfg.get("misconfig_probe_paths", DEFAULT_MASS_PINGER_PATHS) if str(x).strip()]
        misconfig_probe_statuses = {int(x) for x in cfg.get("misconfig_probe_statuses", [200, 206, 401, 403, 500]) if str(x).strip()}
        misconfig_probe_max_hosts = max(1, int(cfg.get("misconfig_probe_max_hosts", 80)))
        mass_pinger_suffixes = {str(x).strip().lower() for x in cfg.get("mass_pinger_suffixes", ["capital.com", "itcapital.io"]) if str(x).strip()}
        sessions = load_sessions(_path(cfg.get("sessions_file", "data/sessions.yaml"))) if use_auth else {}

        queue = [f"{base}{p}" for p in seed_paths if isinstance(p, str)]
        seen: set[str] = set()
        discovered_hosts: set[str] = {task.target}
        endpoints: set[str] = set()
        parameters: set[str] = set()
        forms: list[dict[str, object]] = []
        methods: set[str] = {"GET"}
        js_assets: set[str] = set()
        missing_tools = [tool for tool in CRITICAL_RECON_BINARIES if not _resolve_binary(tool)]
        if missing_tools and logger is not None:
            try:
                logger.warning(
                    "recon_engine_missing_binaries "
                    + ",".join([f"{tool}:/usr/local/bin/{tool}" for tool in missing_tools])
                )
            except Exception:
                pass

        if isinstance(recursive_commands, list) and recursive_commands:
            for cmd_tpl in recursive_commands:
                try:
                    cmd = str(cmd_tpl).format(target=task.target)
                except Exception:
                    continue
                if not cmd.strip():
                    continue
                result = await run_command(
                    cmd,
                    timeout=timeout,
                    stealth_mode=bool(context["runtime"].get("stealth_mode", True)),
                    proxies=context["runtime"].get("proxies", []),
                )
                for line in str(result.get("stdout", "")).splitlines():
                    host = _extract_host(line)
                    if not host:
                        continue
                    if recursive_suffixes and not _host_in_scope(host, recursive_suffixes):
                        continue
                    discovered_hosts.add(host)
                if len(discovered_hosts) >= recursive_max_hosts:
                    break
            for host in sorted(discovered_hosts):
                if host == task.target:
                    continue
                queue.append(f"https://{host}/")
                if len(queue) >= max_pages * 3:
                    break

        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            headers = {}
            if sessions:
                first = next(iter(sessions.values()))
                headers = auth_header(first)
            r = await request_http_async("GET", url, headers=headers, timeout=timeout)
            txt = str(r.get("text", ""))
            up = urlparse(url)
            endpoints.add(up.path or "/")
            for k in parse_qs(up.query).keys():
                parameters.add(k)

            p = _Parser()
            try:
                p.feed(txt)
            except Exception:
                pass
            for lk in p.links:
                lu = urljoin(url, lk)
                lup = urlparse(lu)
                if lup.netloc in {"", *discovered_hosts}:
                    queue.append(lu)
                    endpoints.add(lup.path or "/")
                    for k in parse_qs(lup.query).keys():
                        parameters.add(k)
            for f in p.forms:
                forms.append(f)
                methods.add(str(f.get("method", "GET")).upper())
                action = str(f.get("action", "")).strip()
                if action:
                    endpoints.add(urlparse(urljoin(url, action)).path or "/")
                for fld in f.get("fields", []) if isinstance(f.get("fields"), list) else []:
                    parameters.add(str(fld))
            for s in p.scripts:
                su = urljoin(url, s)
                if urlparse(su).netloc in {"", task.target}:
                    js_assets.add(su)

        for su in sorted(js_assets)[:25]:
            jr = await request_http_async("GET", su, headers={}, timeout=timeout)
            jst = str(jr.get("text", ""))
            for ap in API_RE.findall(jst):
                endpoints.add(urlparse(urljoin(base + "/", ap)).path or "/")
                for k in parse_qs(urlparse(ap).query).keys():
                    parameters.add(k)

        misconfig_hits: list[dict[str, object]] = []
        scan_hosts = [h for h in sorted(discovered_hosts) if _host_in_scope(h, mass_pinger_suffixes)]
        if _host_in_scope(task.target, mass_pinger_suffixes) and task.target not in scan_hosts:
            scan_hosts.insert(0, task.target)
        scan_hosts = scan_hosts[:misconfig_probe_max_hosts]
        for host in scan_hosts:
            for probe_path in misconfig_probe_paths:
                path = probe_path if probe_path.startswith("/") else f"/{probe_path}"
                probe_url = f"https://{host}{path}"
                resp = await request_http_async("GET", probe_url, headers={}, timeout=timeout)
                status = int(resp.get("status", 0) or 0)
                if status not in misconfig_probe_statuses:
                    continue
                body = str(resp.get("text", "") or "")
                body_l = body.lower()
                finding_kind = ""
                finding_severity = "low"
                if path.startswith("/.env") and ("=" in body[:500] or "database_url" in body_l or "secret" in body_l):
                    finding_kind = "env_exposure"
                    finding_severity = "medium"
                elif path.startswith("/.git/") and ("ref:" in body_l or "[core]" in body_l):
                    finding_kind = "git_repository_exposure"
                    finding_severity = "medium"
                elif "phpinfo" in path.lower() and ("php version" in body_l or "phpinfo()" in body_l):
                    finding_kind = "phpinfo_exposure"
                    finding_severity = "medium"
                elif path == "/server-status" and ("server version" in body_l or "apache server status" in body_l):
                    finding_kind = "server_status_exposure"
                    finding_severity = "medium"
                elif path == "/actuator/env" and ("propertysources" in body_l or "\"activeprofiles\"" in body_l):
                    finding_kind = "actuator_env_exposure"
                    finding_severity = "medium"
                elif status in {401, 403}:
                    finding_kind = "protected_sensitive_path"
                    finding_severity = "low"
                elif status in {200, 206, 500}:
                    finding_kind = "sensitive_path_accessible"
                    finding_severity = "low"
                if not finding_kind:
                    continue
                endpoints.add(path)
                misconfig_hits.append(
                    {
                        "host": host,
                        "path": path,
                        "url": probe_url,
                        "status": status,
                        "length": int(resp.get("length", 0) or 0),
                        "kind": finding_kind,
                        "severity": finding_severity,
                        "response_sample": body[:300],
                    }
                )

        if not endpoints:
            return []
        severity = "info"
        category = "recon_engine"
        title = f"Recon engine mapped {len(endpoints)} endpoints and {len(parameters)} parameters"
        if misconfig_hits:
            severity = "medium" if any(str(x.get("severity", "")).lower() == "medium" for x in misconfig_hits) else "low"
            category = "recon_misconfiguration_signal"
            title = f"Recon engine found {len(misconfig_hits)} low/medium misconfiguration signals"
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category=category,
                severity=severity,
                title=title,
                evidence={
                    "endpoints": sorted(endpoints)[:160],
                    "parameters": sorted(parameters)[:160],
                    "forms": forms[:80],
                    "http_methods": sorted(methods),
                    "javascript_assets": sorted(js_assets)[:80],
                    "discovered_subdomains": sorted(discovered_hosts),
                    "misconfiguration_hits": misconfig_hits[:200],
                    "mass_pinger_hosts_scanned": scan_hosts,
                    "missing_binaries": missing_tools,
                },
                metadata={
                    "novelty": 78,
                    "confidence": 80,
                    "impact": 62 if misconfig_hits else 44,
                    "discovery_source": "recon_engine",
                    "endpoints": sorted(endpoints),
                },
            )
        ]
