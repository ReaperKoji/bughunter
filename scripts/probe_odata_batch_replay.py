#!/usr/bin/env python3
"""Replay a captured OData $batch request body across A/B/ANON sessions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_SERVICE_BASE = "https://webwsp.aps.kuleuven.be/sap/opu/odata/sap/ZC_AD_APPLICANT_SRV"
DEFAULT_ENV_FILE = ".env"


@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes
    error: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "ignore")

    @property
    def content_type(self) -> str:
        return str(self.headers.get("Content-Type", ""))


def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in {"'", '"'}:
            v = v[1:-1]
        out[k] = v
    return out


def env_get(name: str, env_file_values: dict[str, str]) -> str:
    value = os.getenv(name, "").strip()
    if value:
        return value
    return env_file_values.get(name, "").strip()


def http_request(method: str, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None, timeout: int = 8) -> HttpResult:
    req = Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    ctx = ssl.create_default_context()
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            return HttpResult(status=int(resp.status), headers={k: v for k, v in resp.headers.items()}, body=resp.read())
    except HTTPError as err:
        hdrs = {k: v for k, v in err.headers.items()} if err.headers else {}
        return HttpResult(status=int(err.code), headers=hdrs, body=err.read(), error=f"http_error_{err.code}")
    except URLError as err:
        return HttpResult(status=0, headers={}, body=str(err).encode("utf-8", "ignore"), error=f"url_error:{err}")
    except Exception as err:  # pragma: no cover
        return HttpResult(status=0, headers={}, body=str(err).encode("utf-8", "ignore"), error=f"unexpected:{err}")


def looks_like_login(result: HttpResult) -> bool:
    text = result.text.lower()
    if "text/html" not in result.content_type.lower() and "<html" not in text:
        return False
    return any(
        signal in text
        for signal in (
            "logon failed",
            "aanmelding mislukt",
            "welcome to ku leuven association",
            "idp.kuleuven.be",
            "saml2",
        )
    )


def fetch_csrf(service_base: str, cookie: str) -> str:
    url = f"{service_base}/?sap-client=200"
    headers = {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "x-csrf-token": "Fetch",
    }
    if cookie:
        headers["Cookie"] = cookie
    resp = http_request("HEAD", url, headers=headers)
    return str(resp.headers.get("x-csrf-token", "")).strip()


def detect_boundary(body_text: str, explicit: str) -> str:
    if explicit:
        return explicit
    for line in body_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("--batch_"):
            return stripped[2:]
    raise ValueError("Could not detect boundary from body. Use --boundary.")


def extract_inner_statuses(text: str) -> list[int]:
    return [int(m.group(1)) for m in re.finditer(r"HTTP/1\\.[01]\\s+(\\d{3})", text)]


def save_report(out_dir: Path, report: dict) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"batch_replay_{stamp}.json"
    md_path = out_dir / f"batch_replay_{stamp}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    lines: list[str] = []
    lines.append(f"# OData Batch Replay - {stamp}")
    lines.append("")
    lines.append(f"- endpoint: `{report.get('endpoint', '')}`")
    lines.append(f"- boundary: `{report.get('boundary', '')}`")
    lines.append(f"- cookie_a_len: `{report.get('cookie_a_len', 0)}`")
    lines.append(f"- cookie_b_len: `{report.get('cookie_b_len', 0)}`")
    lines.append("")
    lines.append("## Matrix")
    for row in report.get("matrix", []):
        lines.append(
            f"- actor={row.get('actor')} status={row.get('status')} csrf_present={row.get('csrf_present')} "
            f"login_like={row.get('login_like')} inner_statuses={row.get('inner_statuses')} sha16={row.get('sha16')}"
        )
    lines.append("")
    lines.append("## Verdict")
    lines.append(f"- a_b_same_body: `{report.get('a_b_same_body', False)}`")
    lines.append(f"- a_b_same_inner_statuses: `{report.get('a_b_same_inner_statuses', False)}`")
    lines.append(f"- notes: `{report.get('notes', '')}`")
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay a captured OData $batch request body.")
    parser.add_argument("--service-base", default=DEFAULT_SERVICE_BASE)
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    parser.add_argument("--body-file", required=True, help="Raw body file captured from browser batch request.")
    parser.add_argument("--boundary", default="", help="Optional explicit batch boundary.")
    parser.add_argument("--out-dir", default="reports/research/manual_checks")
    args = parser.parse_args()

    env_file_values = read_env(Path(args.env_file))
    cookie_a = env_get("HUNTEROPS_USER_COOKIE", env_file_values)
    cookie_b = env_get("HUNTEROPS_USER_B_COOKIE", env_file_values)
    body_text = Path(args.body_file).read_text(encoding="utf-8", errors="ignore")
    boundary = detect_boundary(body_text, args.boundary)
    body = body_text.encode("utf-8")

    endpoint = f"{args.service_base}/$batch?sap-client=200"
    matrix: list[dict] = []
    raw: dict[str, str] = {}
    inner: dict[str, list[int]] = {}
    for actor, cookie in (("A", cookie_a), ("B", cookie_b), ("ANON", "")):
        csrf = fetch_csrf(args.service_base, cookie)
        headers = {
            "Accept": "multipart/mixed",
            "Content-Type": f"multipart/mixed;boundary={boundary}",
            "X-Requested-With": "XMLHttpRequest",
            "DataServiceVersion": "2.0",
            "MaxDataServiceVersion": "2.0",
            "x-csrf-token": csrf,
        }
        if cookie:
            headers["Cookie"] = cookie
        resp = http_request("POST", endpoint, headers=headers, body=body)
        raw[actor] = resp.text
        inner[actor] = extract_inner_statuses(resp.text)
        matrix.append(
            {
                "actor": actor,
                "status": resp.status,
                "csrf_present": bool(csrf),
                "content_type": resp.content_type,
                "login_like": looks_like_login(resp),
                "inner_statuses": inner[actor],
                "sha16": hashlib.sha256(resp.body).hexdigest()[:16],
            }
        )

    a_b_same_body = raw.get("A", "") == raw.get("B", "")
    a_b_same_inner_statuses = inner.get("A", []) == inner.get("B", [])
    notes = "No differential signal in this batch replay."
    if any(row.get("login_like") for row in matrix if row.get("actor") in {"A", "B"}):
        notes = "A/B still not authenticated (login-like response). Refresh cookies from live app flow."
    elif not a_b_same_inner_statuses:
        notes = "A vs B differ in inner batch statuses; inspect those parts for BAC."

    report = {
        "endpoint": endpoint,
        "boundary": boundary,
        "cookie_a_len": len(cookie_a),
        "cookie_b_len": len(cookie_b),
        "matrix": matrix,
        "a_b_same_body": a_b_same_body,
        "a_b_same_inner_statuses": a_b_same_inner_statuses,
        "notes": notes,
    }
    json_path, md_path = save_report(Path(args.out_dir), report)
    print("batch_replay_completed")
    print(f"report_json={json_path}")
    print(f"report_md={md_path}")
    print(f"notes={notes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
