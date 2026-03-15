from __future__ import annotations

import json
from datetime import UTC, datetime

from celery import shared_task

from apps.notifications.services.notifier import notify_high_critical
from apps.recon.models import ScanJob
from apps.recon.services.tool_runner import run_command
from apps.triage.models import Vulnerability
from apps.triage.services.ai_analysis import analyze_http_finding


@shared_task(queue="scan")
def run_nuclei_scan(scan_job_id: int) -> dict:
    job = ScanJob.objects.select_related("subdomain", "program").get(id=scan_job_id)
    job.status = ScanJob.STATUS_RUNNING
    job.started_at = datetime.now(UTC)
    job.save(update_fields=["status", "started_at"])

    target = job.subdomain.hostname
    cmd = [
        "nuclei",
        "-u",
        f"https://{target}",
        "-silent",
        "-jsonl",
        "-tags",
        "cves,misconfiguration,cloud",
    ]

    rc, out, err = run_command(cmd, timeout=900)
    job.stdout = out[:200000]
    job.stderr = err[:200000]

    findings = 0
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue

        sev = str(row.get("info", {}).get("severity", "low")).lower()
        if sev not in {"info", "low", "medium", "high", "critical"}:
            sev = "low"

        title = str(row.get("info", {}).get("name", "Nuclei finding"))
        endpoint = str(row.get("matched-at", ""))
        template_id = str(row.get("template-id", ""))
        repro = f"nuclei -u {endpoint or ('https://' + target)} -id {template_id}".strip()

        vuln = Vulnerability.objects.create(
            program=job.program,
            subdomain=job.subdomain,
            title=title,
            category=template_id,
            severity=sev,
            confidence=70.0,
            tool="nuclei",
            endpoint=endpoint,
            reproduction_command=repro,
            raw=row,
        )

        notify_high_critical(
            title=vuln.title,
            severity=vuln.severity,
            target=job.subdomain.hostname,
            reproduction_command=vuln.reproduction_command,
        )
        findings += 1

    job.status = ScanJob.STATUS_DONE if rc == 0 else ScanJob.STATUS_FAILED
    job.finished_at = datetime.now(UTC)
    job.save(update_fields=["status", "stdout", "stderr", "finished_at"])

    return {"scan_job_id": scan_job_id, "return_code": rc, "findings": findings}


@shared_task(queue="triage")
def run_ai_triage(vulnerability_id: int) -> dict:
    vuln = Vulnerability.objects.select_related("subdomain").get(id=vulnerability_id)
    raw = vuln.raw if isinstance(vuln.raw, dict) else {}
    body = str(raw.get("curl-command", ""))
    result = analyze_http_finding(
        title=vuln.title,
        endpoint=vuln.endpoint,
        response_body=body,
        headers={},
    )
    vuln.ai_triage = result
    vuln.save(update_fields=["ai_triage", "updated_at"])
    return {"vulnerability_id": vulnerability_id, "status": result.get("status", "unknown")}
