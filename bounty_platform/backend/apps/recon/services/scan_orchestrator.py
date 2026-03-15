from __future__ import annotations

import os

from apps.recon.models import Program, ScanJob, Subdomain


def queue_nuclei_scans(program_slug: str, templates_profile: str = "recent_cves,cloud_misconfig") -> int:
    """
    Cria jobs para hosts vivos. Orquestracao multi-VPS via Ax deve ser feita no worker externo,
    mantendo gate de autorizacao e escopo.
    """
    program = Program.objects.get(slug=program_slug, is_active=True)
    count = 0
    for sub in Subdomain.objects.filter(program=program, is_live=True).iterator():
        ScanJob.objects.create(
            program=program,
            subdomain=sub,
            engine="nuclei",
            status=ScanJob.STATUS_QUEUED,
            templates_profile=templates_profile,
        )
        count += 1
    return count


def ax_enabled() -> bool:
    return str(os.getenv("ENABLE_AX_ORCHESTRATION", "0")).strip() == "1"
