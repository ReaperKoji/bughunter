from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from apps.recon.models import Program
from apps.recon.services.scan_orchestrator import queue_nuclei_scans
from apps.recon.tasks import run_nuclei_scan


class Command(BaseCommand):
    help = "Modulo 2: enfileira scans Nuclei para subdominios vivos"

    def add_arguments(self, parser):
        parser.add_argument("--program", required=True)
        parser.add_argument("--templates-profile", default="recent_cves,cloud_misconfig")

    def handle(self, *args, **opts):
        slug = str(opts["program"]).strip()
        if not Program.objects.filter(slug=slug, is_active=True).exists():
            raise CommandError(f"Programa nao encontrado: {slug}")
        queued = queue_nuclei_scans(slug, templates_profile=str(opts["templates_profile"]))
        if queued:
            for job_id in Program.objects.get(slug=slug).scan_jobs.filter(status="queued").values_list("id", flat=True):
                run_nuclei_scan.delay(job_id)
        self.stdout.write(self.style.SUCCESS(f"Scan jobs enfileirados e despachados: {queued}"))
