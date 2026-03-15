from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.recon.tasks import run_ai_triage
from apps.triage.models import Vulnerability


class Command(BaseCommand):
    help = "Modulo 3: roda analise de IA para findings interessantes."

    def add_arguments(self, parser):
        parser.add_argument("--severity-min", default="medium")
        parser.add_argument("--limit", type=int, default=20)

    def handle(self, *args, **opts):
        min_sev = str(opts["severity_min"]).strip().lower()
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = rank.get(min_sev, 2)

        rows = []
        for vuln in Vulnerability.objects.all().order_by("-created_at")[:500]:
            if rank.get(vuln.severity, 0) < min_rank:
                continue
            if vuln.ai_triage:
                continue
            rows.append(vuln)
            if len(rows) >= int(opts["limit"]):
                break

        for vuln in rows:
            run_ai_triage.delay(vuln.id)

        self.stdout.write(self.style.SUCCESS(f"Analises IA enfileiradas: {len(rows)}"))
