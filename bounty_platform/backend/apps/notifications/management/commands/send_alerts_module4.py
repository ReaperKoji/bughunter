from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.notifications.services.notifier import notify_high_critical
from apps.triage.models import Vulnerability


class Command(BaseCommand):
    help = "Modulo 4: envia alertas para High/Critical com comando de reproducao."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=50)

    def handle(self, *args, **opts):
        sent = 0
        qs = Vulnerability.objects.filter(severity__in=["high", "critical"]).order_by("-created_at")[: int(opts["limit"])]
        for vuln in qs:
            notify_high_critical(
                title=vuln.title,
                severity=vuln.severity,
                target=vuln.subdomain.hostname,
                reproduction_command=vuln.reproduction_command,
            )
            sent += 1
        self.stdout.write(self.style.SUCCESS(f"Alertas processados: {sent}"))
