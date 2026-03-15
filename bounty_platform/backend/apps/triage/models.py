from __future__ import annotations

from django.db import models

from apps.recon.models import Program, Subdomain


class Vulnerability(models.Model):
    SEV_INFO = "info"
    SEV_LOW = "low"
    SEV_MEDIUM = "medium"
    SEV_HIGH = "high"
    SEV_CRITICAL = "critical"
    SEVERITY_CHOICES = (
        (SEV_INFO, "Info"),
        (SEV_LOW, "Low"),
        (SEV_MEDIUM, "Medium"),
        (SEV_HIGH, "High"),
        (SEV_CRITICAL, "Critical"),
    )

    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name="vulnerabilities")
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="vulnerabilities")
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=120, blank=True, default="")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES)
    confidence = models.FloatField(default=0.0)
    tool = models.CharField(max_length=64, default="nuclei")
    endpoint = models.CharField(max_length=512, blank=True, default="")
    reproduction_command = models.TextField(blank=True, default="")
    raw = models.JSONField(default=dict, blank=True)
    ai_triage = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["program", "severity"]),
            models.Index(fields=["program", "tool"]),
        ]

    def __str__(self) -> str:
        return f"{self.severity}:{self.title}"
