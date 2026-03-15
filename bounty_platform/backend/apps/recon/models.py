from __future__ import annotations

from django.db import models


class Program(models.Model):
    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=120)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.slug


class ScopeAsset(models.Model):
    TYPE_DOMAIN = "domain"
    TYPE_WILDCARD = "wildcard"
    TYPE_CHOICES = (
        (TYPE_DOMAIN, "Domain"),
        (TYPE_WILDCARD, "Wildcard"),
    )

    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name="scope_assets")
    asset_type = models.CharField(max_length=16, choices=TYPE_CHOICES)
    value = models.CharField(max_length=255)
    in_scope = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("program", "asset_type", "value")

    def __str__(self) -> str:
        return f"{self.program.slug}:{self.asset_type}:{self.value}"


class Subdomain(models.Model):
    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name="subdomains")
    hostname = models.CharField(max_length=255)
    is_live = models.BooleanField(default=False)
    resolved_ips = models.JSONField(default=list, blank=True)
    source = models.CharField(max_length=64, default="recon")
    raw = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("program", "hostname")
        indexes = [
            models.Index(fields=["program", "is_live"]),
            models.Index(fields=["program", "hostname"]),
        ]

    def __str__(self) -> str:
        return f"{self.hostname} live={self.is_live}"


class ScanJob(models.Model):
    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_DONE = "done"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_DONE, "Done"),
        (STATUS_FAILED, "Failed"),
    )

    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name="scan_jobs")
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="scan_jobs")
    engine = models.CharField(max_length=32, default="nuclei")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED)
    templates_profile = models.CharField(max_length=64, default="recent_cves,cloud_misconfig")
    stdout = models.TextField(blank=True, default="")
    stderr = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["program", "status"])]

    def __str__(self) -> str:
        return f"{self.subdomain.hostname} [{self.status}]"
