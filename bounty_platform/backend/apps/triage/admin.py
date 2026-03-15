from __future__ import annotations

from django.contrib import admin

from .models import Vulnerability


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("program", "subdomain", "severity", "title", "tool", "created_at")
    list_filter = ("severity", "tool")
    search_fields = ("title", "endpoint", "subdomain__hostname")
