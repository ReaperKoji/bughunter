from __future__ import annotations

from django.contrib import admin

from .models import Program, ScopeAsset, ScanJob, Subdomain


@admin.register(Program)
class ProgramAdmin(admin.ModelAdmin):
    list_display = ("slug", "name", "is_active", "created_at")
    search_fields = ("slug", "name")


@admin.register(ScopeAsset)
class ScopeAssetAdmin(admin.ModelAdmin):
    list_display = ("program", "asset_type", "value", "in_scope", "created_at")
    list_filter = ("asset_type", "in_scope")
    search_fields = ("value",)


@admin.register(Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ("program", "hostname", "is_live", "source", "last_seen")
    list_filter = ("is_live", "source")
    search_fields = ("hostname",)


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ("program", "subdomain", "engine", "status", "created_at")
    list_filter = ("status", "engine")
