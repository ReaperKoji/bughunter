from __future__ import annotations

from apps.recon.models import ScopeAsset


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def host_in_scope(hostname: str, assets: list[ScopeAsset]) -> bool:
    host = normalize_host(hostname)
    for asset in assets:
        value = normalize_host(asset.value)
        if asset.asset_type == ScopeAsset.TYPE_DOMAIN:
            if host == value:
                return True
        elif asset.asset_type == ScopeAsset.TYPE_WILDCARD:
            root = value[2:] if value.startswith("*.") else value
            if host == root or host.endswith("." + root):
                return True
    return False
