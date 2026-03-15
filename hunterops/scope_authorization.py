from __future__ import annotations

import base64
import fnmatch
import hmac
import json
import os
import hashlib
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except Exception:
    hashes = None  # type: ignore
    padding = None  # type: ignore
    load_pem_public_key = None  # type: ignore

from hunterops.runtime_paths import resolve_path


def _normalize_targets(raw: list[str]) -> list[str]:
    out: list[str] = []
    for item in raw:
        val = str(item or "").strip().lower()
        if val:
            out.append(val)
    return out


def _matches(target: str, patterns: list[str]) -> bool:
    value = str(target or "").strip().lower()
    for pat in patterns:
        pattern = str(pat or "").strip().lower()
        if not pattern:
            continue
        if fnmatch.fnmatch(value, pattern):
            return True
    return False


DEFAULT_SCOPE_PATH = "config/scope.json"
DEFAULT_SIGNER_KEY = Path("config/signer.key")
DEFAULT_SIGNER_PUB = Path("config/signer.pub")


def load_authorized_scope(scope_path: str = DEFAULT_SCOPE_PATH) -> dict[str, Any]:
    env_path = os.getenv("HUNTEROPS_SCOPE_PATH", "").strip()
    path = resolve_path(env_path or scope_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _canonical_payload(scope: dict[str, Any]) -> bytes:
    payload = {
        "targets": sorted(list(scope.get("targets", []))),
        "authorized_by": str(scope.get("authorized_by", "")),
        "valid_from": str(scope.get("valid_from", "")),
        "valid_to": str(scope.get("valid_to", "")),
        "rules_of_engagement": str(scope.get("rules_of_engagement", "")),
        "signature_meta": scope.get("signature_meta", {}),
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def _parse_time(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)


def _read_key(path: Path, env_name: str) -> bytes:
    env_value = os.getenv(env_name, "").strip()
    if env_value:
        return env_value.encode("utf-8")
    if path.exists():
        return path.read_bytes()
    return b""


def _verify_rsa(payload: bytes, pub_key: bytes, signature: str) -> bool:
    if load_pem_public_key is None:
        return False
    try:
        public_key = load_pem_public_key(pub_key)
        sig_bytes = base64.b64decode(signature.encode("utf-8"))
        public_key.verify(sig_bytes, payload, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def validate_scope_signature(scope: dict[str, Any]) -> bool:
    required = ["targets", "authorized_by", "valid_from", "valid_to", "rules_of_engagement", "signature", "signature_meta"]
    for key in required:
        if key not in scope:
            return False
    if not str(scope.get("authorized_by", "")).strip():
        return False
    try:
        start = _parse_time(str(scope.get("valid_from")))
        end = _parse_time(str(scope.get("valid_to")))
    except Exception:
        return False
    now = datetime.now(timezone.utc)
    if not (start <= now <= end):
        return False

    meta = scope.get("signature_meta", {}) if isinstance(scope.get("signature_meta"), dict) else {}
    algo = str(meta.get("algorithm", "hmac-sha256")).lower()
    signature = str(scope.get("signature", "")).strip()
    if not signature:
        return False
    payload = _canonical_payload(scope)

    if algo == "hmac-sha256":
        key = _read_key(DEFAULT_SIGNER_KEY, "SCOPE_SIGNING_KEY")
        if not key:
            return False
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    if algo == "rsa-sha256":
        pub_key = _read_key(DEFAULT_SIGNER_PUB, "SCOPE_SIGNING_PUBKEY")
        if not pub_key:
            return False
        return _verify_rsa(payload, pub_key, signature)
    return False


def authorize_targets(targets: list[str], scope: dict[str, Any]) -> tuple[bool, list[str]]:
    if scope and validate_scope_signature(scope):
        patterns = _normalize_targets(scope.get("targets", []))
        unauthorized = [t for t in targets if not _matches(t, patterns)]
        return len(unauthorized) == 0, unauthorized

    require_signed = str(os.getenv("HUNTEROPS_REQUIRE_SIGNED_SCOPE", "")).strip().lower() in {"1", "true", "yes", "on"}
    if require_signed:
        return False, targets

    env_targets = os.getenv("AUTHORIZED_TARGETS", "").strip()
    if env_targets:
        patterns = _normalize_targets(env_targets.split(","))
        unauthorized = [t for t in targets if not _matches(t, patterns)]
        return len(unauthorized) == 0, unauthorized

    return False, targets
