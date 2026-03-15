#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except Exception:
    hashes = None  # type: ignore
    padding = None  # type: ignore
    load_pem_public_key = None  # type: ignore

DEFAULT_KEY_PATH = Path("config/signer.key")
DEFAULT_PUB_PATH = Path("config/signer.pub")


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


def _read_key(path: Path, env_name: str) -> bytes:
    env_value = os.getenv(env_name, "").strip()
    if env_value:
        return env_value.encode("utf-8")
    if not path.exists():
        raise FileNotFoundError(f"key missing: {path}")
    return path.read_bytes()


def _verify_hmac(payload: bytes, key: bytes, signature: str) -> bool:
    import hmac
    import hashlib

    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _verify_rsa(payload: bytes, pub_key: bytes, signature: str) -> bool:
    if load_pem_public_key is None:
        raise RuntimeError("cryptography not installed")
    public_key = load_pem_public_key(pub_key)
    sig_bytes = base64.b64decode(signature.encode("utf-8"))
    public_key.verify(sig_bytes, payload, padding.PKCS1v15(), hashes.SHA256())
    return True


def _parse_time(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)


def verify_scope(scope: dict[str, Any], *, key_path: Path, pub_path: Path) -> tuple[bool, str]:
    required = ["targets", "authorized_by", "valid_from", "valid_to", "rules_of_engagement", "signature", "signature_meta"]
    for k in required:
        if k not in scope:
            return False, f"missing_field:{k}"
    if not scope.get("authorized_by"):
        return False, "authorized_by_empty"
    try:
        start = _parse_time(str(scope.get("valid_from")))
        end = _parse_time(str(scope.get("valid_to")))
    except Exception:
        return False, "invalid_time_format"
    now = datetime.now(timezone.utc)
    if not (start <= now <= end):
        return False, "scope_not_in_valid_window"

    meta = scope.get("signature_meta", {}) if isinstance(scope.get("signature_meta"), dict) else {}
    algo = str(meta.get("algorithm", "hmac-sha256")).lower()
    payload = _canonical_payload(scope)
    signature = str(scope.get("signature", ""))
    if algo == "hmac-sha256":
        key = _read_key(key_path, "SCOPE_SIGNING_KEY")
        ok = _verify_hmac(payload, key, signature)
        return ok, "ok" if ok else "bad_signature"
    if algo == "rsa-sha256":
        pub = _read_key(pub_path, "SCOPE_SIGNING_PUBKEY")
        try:
            ok = _verify_rsa(payload, pub, signature)
            return ok, "ok"
        except Exception:
            return False, "bad_signature"
    return False, "unsupported_algorithm"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify scope.json signature")
    parser.add_argument("scope_path")
    parser.add_argument("--key", default=str(DEFAULT_KEY_PATH))
    parser.add_argument("--pub", default=str(DEFAULT_PUB_PATH))
    args = parser.parse_args()
    scope = json.loads(Path(args.scope_path).read_text(encoding="utf-8"))
    ok, reason = verify_scope(scope, key_path=Path(args.key), pub_path=Path(args.pub))
    if not ok:
        print(f"scope_invalid reason={reason}")
        return 1
    print("scope_valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
