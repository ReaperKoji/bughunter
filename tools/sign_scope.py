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
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except Exception:
    hashes = None  # type: ignore
    padding = None  # type: ignore
    load_pem_private_key = None  # type: ignore

DEFAULT_KEY_PATH = Path("config/signer.key")


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


def _load_key(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(f"signer key missing: {path}")
    return path.read_bytes()


def _sign_hmac(payload: bytes, key: bytes) -> str:
    import hmac
    import hashlib

    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _sign_rsa(payload: bytes, key: bytes) -> str:
    if load_pem_private_key is None:
        raise RuntimeError("cryptography not installed")
    private_key = load_pem_private_key(key, password=None)
    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("utf-8")


def sign_scope(scope: dict[str, Any], *, algo: str, key_path: Path) -> dict[str, Any]:
    scope = dict(scope)
    scope.setdefault("signature_meta", {})
    scope["signature_meta"]["algorithm"] = algo
    scope["signature_meta"]["created_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    key = _load_key(key_path)
    payload = _canonical_payload(scope)
    if algo == "hmac-sha256":
        signature = _sign_hmac(payload, key)
    elif algo == "rsa-sha256":
        signature = _sign_rsa(payload, key)
    else:
        raise ValueError("unsupported algorithm")
    scope["signature"] = signature
    return scope


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign scope.json with HMAC-SHA256 or RSA")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--algo", default="hmac-sha256")
    parser.add_argument("--key", default=str(DEFAULT_KEY_PATH))
    args = parser.parse_args()

    scope = json.loads(Path(args.input).read_text(encoding="utf-8"))
    signed = sign_scope(scope, algo=str(args.algo).lower(), key_path=Path(args.key))
    Path(args.output).write_text(json.dumps(signed, ensure_ascii=True, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
