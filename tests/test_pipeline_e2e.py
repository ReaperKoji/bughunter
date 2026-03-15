from __future__ import annotations

import asyncio
import hmac
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
import importlib.util

import httpx
import yaml
import pytest

from hunterops.attack_chain import ChainOrchestrator
from hunterops.attack_chain.config import load_attack_pipeline


def _load_signer():
    spec = importlib.util.spec_from_file_location("sign_scope", "tools/sign_scope.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_pipeline_e2e_against_mockserver(tmp_path: Path) -> None:
    mock_url = os.getenv("MOCKSERVER_URL", "http://localhost:8008")
    try:
        resp = httpx.get(f"{mock_url}/api/baseline", timeout=2.0)
        if resp.status_code != 200:
            pytest.skip("mockserver not ready")
    except Exception:
        pytest.skip("mockserver not reachable")

    # prepare signed scope
    signer = _load_signer()
    key = "e2e-test-key"
    os.environ["SCOPE_SIGNING_KEY"] = key
    now = datetime.now(timezone.utc)
    scope = {
        "targets": ["localhost", "127.0.0.1"],
        "authorized_by": "e2e",
        "valid_from": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "valid_to": (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "rules_of_engagement": "automation allowed",
        "signature_meta": {"algorithm": "hmac-sha256"},
    }
    payload = signer._canonical_payload(scope)  # type: ignore[attr-defined]
    scope["signature"] = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    scope_path = tmp_path / "scope.json"
    import json
    scope_path.write_text(json.dumps(scope, ensure_ascii=True, indent=2), encoding="utf-8")
    os.environ["HUNTEROPS_SCOPE_PATH"] = str(scope_path)

    # targets file
    targets_path = tmp_path / "targets.txt"
    targets_path.write_text(f"mock-lab::{mock_url}/api/transfer\n", encoding="utf-8")

    events_path = tmp_path / "events.ndjson"
    metrics_path = tmp_path / "metrics"

    pipeline_cfg = {
        "name": "e2e",
        "real_mode": False,
        "globals": {
            "timeouts": {"connect_s": 2, "read_s": 5, "total_s": 10, "tool_s": 10},
            "http_limits": {"rate_per_sec": 5, "max_inflight": 2},
            "politeness": {"per_host_rpm": 60, "per_target_rpm": 60, "concurrency_per_host": 1, "jitter_ms": [0, 0]},
            "validator": {"heuristics": {"require_two_signals": False, "min_sensitivity_score": 0.1, "min_body_diff_ratio": 0.0, "max_body_diff_ratio": 1.0}},
        },
        "target_sources": [{"type": "file", "path": str(targets_path)}],
        "chain": {"order": ["idor"], "fallback_on": ["no_poc", "false_positive", "inconclusive"]},
        "modules": {
            "idor": {"enabled": True, "module": "idor", "timeout_s": 5, "retries": 0, "safe_payloads_only": True},
        },
        "outputs": {"events_path": str(events_path), "metrics_path": str(metrics_path)},
        "storage": {"enabled": False},
        "metrics": {"enabled": False},
        "session_guardian": {"enabled": False},
        "impact_validator": {"enabled": False},
    }

    cfg_path = tmp_path / "pipeline.yaml"
    cfg_path.write_text(yaml.safe_dump({"pipeline": pipeline_cfg}), encoding="utf-8")

    cfg = load_attack_pipeline(str(cfg_path))
    orchestrator = ChainOrchestrator(cfg)
    await orchestrator.run()

    assert events_path.exists()
    lines = events_path.read_text(encoding="utf-8").splitlines()
    assert lines
    import json as _json
    for line in lines:
        if not line.strip():
            continue
        data = _json.loads(line)
        for key in ("target", "endpoint"):
            if key in data:
                host = urlparse(str(data[key])).hostname
                assert host in {"localhost", "127.0.0.1"}

    os.environ.pop("SCOPE_SIGNING_KEY", None)
    os.environ.pop("HUNTEROPS_SCOPE_PATH", None)
