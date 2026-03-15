#!/usr/bin/env python3
import json
import sys
from typing import Dict

WEIGHTS = {
    "asset_criticality": 0.25,
    "endpoint_novelty": 0.15,
    "js_entropy": 0.10,
    "historical_payout_density": 0.15,
    "api_surface_complexity": 0.10,
    "parameter_density": 0.10,
    "auth_surface": 0.10,
    "instability_penalty": -0.05
}

def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))

def compute_priority(metrics: Dict) -> float:
    score = 0.0
    for key, weight in WEIGHTS.items():
        val = float(metrics.get(key, 0.0))
        score += weight * _clamp(val)
    return max(0.0, min(100.0, score * 100.0))

def main() -> int:
    data = sys.stdin.read().strip()
    if not data:
        print("0.0")
        return 0
    metrics = json.loads(data)
    score = compute_priority(metrics if isinstance(metrics, dict) else {})
    print(f"{score:.2f}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
