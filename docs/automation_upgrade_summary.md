# Automation Upgrade Summary

## Implemented Features
- JSON body support across core modules (IDOR, SQLi, SSTI, XSS, LFI, RCE, SSRF, Open Redirect, Info Leak).
- Safe placeholder templating for body payloads (no code execution).
- Baseline comparer (GET vs POST vs PUT) with suppression of noisy diff signals.
- Sensitivity scoring for emails, phone, IBAN, CPF/CNPJ, tokens, balance/account signals.
- UUID/GUID IDOR handling with cache and safe permutation.
- SessionGuardian failover with backoff, lockout protection, and auth metrics.
- Endpoint governance (allow/deny rules) with manual override audit trail.
- Prometheus metrics and Grafana dashboard JSON, plus alert rules.
- Signed scope/authorization gate enforced before execution.

## Tests Added
- Body-based detection for IDOR/SQLi/SSTI/XSS/LFI.
- Baseline comparer scoring for same vs divergent methods.
- Sensitivity scoring regression checks.
- UUID IDOR path detection.
- SessionGuardian failover behavior.
- Endpoint policy enforcement.
- Observability assets (Grafana JSON and alert rules) validation.

## Notes on Metrics
- No live FP/TP rates recorded yet. Run the suite and pipeline to generate real metrics.
- The pipeline writes a run summary to `data/metrics/attack_chain_summary.json`.

## Recommended Next Steps
1. Run tests and fix any environment-specific failures:
   - `pytest -q`
2. Run the mock API locally and validate end-to-end:
   - `cd tests/mock_api && docker compose up -d`
3. Fill `config/scope.json` or `AUTHORIZED_TARGETS` before any real target runs.
4. Populate `data/sessions.yaml` and `config/vault.yaml` for authenticated paths.
5. Tune `attack_pipeline.yaml` thresholds based on measured FP/TP rates.
