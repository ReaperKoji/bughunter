# Scripts

- `scope_guard.py`: Enforces target scope from config.
- `main.py`: Main orchestrator (recon, probe, crawl, fuzz, scan).
- `recon_pipeline.py`: Lightweight recon-only runner.
- `delta_recon.py`: Day-over-day change detection (subdomain, endpoint, stack, ports).
- `endpoint_pipeline.py`: Endpoint + parameter extraction and business cluster mapping.
- `playwright_auth_runner.py`: Authenticated surface collector for in-scope programs.
- `business_logic_hypotheses.py`: Hypothesis engine for IDOR/tenant/workflow/rate abuse tests.
- `priority_queue.py`: Daily top-N hunt queue by profile and novelty.
- `dedupe_findings.py`: Removes duplicates by stable signature.
- `generate_report.py`: Produces markdown report draft from JSON finding.
- `quality_gate.py`: Pre-submission checklist validator with risk score output.
- `coverage_and_kpi.py`: Coverage/gaps report, backlog generation, weekly KPI, priority queue.
- `nuclei_curation.py`: Classifies nuclei templates into high-signal/noise sets from outcomes.
- `nuclei_curation_apply.py`: Builds a curated nuclei templates directory from curation output.
- `opsec_check.py`: OPSEC/security posture check (scope, secrets, session hygiene).
- `feedback_loop.py`: Builds adaptive scoring adjustments from triage/payout data.
- `calibrate_profiles.py`: Calibrates program profile weights from real submissions.
- `monitor_engine.py`: Evaluates plugin metrics and emits alerts.
- `impact_validation.py`: Validates impact evidence for high-value classes.
- `platform_sync_export.py`: Extracts platform operational sync output.
- `delta_first_queue.py`: Prioritizes findings by novelty/delta-first strategy.
- `role_baseline.py`: Maintains session/role baseline and role diffs over time.
- `generate_poc_kit.py`: Builds submission-ready PoC markdown kits for high-value classes.
- `cve_feed_update.py`: Builds local CVE catalog (NVD/KEV/EPSS) for relevance matching.
- `cve_prioritized_queue.py`: Creates top-N CVE validation queue from engine findings.
- `research_pipeline.py`: Autonomous research loop with reaction logic (`js_discovery` => `parameter_intelligence`).
- `preflight_real_setup.py`: Blocks execution when scope/env/binaries are incomplete for real operation.
- `setup_env.sh`: Linux/macOS installer for core Go-based binaries.
- `setup_linux.sh`: Linux full bootstrap (Docker/Compose + Postgres + HunterOps + permissions hardening).
- `common.py`: Shared JSON helpers and signature logic.

## Execution Order
1. `scope_guard.py`
2. `main.py`
3. `delta_recon.py`
4. `endpoint_pipeline.py`
5. `playwright_auth_runner.py`
6. `business_logic_hypotheses.py`
7. `dedupe_findings.py`
8. `priority_queue.py`
9. `quality_gate.py` (before every submission)
10. `coverage_and_kpi.py` + `nuclei_curation.py` + `nuclei_curation_apply.py` (weekly cadence)
