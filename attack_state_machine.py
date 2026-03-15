from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
import time


class Verdict(str, Enum):
    POC_VALID = "poc_valid"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"
    NO_POC = "no_poc"
    ERROR = "error"


@dataclass
class Target:
    target_id: str
    url: str
    program_id: str
    scope_id: str


@dataclass
class ModuleResult:
    module: str
    status: str
    evidence: Dict
    candidate_poc: str
    metadata: Dict


@dataclass
class ValidationDecision:
    verdict: Verdict
    confidence: float
    rationale: str


@dataclass
class HistoryEntry:
    module: str
    verdict: Verdict
    reason: str
    ts: float
    metadata: Dict = field(default_factory=dict)


class Module:
    name: str

    def run(self, target: Target, cfg: Dict) -> ModuleResult:
        raise NotImplementedError


class PoCValidator:
    def __init__(self, llm_providers: List[str]):
        self.llm_providers = llm_providers

    def validate(self, result: ModuleResult, target: Target) -> ValidationDecision:
        heur = self.heuristic_check(result)
        if not heur["pass"]:
            return ValidationDecision(Verdict.FALSE_POSITIVE, heur["confidence"], heur["reason"])

        llm_decision = self.llm_triage(result, target)
        if llm_decision is None:
            return ValidationDecision(
                Verdict.INCONCLUSIVE,
                0.50,
                "LLM unavailable and heuristics partial."
            )

        return llm_decision

    def heuristic_check(self, result: ModuleResult) -> Dict:
        # Minimal heuristic example. Replace with real checks.
        evidence = result.evidence or {}
        signals = 0
        reasons = []

        if evidence.get("status_diff"):
            signals += 1
            reasons.append("status_diff")
        if evidence.get("body_diff_ratio", 1.0) < 0.30:
            signals += 1
            reasons.append("low_body_diff")
        if evidence.get("error_signature"):
            signals += 1
            reasons.append("error_signature")

        passed = signals >= 2
        return {
            "pass": passed,
            "confidence": 0.70 if passed else 0.30,
            "reason": ",".join(reasons) or "insufficient_signals",
        }

    def llm_triage(self, result: ModuleResult, target: Target) -> Optional[ValidationDecision]:
        for provider in self.llm_providers:
            try:
                return self._call_llm(provider, result, target)
            except Exception:
                continue
        return None

    def _call_llm(self, provider: str, result: ModuleResult, target: Target) -> ValidationDecision:
        # Placeholder for LLM call. Must return 2-4 sentence rationale.
        rationale = (
            "Response showed consistent error signature and controlled payload reflection. "
            "Behavior is stable across retries and deviates from baseline. "
            "No evidence of transient network issues."
        )
        return ValidationDecision(Verdict.POC_VALID, 0.82, rationale)


class Orchestrator:
    def __init__(self, modules: List[Module], validator: PoCValidator, cfg: Dict):
        self.modules = modules
        self.validator = validator
        self.cfg = cfg

    def run_target(self, target: Target) -> Dict:
        history: List[HistoryEntry] = []

        if not self._in_scope(target):
            return {
                "status": "aborted",
                "reason": "out_of_scope",
                "history": history,
            }

        for module in self.modules:
            result = module.run(target, self.cfg)

            if result.status in ["error", "timeout"]:
                history.append(
                    HistoryEntry(module.name, Verdict.ERROR, result.status, time.time(), result.metadata)
                )
                continue

            decision = self.validator.validate(result, target)
            history.append(
                HistoryEntry(module.name, decision.verdict, decision.rationale, time.time(), result.metadata)
            )

            if decision.verdict == Verdict.POC_VALID:
                report_id = self._emit_poc_report(target, result, decision)
                return {
                    "status": "poc_valid",
                    "report_id": report_id,
                    "history": history,
                }

        return {
            "status": "no_poc",
            "history": history,
        }

    def _emit_poc_report(self, target: Target, result: ModuleResult, decision: ValidationDecision) -> str:
        # Persist PoC evidence and metadata. Return report identifier.
        return f"report-{target.target_id}-{result.module}"

    def _in_scope(self, target: Target) -> bool:
        # Placeholder: check against program scope list and KYC rules.
        return True


# Example usage
# modules = [IdorModule(), SqliModule(), SstiModule(), XssModule(), LfiModule(), RceModule()]
# validator = PoCValidator(["openai", "ollama", "llamacpp"])
# orchestrator = Orchestrator(modules, validator, cfg)
# result = orchestrator.run_target(target)
