from __future__ import annotations

import json
import re
from typing import Any, Optional

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

from hunterops.attack_chain.types import ValidationDecision, Verdict


SENSITIVE_KEY_RE = re.compile(r"(token|cookie|authorization|session|secret|password|set-cookie|apikey)", re.IGNORECASE)


class PoCValidator:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg if isinstance(cfg, dict) else {}
        heur = self.cfg.get("heuristics", {}) if isinstance(self.cfg.get("heuristics", {}), dict) else {}
        self.require_two_signals = bool(heur.get("require_two_signals", True))
        self.min_confidence = float(heur.get("min_confidence", 0.7) or 0.7)
        self.min_body_diff_ratio = float(heur.get("min_body_diff_ratio", 0.2) or 0.2)
        self.max_body_diff_ratio = float(heur.get("max_body_diff_ratio", 0.9) or 0.9)
        self.min_json_key_diff_ratio = float(heur.get("min_json_key_diff_ratio", 0.2) or 0.2)
        self.min_sensitivity_score = float(heur.get("min_sensitivity_score", 0.55) or 0.55)
        self.baseline_score_threshold = float(heur.get("baseline_score_threshold", 0.45) or 0.45)
        self.llm_cfg = self.cfg.get("llm", {}) if isinstance(self.cfg.get("llm"), dict) else {}
        self.provider_order = self.llm_cfg.get("provider_order", ["ollama", "llamacpp", "openai"])
        self.timeout_s = int(self.llm_cfg.get("timeout_s", 20) or 20)
        self.max_tokens = int(self.llm_cfg.get("max_tokens", 512) or 512)
        self.require_rationale = bool(self.llm_cfg.get("require_rationale", True))

    async def validate(self, evidence: dict[str, Any], module: str, target: str) -> ValidationDecision:
        signals = self.heuristic_signals(evidence)
        if self.require_two_signals and len(signals) < 2:
            return ValidationDecision(
                verdict=Verdict.FALSE_POSITIVE,
                confidence=0.3,
                rationale="insufficient_signals",
                signals=signals,
            )

        llm_decision = await self.llm_triage(evidence, module, target)
        if llm_decision is None:
            return ValidationDecision(
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.5,
                rationale="llm_unavailable_or_failed",
                signals=signals,
            )
        llm_decision.signals = signals
        return llm_decision

    def heuristic_signals(self, evidence: dict[str, Any]) -> list[str]:
        signals: list[str] = []
        baseline_score = float(evidence.get("baseline_score", 0.0) or 0.0)
        suppress_diff = baseline_score >= self.baseline_score_threshold
        if evidence.get("status_diff"):
            signals.append("status_diff")
        if evidence.get("error_signature"):
            signals.append("error_signature")
        if evidence.get("payload_reflected"):
            signals.append("payload_reflected")
        if evidence.get("payload_reflected_encoded"):
            signals.append("payload_reflected")
        if evidence.get("ssti_evaluated"):
            signals.append("ssti_evaluated")
        if evidence.get("lfi_marker"):
            signals.append("lfi_marker")
        if evidence.get("rce_marker"):
            signals.append("rce_marker")
        if evidence.get("idor_anomaly"):
            signals.append("idor_anomaly")
        if evidence.get("open_redirect"):
            signals.append("open_redirect")
        if evidence.get("ssrf_marker"):
            signals.append("ssrf_marker")
        if evidence.get("hits"):
            signals.append("sensitive_misconfig")
        if evidence.get("secret_hits"):
            signals.append("secret_hits")
        if evidence.get("impact_confirmed"):
            signals.append("impact_confirmed")
        sens_score = float(evidence.get("sensitivity_score", 0.0) or 0.0)
        if sens_score >= self.min_sensitivity_score:
            signals.append("sensitivity_score")
        body_ratio = float(evidence.get("body_diff_ratio", 0.0) or 0.0)
        if not suppress_diff and body_ratio >= self.min_body_diff_ratio and body_ratio <= self.max_body_diff_ratio:
            signals.append("body_diff_ratio")
        json_ratio = evidence.get("json_key_diff_ratio")
        if json_ratio is not None:
            try:
                if not suppress_diff and float(json_ratio) >= self.min_json_key_diff_ratio:
                    signals.append("json_key_diff_ratio")
            except Exception:
                pass
        return signals

    async def llm_triage(self, evidence: dict[str, Any], module: str, target: str) -> Optional[ValidationDecision]:
        providers = [str(x).strip().lower() for x in self.provider_order if str(x).strip()]
        for provider in providers:
            try:
                return await self._call_llm(provider, evidence, module, target)
            except Exception:
                continue
        return None

    async def _call_llm(self, provider: str, evidence: dict[str, Any], module: str, target: str) -> ValidationDecision:
        if provider == "openai":
            return await self._call_openai(evidence, module, target)
        if provider == "ollama":
            return await self._call_ollama(evidence, module, target)
        if provider == "llamacpp":
            return await self._call_llamacpp(evidence, module, target)
        raise ValueError(f"Unsupported LLM provider: {provider}")

    def _build_prompt(self, evidence: dict[str, Any], module: str, target: str) -> str:
        sanitized = self._sanitize_evidence(evidence)
        return (
            "You are a senior application security analyst. "
            "Classify the PoC as 'poc_valid', 'inconclusive', or 'false_positive'. "
            "Return JSON with keys: verdict, confidence, rationale. "
            "Rationale must be 2-4 sentences.\n\n"
            f"Module: {module}\nTarget: {target}\nEvidence: {json.dumps(sanitized, ensure_ascii=True)}\n"
        )

    def _sanitize_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        sanitized: dict[str, Any] = {}
        for key, value in (evidence or {}).items():
            if key in {"body", "body_sample", "response_text"}:
                continue
            if SENSITIVE_KEY_RE.search(str(key)):
                continue
            if isinstance(value, str) and len(value) > 500:
                sanitized[key] = value[:500] + "..."
                continue
            sanitized[key] = value
        return sanitized

    def _parse_llm_json(self, content: str) -> ValidationDecision:
        payload = self._extract_json(content)
        verdict_raw = str(payload.get("verdict", "inconclusive")).strip().lower()
        if verdict_raw not in {"poc_valid", "inconclusive", "false_positive"}:
            verdict_raw = "inconclusive"
        confidence = float(payload.get("confidence", 0.5) or 0.5)
        rationale = str(payload.get("rationale", ""))
        if self.require_rationale and (len(rationale.split()) < 6):
            rationale = "LLM response missing sufficient rationale."
        if verdict_raw == "poc_valid" and confidence < self.min_confidence:
            verdict_raw = "inconclusive"
        return ValidationDecision(Verdict(verdict_raw), confidence, rationale)

    def _extract_json(self, content: str) -> dict[str, Any]:
        try:
            return json.loads(content)
        except Exception:
            pass
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                return {}
        return {}

    async def _call_openai(self, evidence: dict[str, Any], module: str, target: str) -> ValidationDecision:
        api_key = str(__import__("os").environ.get("OPENAI_API_KEY", "")).strip()
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        if httpx is None:
            raise RuntimeError("httpx not available")
        prompt = self._build_prompt(evidence, module, target)
        payload = {
            "model": str(__import__("os").environ.get("OPENAI_MODEL", "gpt-4o-mini")),
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": "You are an application security analyst."},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": self.max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
        if resp.status_code >= 300:
            raise RuntimeError(f"OpenAI error: {resp.status_code}")
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return self._parse_llm_json(content or "")

    async def _call_ollama(self, evidence: dict[str, Any], module: str, target: str) -> ValidationDecision:
        if httpx is None:
            raise RuntimeError("httpx not available")
        base_url = str(__import__("os").environ.get("OLLAMA_URL", "http://localhost:11434"))
        model = str(__import__("os").environ.get("OLLAMA_MODEL", "llama3.1"))
        prompt = self._build_prompt(evidence, module, target)
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.post(f"{base_url}/api/generate", json=payload)
        if resp.status_code >= 300:
            raise RuntimeError(f"Ollama error: {resp.status_code}")
        data = resp.json()
        content = data.get("response", "")
        return self._parse_llm_json(content or "")

    async def _call_llamacpp(self, evidence: dict[str, Any], module: str, target: str) -> ValidationDecision:
        if httpx is None:
            raise RuntimeError("httpx not available")
        url = str(__import__("os").environ.get("LLAMACPP_URL", "http://localhost:8080/completion"))
        prompt = self._build_prompt(evidence, module, target)
        payload = {"prompt": prompt, "n_predict": self.max_tokens, "temperature": 0.1}
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.post(url, json=payload)
        if resp.status_code >= 300:
            raise RuntimeError(f"llama.cpp error: {resp.status_code}")
        data = resp.json()
        content = data.get("content", data.get("completion", ""))
        return self._parse_llm_json(content or "")
