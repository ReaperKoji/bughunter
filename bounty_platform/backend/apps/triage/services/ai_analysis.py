from __future__ import annotations

import os
from typing import Any

from openai import OpenAI


SYSTEM_PROMPT = (
    "You are a senior application security triage analyst. "
    "Classify likely false positive vs actionable finding, explain impact in business language, "
    "and propose safe manual validation questions. Do not provide exploit payloads."
)


def analyze_http_finding(*, title: str, endpoint: str, response_body: str, headers: dict[str, Any] | None = None) -> dict[str, Any]:
    provider = str(os.getenv("LLM_PROVIDER", "openai")).strip().lower()
    if provider != "openai":
        return {
            "provider": provider,
            "status": "unsupported_provider",
            "summary": "No supported LLM provider configured.",
        }

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return {
            "provider": "openai",
            "status": "missing_api_key",
            "summary": "OPENAI_API_KEY is not configured.",
        }

    client = OpenAI(api_key=api_key)
    user_prompt = (
        f"Title: {title}\n"
        f"Endpoint: {endpoint}\n"
        f"Headers: {headers or {}}\n"
        f"Response body (truncated):\n{response_body[:6000]}\n\n"
        "Return JSON with keys: confidence, likely_false_positive, business_impact, validation_questions, remediation_hint."
    )

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        temperature=0.1,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    content = resp.choices[0].message.content if resp.choices else ""
    return {
        "provider": "openai",
        "status": "ok",
        "raw": content,
    }
