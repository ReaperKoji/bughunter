from __future__ import annotations

import re
from typing import Any

EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
PHONE_RE = re.compile(r"\b(\+?\d{1,3})?[\s.-]?\(?\d{2,3}\)?[\s.-]?\d{3,4}[\s.-]?\d{4}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
CPF_RE = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b")
CNPJ_RE = re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b|\b\d{14}\b")
TOKEN_RE = re.compile(r"\b(?:sk_live|sk_test|ghp|xox[baprs]|AIza)[0-9A-Za-z_-]{8,}\b")
BALANCE_RE = re.compile(r"\b(?:balance|saldo|available)\b", re.IGNORECASE)
ACCOUNT_RE = re.compile(r"\b(?:account|iban|wallet|portfolio|transaction|order|trade)\b", re.IGNORECASE)


def sensitivity_score(text: str, injected_values: list[str] | None = None) -> tuple[float, dict[str, Any]]:
    sample = str(text or "")
    if not sample:
        return 0.0, {"hits": {}, "injected_match": False}
    hits: dict[str, int] = {}
    weights = {
        "email": 0.2,
        "phone": 0.15,
        "iban": 0.25,
        "cpf": 0.2,
        "cnpj": 0.2,
        "token": 0.25,
        "balance": 0.1,
        "account": 0.1,
    }
    hits["email"] = len(EMAIL_RE.findall(sample))
    hits["phone"] = len(PHONE_RE.findall(sample))
    hits["iban"] = len(IBAN_RE.findall(sample))
    hits["cpf"] = len(CPF_RE.findall(sample))
    hits["cnpj"] = len(CNPJ_RE.findall(sample))
    hits["token"] = len(TOKEN_RE.findall(sample))
    hits["balance"] = len(BALANCE_RE.findall(sample))
    hits["account"] = len(ACCOUNT_RE.findall(sample))

    injected_values = injected_values or []
    injected_match = any(val and val in sample for val in injected_values)

    score = 0.0
    for key, count in hits.items():
        if count:
            score += weights.get(key, 0.05)
    if injected_match:
        score += 0.2
    score = min(1.0, score)
    return round(score, 4), {"hits": hits, "injected_match": injected_match}

