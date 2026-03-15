from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


_PROHIBITIVE_PATTERNS = [
    r"no automated scanning",
    r"do not use automated scanners",
    r"do not use automatic scanners",
    r"no automated tools",
    r"no automatic tools",
    r"automation is not allowed",
    r"automated scanning is prohibited",
    r"scanners are not allowed",
]


@dataclass
class RulesDecision:
    automation_allowed: bool
    manual_only: bool
    reason: str


def check_automation_allowed(program_rules_text: str) -> RulesDecision:
    text = str(program_rules_text or "").strip().lower()
    if not text:
        return RulesDecision(automation_allowed=True, manual_only=False, reason="no_rules_text")
    for pat in _PROHIBITIVE_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return RulesDecision(automation_allowed=False, manual_only=True, reason=f"matched:{pat}")
    return RulesDecision(automation_allowed=True, manual_only=False, reason="allowed")


def summary(decision: RulesDecision) -> dict[str, Any]:
    return {
        "automation_allowed": decision.automation_allowed,
        "manual_only": decision.manual_only,
        "reason": decision.reason,
    }
