from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    POC_VALID = "poc_valid"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"
    NO_POC = "no_poc"
    ERROR = "error"
    ABORTED = "aborted"


@dataclass
class Target:
    target_id: str
    url: str
    program_id: str
    scope_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    module: str
    status: str
    evidence: dict[str, Any]
    candidate_poc: str
    metadata: dict[str, Any]


@dataclass
class ValidationDecision:
    verdict: Verdict
    confidence: float
    rationale: str
    signals: list[str] = field(default_factory=list)


@dataclass
class HistoryEntry:
    module: str
    verdict: Verdict
    reason: str
    ts: float
    metadata: dict[str, Any] = field(default_factory=dict)
