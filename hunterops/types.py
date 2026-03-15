from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Task:
    plugin: str
    target: str
    payload: dict[str, Any] = field(default_factory=dict)
    task_id: str = ""


@dataclass
class Finding:
    plugin: str
    target: str
    category: str
    severity: str
    title: str
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
