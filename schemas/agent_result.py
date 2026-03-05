from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class AgentResult:
    agent: str                  # Which agent produced this: "behavioral", "semantic"
    risk_score: float           # 0.0 (safe) to 1.0 (dangerous)
    flags: List[str] = field(default_factory=list)       # What was detected, e.g. ["high_request_rate"]
    explanation: str = ""       # Human-readable summary
    metadata: Dict = field(default_factory=dict)          # Extra data like feature values