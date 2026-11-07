"""Domain models for triage results."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class LogEvent:
    """One normalised log line, whatever the source format."""

    timestamp: str
    source: str          # e.g. "auth" or "app"
    kind: str            # e.g. "failed_login", "accepted_login", "http_request"
    detail: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Detection:
    """A finding the agent considers worth a human's attention."""

    rule: str
    severity: Severity
    summary: str
    evidence: str
    runbook: Optional[str] = None
    recommended_action: str = ""


@dataclass
class IncidentReport:
    """The agent's output: every detection, ranked, ready to paste into an incident channel."""

    agent: str
    detections: list[Detection] = field(default_factory=list)

    def add(self, detection: Detection) -> None:
        self.detections.append(detection)

    @property
    def worst_severity(self) -> Severity:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(d.severity == sev for d in self.detections):
                return sev
        return Severity.INFO

    def to_markdown(self) -> str:
        lines = [
            f"# Incident triage report — {self.agent}",
            "",
            f"Worst severity: **{self.worst_severity.value}** — {len(self.detections)} detection(s).",
            "",
        ]
        if not self.detections:
            lines.append("No anomalies found. Baseline looks healthy.")
            return "\n".join(lines)
        for i, d in enumerate(sorted(self.detections, key=lambda x: x.severity.name != "CRITICAL"), 1):
            lines.extend([
                f"## {i}. [{d.severity.value}] {d.rule}",
                "",
                f"- **Summary:** {d.summary}",
                f"- **Evidence:** {d.evidence}",
            ])
            if d.runbook:
                lines.append(f"- **Runbook:** `{d.runbook}`")
            if d.recommended_action:
                lines.append(f"- **Recommended action:** {d.recommended_action}")
            lines.append("")
        return "\n".join(lines)
