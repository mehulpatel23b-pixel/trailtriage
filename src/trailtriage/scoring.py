"""Risk scoring for principals.

Two numbers matter in a triage queue:

* **score** - how bad this principal looks overall, weighted by severity and chains.
  Chains multiply because a proven sequence is far more damning than the same number of
  unrelated signals.
* **grade** - a coarse band (critical / high / medium / low) so an analyst can sort the
  queue without reading numbers. It is driven by the *worst* finding, not by the sum: a
  principal with one critical finding is critical even when its arithmetic score is low,
  because burying a confirmed critical alert under a numeric threshold is how real
  incidents get promoted-but-ignored. Chains count one band higher than a lone signal with
  the same severity, since a proven sequence is stronger evidence than a single call.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .rules import SEVERITY_WEIGHT, Finding

__all__ = ["PrincipalScore", "score_principals", "GRADE_ORDER"]

GRADE_ORDER = ["low", "medium", "high", "critical"]


def _band(severity: int) -> str:
    if severity >= 4:
        return "critical"
    if severity == 3:
        return "high"
    if severity == 2:
        return "medium"
    return "low"


@dataclass
class PrincipalScore:
    principal: str
    principal_type: str
    score: float
    grade: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def max_severity(self) -> int:
        return max((f.severity for f in self.findings), default=0)

    @property
    def chains(self) -> list[str]:
        return sorted({f.chain for f in self.findings if f.chain})

    @property
    def source_ips(self) -> list[str]:
        ips: list[str] = []
        for finding in self.findings:
            for line in finding.evidence:
                for token in line.split():
                    if token.count(".") == 3 and token.replace(".", "").isdigit():
                        if token not in ips:
                            ips.append(token)
        return ips

    def to_dict(self) -> dict:
        return {
            "principal": self.principal,
            "principal_type": self.principal_type,
            "score": round(self.score, 2),
            "grade": self.grade,
            "finding_count": self.finding_count,
            "max_severity": self.max_severity,
            "chains": self.chains,
            "source_ips": self.source_ips,
            "findings": [f.to_dict() for f in self.findings],
        }


def _finding_weight(finding: Finding) -> float:
    weight = SEVERITY_WEIGHT.get(finding.severity, 1.0)
    if finding.chain:
        weight *= 2.0
    # Repeat occurrences add diminishing weight, not linear.
    return weight * (1.0 + math.log1p(max(0, finding.event_count - 1)) * 0.15)


def _score_findings(findings: list[Finding]) -> float:
    """Worst finding dominates, the rest add damped weight.

    A plain sum would let forty low-severity noise findings outrank one critical attack
    chain, which is exactly the ranking mistake a triage tool must not make.
    """
    if not findings:
        return 0.0
    weights = sorted((_finding_weight(f) for f in findings), reverse=True)
    return weights[0] + sum(weights[1:]) * 0.25


def _grade(findings: list[Finding]) -> str:
    """Band the principal by its worst finding, letting chains escalate one step."""
    worst = 0
    for finding in findings:
        effective = finding.severity + (1 if finding.chain else 0)
        worst = max(worst, min(4, effective))
    return _band(worst)


def score_principals(findings: list[Finding]) -> list[PrincipalScore]:
    """Aggregate findings into one score per principal, worst first."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.principal, []).append(finding)

    scores: list[PrincipalScore] = []
    for principal, items in grouped.items():
        value = _score_findings(items)
        scores.append(
            PrincipalScore(
                principal=principal,
                principal_type=items[0].principal_type,
                score=value,
                grade=_grade(items),
                findings=sorted(items, key=lambda f: (-f.severity, f.rule_id)),
            )
        )
    scores.sort(key=lambda s: (-s.score, s.principal))
    return scores
