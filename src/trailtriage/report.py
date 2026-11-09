"""Render findings as text, Markdown or JSON for humans, tickets and CI."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .scoring import PrincipalScore

__all__ = ["render_json", "render_text", "render_markdown", "exit_code"]


def _generated_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_summary(scores: list[PrincipalScore], event_count: int, principal_count: int) -> dict:
    by_grade: dict[str, int] = {}
    for score in scores:
        by_grade[score.grade] = by_grade.get(score.grade, 0) + 1
    return {
        "generated_at": _generated_at(),
        "tool": "trailtriage",
        "events_analyzed": event_count,
        "principals_analyzed": principal_count,
        "principals_flagged": len(scores),
        "by_grade": by_grade,
        "finding_count": sum(s.finding_count for s in scores),
    }


def render_json(scores: list[PrincipalScore], event_count: int, principal_count: int) -> str:
    payload = {
        "summary": build_summary(scores, event_count, principal_count),
        "principals": [s.to_dict() for s in scores],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def render_text(scores: list[PrincipalScore], event_count: int, principal_count: int, top: int = 0) -> str:
    summary = build_summary(scores, event_count, principal_count)
    lines = [
        "trailtriage - CloudTrail identity attack triage",
        f"generated {summary['generated_at']}",
        f"{event_count} events / {principal_count} principals / {len(scores)} flagged "
        f"/ {summary['finding_count']} findings",
        "",
    ]
    if not scores:
        lines.append("No findings. Nothing in this window matched an identity-attack pattern.")
        return "\n".join(lines)

    shown = scores[:top] if top else scores
    for index, score in enumerate(shown, start=1):
        lines.append(f"{index}. [{score.grade.upper()}] {score.principal}")
        lines.append(
            f"   score {score.score:.1f} | {score.finding_count} finding(s) | type {score.principal_type}"
        )
        if score.chains:
            lines.append(f"   chains: {', '.join(score.chains)}")
        for finding in score.findings:
            tag = f" chain:{finding.chain}" if finding.chain else ""
            lines.append(
                f"   - {finding.rule_id} {finding.title} "
                f"[{finding.severity_label}]{tag} ({finding.event_count} events)"
            )
            for item in finding.evidence[:3]:
                lines.append(f"       {item}")
        lines.append("")

    remaining = len(scores) - len(shown)
    if remaining > 0:
        lines.append(f"... and {remaining} more principal(s). Use --top 0 to see all.")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(scores: list[PrincipalScore], event_count: int, principal_count: int, top: int = 0) -> str:
    summary = build_summary(scores, event_count, principal_count)
    out = [
        "# trailtriage report",
        "",
        f"Generated `{summary['generated_at']}`",
        "",
        f"- **{event_count}** events analyzed",
        f"- **{principal_count}** principals analyzed",
        f"- **{len(scores)}** principals flagged",
        f"- **{summary['finding_count']}** findings",
        "",
    ]
    if not scores:
        out.append("No findings in this window.")
        return "\n".join(out)

    out.extend(["## Flagged principals", "", "| Grade | Principal | Score | Findings | Chains |", "|---|---|---|---|---|"])
    shown = scores[:top] if top else scores
    for score in shown:
        chains = ", ".join(score.chains) or "-"
        out.append(
            f"| {score.grade} | `{score.principal}` | {score.score:.1f} | {score.finding_count} | {chains} |"
        )
    out.append("")
    for score in shown:
        out.extend([f"### {score.grade.upper()}: `{score.principal}`", ""])
        out.append(f"Score **{score.score:.1f}** across {score.finding_count} finding(s).")
        out.append("")
        for finding in score.findings:
            out.append(f"**{finding.rule_id} {finding.title}** ({finding.severity_label})")
            out.append("")
            out.append(f"- Technique: {finding.technique}")
            out.append(f"- Window: {finding.first_seen} to {finding.last_seen}")
            out.append(f"- Events: {finding.event_count}")
            if finding.chain:
                out.append(f"- Chain: `{finding.chain}`")
            for item in finding.evidence:
                out.append(f"  - `{item}`")
            out.append(f"- Fix: {finding.remediation}")
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def exit_code(scores: list[PrincipalScore], fail_on: str = "high") -> int:
    """CI gate. Returns 1 when any principal reaches the ``fail_on`` grade."""
    order = ["low", "medium", "high", "critical"]
    if fail_on not in order:
        return 0
    threshold = order.index(fail_on)
    for score in scores:
        if order.index(score.grade) >= threshold:
            return 1
    return 0
