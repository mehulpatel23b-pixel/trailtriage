"""Tests for report rendering and CI exit codes."""

from __future__ import annotations

import json
import os

from trailtriage.events import load_events
from trailtriage.report import exit_code, render_json, render_markdown, render_text
from trailtriage.rules import Finding, run_rules
from trailtriage.scoring import PrincipalScore, score_principals

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "cloudtrail-sample.json")


def _scores():
    return score_principals(run_rules(load_events(FIXTURE)))


class TestJsonReport:
    def test_valid_json_with_summary(self):
        payload = json.loads(render_json(_scores(), 75, 6))
        assert payload["summary"]["events_analyzed"] == 75
        assert payload["summary"]["tool"] == "trailtriage"
        assert isinstance(payload["principals"], list)

    def test_empty_scores_still_valid(self):
        payload = json.loads(render_json([], 0, 0))
        assert payload["principals"] == []
        assert payload["summary"]["principals_flagged"] == 0


class TestTextReport:
    def test_contains_header_and_findings(self):
        text = render_text(_scores(), 75, 6)
        assert "trailtriage" in text
        assert "flagged" in text
        assert "TRAIL-" in text or "CHAIN-" in text

    def test_clean_text_message(self):
        assert "No findings" in render_text([], 10, 1)

    def test_top_limits_output(self):
        scores = _scores()
        if len(scores) < 2:
            return
        text = render_text(scores, 75, 6, top=1)
        assert "more principal(s)" in text

    def test_evidence_indented(self):
        assert " from " in render_text(_scores(), 75, 6)


class TestMarkdownReport:
    def test_table_and_sections(self):
        md = render_markdown(_scores(), 75, 6)
        assert md.startswith("# trailtriage report")
        assert "| Grade | Principal |" in md
        assert "**" in md

    def test_clean_markdown(self):
        assert "No findings" in render_markdown([], 0, 0)


class TestExitCode:
    def _score(self, grade):
        return PrincipalScore(principal="p", principal_type="IAMUser", score=1.0, grade=grade, findings=[_finding()])

    def test_no_findings_passes(self):
        assert exit_code([], "high") == 0

    def test_critical_fails_on_high(self):
        assert exit_code([self._score("critical")], "high") == 1

    def test_medium_passes_on_high(self):
        assert exit_code([self._score("medium")], "high") == 0

    def test_critical_fails_on_critical(self):
        assert exit_code([self._score("critical")], "critical") == 1

    def test_high_does_not_fail_on_critical(self):
        assert exit_code([self._score("high")], "critical") == 0

    def test_fail_on_none_never_fails(self):
        assert exit_code([self._score("critical")], "none") == 0

    def test_low_threshold_catches_low(self):
        assert exit_code([self._score("low")], "low") == 1


def _finding():
    return Finding(rule_id="R1", title="t", severity=1, technique="x", principal="p",
                   principal_type="IAMUser", first_seen="a", last_seen="b", event_count=1)
