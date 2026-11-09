"""Tests for principal scoring and grading."""

from __future__ import annotations

import os

from trailtriage.events import load_events
from trailtriage.rules import Finding, run_rules
from trailtriage.scoring import PrincipalScore, score_principals

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "cloudtrail-sample.json")


def _finding(rule_id="R", severity=1, principal="arn:aws:iam::1:user/a", chain="", event_count=1):
    return Finding(
        rule_id=rule_id,
        title="t",
        severity=severity,
        technique="tech",
        principal=principal,
        principal_type="IAMUser",
        first_seen="2026-11-08T01:00:00Z",
        last_seen="2026-11-08T01:05:00Z",
        event_count=event_count,
        evidence=["2026-11-08T01:00:00Z s3:GetObject from 198.51.100.77 [ok]"],
        chain=chain,
    )


class TestScoring:
    def test_groups_by_principal(self):
        scores = score_principals([
            _finding(principal="a"),
            _finding(principal="a"),
            _finding(principal="b"),
        ])
        assert len(scores) == 2
        assert {s.principal: s.finding_count for s in scores} == {"a": 2, "b": 1}

    def test_higher_severity_scores_higher(self):
        low = score_principals([_finding(severity=1)])[0]
        crit = score_principals([_finding(severity=4)])[0]
        assert crit.score > low.score

    def test_chain_multiplies_score(self):
        plain = score_principals([_finding(severity=3)])[0]
        chained = score_principals([_finding(severity=3, chain="x")])[0]
        assert chained.score == plain.score * 2

    def test_many_lows_do_not_beat_one_critical(self):
        many = score_principals([_finding(rule_id=f"R{i}", severity=1) for i in range(40)])[0]
        single = score_principals([_finding(severity=4)])[0]
        assert single.score > many.score

    def test_grades_follow_worst_finding(self):
        assert score_principals([_finding(severity=4)])[0].grade == "critical"
        assert score_principals([_finding(severity=3)])[0].grade == "high"
        assert score_principals([_finding(severity=2)])[0].grade == "medium"
        assert score_principals([_finding(severity=1)])[0].grade == "low"

    def test_chain_escalates_one_band(self):
        assert score_principals([_finding(severity=3)])[0].grade == "high"
        assert score_principals([_finding(severity=3, chain="c")])[0].grade == "critical"

    def test_grade_not_diluted_by_many_lows(self):
        findings = [_finding(rule_id=f"R{i}", severity=1) for i in range(40)]
        findings.append(_finding(rule_id="BOOM", severity=4))
        assert score_principals(findings)[0].grade == "critical"

    def test_sorted_worst_first(self):
        scores = score_principals([
            _finding(principal="low", severity=1),
            _finding(principal="bad", severity=4, chain="c"),
        ])
        assert scores[0].principal == "bad"

    def test_chains_extracted(self):
        score = score_principals([_finding(chain="a"), _finding(chain="b"), _finding(chain="a")])[0]
        assert score.chains == ["a", "b"]

    def test_source_ips_extracted_from_evidence(self):
        assert "198.51.100.77" in score_principals([_finding()])[0].source_ips

    def test_empty_input(self):
        assert score_principals([]) == []

    def test_to_dict_shape(self):
        payload = score_principals([_finding(severity=3)])[0].to_dict()
        assert set(payload) >= {"principal", "score", "grade", "findings", "chains"}
        assert isinstance(payload["findings"], list)

    def test_repeat_events_add_diminishing_weight(self):
        once = score_principals([_finding(severity=3, event_count=1)])[0].score
        many = score_principals([_finding(severity=3, event_count=500)])[0].score
        assert many > once
        assert many < once * 3


class TestFixtureScores:
    def test_worst_principal_is_an_attacker(self, ):
        scores = score_principals(run_rules(load_events(FIXTURE)))
        assert scores[0].grade in {"high", "critical"}
        assert scores[0].finding_count >= 1

    def test_ci_not_in_scores(self):
        scores = score_principals(run_rules(load_events(FIXTURE)))
        assert not [s for s in scores if "ci-deploy" in s.principal]

    def test_principal_score_properties(self):
        score = PrincipalScore(principal="p", principal_type="IAMUser", score=9.0, grade="medium",
                               findings=[_finding(severity=3), _finding(severity=2)])
        assert score.max_severity == 3
        assert score.finding_count == 2
