"""Tests for detection rules and chain correlation."""

from __future__ import annotations

import os

import pytest

from trailtriage.events import load_events
from trailtriage.rules import CHAIN_RULES, RULES, Finding, run_rules

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "cloudtrail-sample.json")


def _record(eid, time, name, arn, ptype="IAMUser", source="iam.amazonaws.com",
            ip="203.0.113.45", err="", mfa="false", key="AKIA1", params=None, response=None):
    identity = {"type": ptype, "arn": arn, "accessKeyId": key, "accountId": "111122223333"}
    if ptype == "Root":
        identity = {"type": "Root", "arn": "arn:aws:iam::111122223333:root", "accountId": "111122223333"}
    identity.setdefault("sessionContext", {"attributes": {"mfaAuthenticated": mfa}})
    return {
        "eventID": eid,
        "eventTime": time,
        "eventName": name,
        "eventSource": source,
        "awsRegion": "us-east-1",
        "sourceIPAddress": ip,
        "errorCode": err,
        "recipientAccountId": "111122223333",
        "userIdentity": identity,
        "requestParameters": params or {},
        "responseElements": response or {},
    }


def _events(records):
    from trailtriage.events import parse_records

    return parse_records(records)


@pytest.fixture(scope="module")
def fixture_events():
    return load_events(FIXTURE)


def _ids(findings):
    return {f.rule_id for f in findings}


class TestFixtureEndToEnd:
    def test_flags_the_attack_stories(self, fixture_events):
        findings = run_rules(fixture_events)
        ids = _ids(findings)
        assert "CHAIN-001" in ids, "fresh key then S3 drain must be caught"
        assert "CHAIN-002" in ids, "logging disabled then secrets read must be caught"
        assert "TRAIL-001" in ids, "root login without MFA must be caught"
        assert "TRAIL-009" in ids, "denial burst must be caught"

    def test_benign_ci_is_not_flagged(self, fixture_events):
        findings = run_rules(fixture_events)
        ci = [f for f in findings if "ci-deploy" in f.principal]
        assert ci == [], f"CI automation produced false positives: {[f.rule_id for f in ci]}"

    def test_chain_findings_have_chain_label(self, fixture_events):
        findings = [f for f in run_rules(fixture_events) if f.rule_id.startswith("CHAIN-")]
        assert findings
        assert all(f.chain for f in findings)

    def test_sorted_by_severity(self, fixture_events):
        findings = run_rules(fixture_events)
        severities = [f.severity for f in findings]
        assert severities == sorted(severities, reverse=True)

    def test_no_findings_on_clean_traffic(self):
        clean = _events([
            _record("c1", "2026-11-08T01:00:00Z", "DescribeInstances", "arn:aws:iam::111122223333:role/app",
                    ptype="AssumedRole", source="ec2.amazonaws.com", ip="10.0.0.5"),
            _record("c2", "2026-11-08T01:05:00Z", "GetObject", "arn:aws:iam::111122223333:role/app",
                    ptype="AssumedRole", source="s3.amazonaws.com", ip="10.0.0.5"),
        ])
        assert run_rules(clean) == []


class TestRootRules:
    def test_root_without_mfa_is_critical(self):
        events = _events([
            _record("r1", "2026-11-08T01:00:00Z", "ConsoleLogin", "arn:aws:iam::111122223333:root",
                    ptype="Root", source="signin.amazonaws.com", key=""),
        ])
        findings = run_rules(events)
        root = [f for f in findings if f.rule_id == "TRAIL-001"]
        assert len(root) == 1
        assert root[0].severity == 4
        assert "without MFA" in root[0].title

    def test_root_with_mfa_is_high_not_critical(self):
        events = _events([
            _record("r1", "2026-11-08T01:00:00Z", "ConsoleLogin", "arn:aws:iam::111122223333:root",
                    ptype="Root", source="signin.amazonaws.com", key="", mfa="true"),
        ])
        root = [f for f in run_rules(events) if f.rule_id == "TRAIL-001"]
        assert root[0].severity == 3

    def test_root_chain_detected(self):
        events = _events([
            _record("r1", "2026-11-08T01:00:00Z", "ConsoleLogin", "arn:aws:iam::111122223333:root",
                    ptype="Root", source="signin.amazonaws.com", key="", mfa="false"),
            _record("r2", "2026-11-08T01:10:00Z", "CreateUser", "arn:aws:iam::111122223333:root",
                    ptype="Root", key="", params={"userName": "backdoor"}),
        ])
        assert "CHAIN-004" in _ids(run_rules(events))


class TestDefenseEvasion:
    @pytest.mark.parametrize(
        "action",
        ["StopLogging", "DeleteTrail", "PutEventSelectors"],
    )
    def test_cloudtrail_tamper(self, action):
        events = _events([
            _record("t1", "2026-11-08T01:00:00Z", action, "arn:aws:iam::111122223333:user/admin",
                    source="cloudtrail.amazonaws.com"),
        ])
        findings = [f for f in run_rules(events) if f.rule_id == "TRAIL-002"]
        assert findings and findings[0].severity == 4

    @pytest.mark.parametrize(
        "source,action",
        [
            ("guardduty.amazonaws.com", "DeleteDetector"),
            ("config.amazonaws.com", "StopConfigurationRecorder"),
            ("securityhub.amazonaws.com", "DisableSecurityHub"),
            ("ec2.amazonaws.com", "DeleteFlowLogs"),
            ("logs.amazonaws.com", "DeleteLogGroup"),
        ],
    )
    def test_detection_disable(self, source, action):
        events = _events([
            _record("t2", "2026-11-08T01:00:00Z", action, "arn:aws:iam::111122223333:user/admin", source=source),
        ])
        assert "TRAIL-003" in _ids(run_rules(events))

    def test_failed_tamper_attempt_not_reported_as_success(self):
        events = _events([
            _record("t3", "2026-11-08T01:00:00Z", "StopLogging", "arn:aws:iam::111122223333:user/low",
                    source="cloudtrail.amazonaws.com", err="AccessDenied"),
        ])
        assert "TRAIL-002" not in _ids(run_rules(events))


class TestPersistenceRules:
    @pytest.mark.parametrize(
        "action",
        ["CreateUser", "CreateLoginProfile", "AttachUserPolicy", "UpdateAssumeRolePolicy"],
    )
    def test_iam_persistence(self, action):
        events = _events([
            _record("p1", "2026-11-08T01:00:00Z", action, "arn:aws:iam::111122223333:user/admin"),
        ])
        assert "TRAIL-004" in _ids(run_rules(events))

    def test_mfa_removal_critical(self):
        events = _events([
            _record("p2", "2026-11-08T01:00:00Z", "DeactivateMFADevice", "arn:aws:iam::111122223333:user/admin"),
        ])
        mfa = [f for f in run_rules(events) if f.rule_id == "TRAIL-005"]
        assert mfa[0].severity == 4

    def test_guardrail_detach(self):
        events = _events([
            _record("p3", "2026-11-08T01:00:00Z", "DetachRolePolicy", "arn:aws:iam::111122223333:user/admin"),
        ])
        assert "TRAIL-012" in _ids(run_rules(events))


class TestPublicExposure:
    @pytest.mark.parametrize(
        "uri",
        ["http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"],
    )
    def test_public_snapshot(self, uri):
        events = _events([
            _record("s1", "2026-11-08T01:00:00Z", "ModifySnapshotAttribute",
                    "arn:aws:iam::111122223333:user/dev", source="ec2.amazonaws.com",
                    params={"createVolumePermission": {"add": {"items": [{"group": "all"}]}}, "uri": uri}),
        ])
        assert "TRAIL-006" in _ids(run_rules(events))

    def test_public_bucket_policy(self):
        events = _events([
            _record("s2", "2026-11-08T01:00:00Z", "PutBucketPolicy",
                    "arn:aws:iam::111122223333:user/dev", source="s3.amazonaws.com",
                    params={"bucketPolicy": {"Statement": [{"Principal": "*"}]}}),
        ])
        assert "TRAIL-006" in _ids(run_rules(events))

    def test_private_snapshot_not_flagged(self):
        events = _events([
            _record("s3", "2026-11-08T01:00:00Z", "ModifySnapshotAttribute",
                    "arn:aws:iam::111122223333:user/dev", source="ec2.amazonaws.com",
                    params={"userIds": ["999988887777"]}),
        ])
        assert "TRAIL-006" not in _ids(run_rules(events))


class TestVolumeAndRecon:
    def test_bulk_reads_flagged(self):
        records = [
            _record(f"v{i}", f"2026-11-08T01:{i // 60:02d}:{i % 60:02d}Z", "GetObject",
                    "arn:aws:iam::111122223333:user/reader", source="s3.amazonaws.com")
            for i in range(60)
        ]
        assert "TRAIL-007" in _ids(run_rules(_events(records)))

    def test_below_threshold_not_flagged(self):
        records = [
            _record(f"v{i}", f"2026-11-08T01:{i:02d}:00Z", "GetObject",
                    "arn:aws:iam::111122223333:user/reader", source="s3.amazonaws.com")
            for i in range(10)
        ]
        assert "TRAIL-007" not in _ids(run_rules(_events(records)))

    def test_broad_recon_flagged(self):
        services = [("ec2", "DescribeInstances"), ("s3", "ListBuckets"), ("iam", "ListUsers"),
                    ("rds", "DescribeDBInstances"), ("lambda", "ListFunctions")]
        records = []
        for i in range(30):
            svc, action = services[i % len(services)]
            records.append(_record(f"re{i}", f"2026-11-08T02:{i:02d}:00Z", action,
                                   "arn:aws:iam::111122223333:user/scanner", source=f"{svc}.amazonaws.com"))
        # add distinct names to clear the 25 distinct-action bar
        for i in range(22):
            records.append(_record(f"rf{i}", f"2026-11-08T03:{i:02d}:00Z", f"DescribeThing{i}",
                                   "arn:aws:iam::111122223333:user/scanner", source="ec2.amazonaws.com"))
        assert "TRAIL-008" in _ids(run_rules(_events(records)))

    def test_narrow_usage_not_recon(self):
        records = [
            _record(f"n{i}", f"2026-11-08T02:{i:02d}:00Z", "DescribeInstances",
                    "arn:aws:iam::111122223333:user/app", source="ec2.amazonaws.com")
            for i in range(20)
        ]
        assert "TRAIL-008" not in _ids(run_rules(_events(records)))

    def test_denied_burst(self):
        records = [
            _record(f"d{i}", f"2026-11-08T04:{i:02d}:00Z", "DeleteUser",
                    "arn:aws:iam::111122223333:user/jr", err="AccessDenied")
            for i in range(12)
        ]
        assert "TRAIL-009" in _ids(run_rules(_events(records)))

    def test_few_denials_ignored(self):
        records = [
            _record(f"d{i}", f"2026-11-08T04:{i:02d}:00Z", "DeleteUser",
                    "arn:aws:iam::111122223333:user/jr", err="AccessDenied")
            for i in range(3)
        ]
        assert "TRAIL-009" not in _ids(run_rules(_events(records)))


class TestKmsAndConsole:
    def test_kms_key_deletion(self):
        events = _events([
            _record("k1", "2026-11-08T01:00:00Z", "ScheduleKeyDeletion",
                    "arn:aws:iam::111122223333:user/admin", source="kms.amazonaws.com"),
        ])
        assert "TRAIL-010" in _ids(run_rules(events))

    def test_console_login_without_mfa(self):
        events = _events([
            _record("cl1", "2026-11-08T01:00:00Z", "ConsoleLogin",
                    "arn:aws:iam::111122223333:user/human", source="signin.amazonaws.com", mfa="false"),
        ])
        assert "TRAIL-011" in _ids(run_rules(events))

    def test_console_login_with_mfa_clean(self):
        events = _events([
            _record("cl2", "2026-11-08T01:00:00Z", "ConsoleLogin",
                    "arn:aws:iam::111122223333:user/human", source="signin.amazonaws.com", mfa="true"),
        ])
        assert "TRAIL-011" not in _ids(run_rules(events))


class TestChains:
    def test_cred_then_use_outside_window_not_chained(self):
        records = [
            _record("ch1", "2026-11-08T01:00:00Z", "CreateAccessKey", "arn:aws:iam::111122223333:user/x",
                    response={"accessKey": {"accessKeyId": "AKIANEW1"}}),
            _record("ch2", "2026-11-12T01:00:00Z", "GetObject", "arn:aws:iam::111122223333:user/x",
                    source="s3.amazonaws.com", key="AKIANEW1"),
        ]
        findings = run_rules(_events(records), window_hours=2)
        assert "CHAIN-001" not in _ids(findings)

    def test_cred_then_use_inside_window_chained(self):
        records = [
            _record("ch1", "2026-11-08T01:00:00Z", "CreateAccessKey", "arn:aws:iam::111122223333:user/x",
                    response={"accessKey": {"accessKeyId": "AKIANEW1"}}),
            _record("ch2", "2026-11-08T01:20:00Z", "GetObject", "arn:aws:iam::111122223333:user/x",
                    source="s3.amazonaws.com", key="AKIANEW1"),
        ]
        findings = [f for f in run_rules(_events(records), window_hours=2) if f.rule_id == "CHAIN-001"]
        assert findings and findings[0].severity == 4
        assert "AKIANEW1"[:8] in findings[0].evidence[0]

    def test_evasion_then_collection(self):
        records = [_record("ev1", "2026-11-08T01:00:00Z", "StopLogging",
                           "arn:aws:iam::111122223333:user/x", source="cloudtrail.amazonaws.com")]
        records += [
            _record(f"ev{i}", f"2026-11-08T01:{i:02d}:00Z", "GetSecretValue",
                    "arn:aws:iam::111122223333:user/x", source="secretsmanager.amazonaws.com")
            for i in range(2, 10)
        ]
        assert "CHAIN-002" in _ids(run_rules(_events(records)))

    def test_service_principals_skip_signal_rules(self):
        records = [
            _record(f"sp{i}", f"2026-11-08T01:{i:02d}:00Z", "DescribeInstances",
                    "arn:aws:iam::111122223333:role/aws-service-role/x", ptype="AWSService",
                    source="ec2.amazonaws.com")
            for i in range(30)
        ]
        # Force AWSService identity shape
        for rec in records:
            rec["userIdentity"] = {"type": "AWSService", "invokedBy": "autoscaling.amazonaws.com"}
        assert run_rules(_events(records)) == []


class TestFinding:
    def test_severity_label_and_dict(self):
        finding = Finding(
            rule_id="TRAIL-999", title="t", severity=2, technique="x", principal="p",
            principal_type="IAMUser", first_seen="a", last_seen="b", event_count=1,
        )
        assert finding.severity_label == "medium"
        assert finding.to_dict()["severity"] == "medium"

    def test_all_rules_registered(self):
        assert len(RULES) == 12
        assert len(CHAIN_RULES) == 4
