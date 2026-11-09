"""Tests for CloudTrail parsing and normalization."""

from __future__ import annotations

import gzip
import json
import os

import pytest

from trailtriage.events import Event, ParseError, load_events, load_path, parse_record, parse_records, parse_time

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "cloudtrail-sample.json")


def _base(**overrides):
    record = {
        "eventID": "x1",
        "eventTime": "2026-11-08T02:10:00Z",
        "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.45",
        "userAgent": "aws-cli/2.15.0",
        "recipientAccountId": "111122223333",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::111122223333:user/dev",
            "accessKeyId": "AKIA1",
        },
    }
    record.update(overrides)
    return record


class TestParseTime:
    def test_z_suffix(self):
        assert parse_time("2026-11-08T02:10:00Z").hour == 2

    def test_offset(self):
        assert parse_time("2026-11-08T07:40:00+05:30").hour == 2

    def test_naive_assumed_utc(self):
        assert parse_time("2026-11-08T02:10:00").tzinfo is not None

    def test_missing_raises(self):
        with pytest.raises(ParseError):
            parse_time(None)

    def test_garbage_raises(self):
        with pytest.raises(ParseError):
            parse_time("not-a-time")


class TestParseRecord:
    def test_basic_fields(self):
        ev = parse_record(_base())
        assert ev.name == "GetObject"
        assert ev.service == "s3"
        assert ev.action == "s3:GetObject"
        assert ev.principal == "arn:aws:iam::111122223333:user/dev"
        assert ev.account_id == "111122223333"
        assert ev.failed is False

    def test_failed_event(self):
        assert parse_record(_base(errorCode="AccessDenied")).failed is True

    def test_missing_event_name_raises(self):
        with pytest.raises(ParseError):
            parse_record({"eventTime": "2026-11-08T02:10:00Z"})

    def test_non_dict_raises(self):
        with pytest.raises(ParseError):
            parse_record(["nope"])

    def test_root_principal_label(self):
        rec = _base()
        rec["userIdentity"] = {"type": "Root", "arn": "arn:aws:iam::111122223333:root", "accountId": "111122223333"}
        ev = parse_record(rec)
        assert ev.principal == "root:111122223333"
        assert ev.principal_type == "Root"

    def test_service_principal(self):
        rec = _base()
        rec["userIdentity"] = {"type": "AWSService", "invokedBy": "ec2.amazonaws.com"}
        ev = parse_record(rec)
        assert ev.principal == "service:ec2.amazonaws.com"
        assert ev.is_service_principal is True

    def test_assumed_role_keeps_arn(self):
        rec = _base()
        rec["userIdentity"] = {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::111122223333:assumed-role/Deploy/i-abc",
            "accessKeyId": "ASIA1",
        }
        ev = parse_record(rec)
        assert ev.principal_type == "AssumedRole"
        assert "assumed-role" in ev.principal

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("10.0.4.19", True),
            ("172.16.9.9", True),
            ("172.32.1.1", False),
            ("192.168.1.4", True),
            ("AWS Internal", True),
            ("198.51.100.77", False),
            ("", True),
        ],
    )
    def test_internal_ip_detection(self, ip, expected):
        rec = _base(sourceIPAddress=ip)
        assert parse_record(rec).is_internal_ip is expected

    def test_mfa_attribute_parsed(self):
        rec = _base()
        rec["userIdentity"]["sessionContext"] = {"attributes": {"mfaAuthenticated": "true"}}
        assert parse_record(rec).mfa_authenticated is True

    def test_resources_normalized(self):
        rec = _base(resources=[{"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::b/k"}])
        assert parse_record(rec).resources == ("AWS::S3::Object:arn:aws:s3:::b/k",)


class TestParseRecords:
    def test_records_envelope(self):
        assert len(parse_records({"Records": [_base(), _base(eventID="x2")]})) == 2

    def test_single_object(self):
        assert len(parse_records(_base())) == 1

    def test_bare_list(self):
        assert len(parse_records([_base()])) == 1

    def test_bad_record_skipped_not_fatal(self):
        payload = {"Records": [_base(), {"eventTime": "2026-11-08T02:10:00Z"}]}
        assert len(parse_records(payload)) == 1

    def test_scalar_payload_raises(self):
        with pytest.raises(ParseError):
            parse_records("nope")


class TestLoadEvents:
    def test_fixture_loads(self):
        events = load_events(FIXTURE)
        assert len(events) == 75
        assert all(isinstance(ev, Event) for ev in events)

    def test_jsonl(self, tmp_path):
        path = tmp_path / "events.jsonl"
        path.write_text(json.dumps(_base()) + "\n" + json.dumps(_base(eventID="x2")) + "\n")
        assert len(load_events(str(path))) == 2

    def test_gzip(self, tmp_path):
        path = tmp_path / "events.json.gz"
        with gzip.open(path, "wt") as handle:
            json.dump({"Records": [_base()]}, handle)
        assert len(load_events(str(path))) == 1

    def test_empty_file_returns_nothing(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text("")
        assert load_events(str(path)) == []

    def test_missing_file_raises(self):
        with pytest.raises(ParseError):
            load_events("/nonexistent/trail.json")

    def test_noise_around_records_ignored(self, tmp_path):
        path = tmp_path / "noisy.jsonl"
        path.write_text("garbage line\n" + json.dumps(_base()) + "\n{broken\n")
        assert len(load_events(str(path))) == 1


class TestLoadPath:
    def test_directory_walk_sorted(self, tmp_path):
        (tmp_path / "b.json").write_text(json.dumps({"Records": [_base(eventID="later", eventTime="2026-11-08T09:00:00Z")]}))
        (tmp_path / "a.json").write_text(json.dumps({"Records": [_base(eventID="early", eventTime="2026-11-08T01:00:00Z")]}))
        events, warnings = load_path(str(tmp_path))
        assert [ev.event_id for ev in events] == ["early", "later"]
        assert warnings == []

    def test_bad_file_reported_as_warning(self, tmp_path):
        (tmp_path / "good.json").write_text(json.dumps({"Records": [_base()]}))
        (tmp_path / "bad.json").write_text("")
        events, warnings = load_path(str(tmp_path))
        assert len(events) == 1
        assert len(warnings) == 1

    def test_empty_directory_raises(self, tmp_path):
        with pytest.raises(ParseError):
            load_path(str(tmp_path))

    def test_nonexistent_raises(self):
        with pytest.raises(ParseError):
            load_path("/nope/nope")
