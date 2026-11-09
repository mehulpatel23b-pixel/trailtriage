"""Parse and normalize AWS CloudTrail records into Event objects.

Accepts:
  * a single ``.json`` file containing ``{"Records": [...]}``
  * newline-delimited CloudTrail JSON (one record per line)
  * gzip-compressed variants of either
  * a directory (walked recursively)

Every traceback-worthy problem is turned into a :class:`ParseError` so the CLI can
report bad files without aborting the whole run.
"""

from __future__ import annotations

import gzip
import io
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

__all__ = ["Event", "ParseError", "parse_record", "parse_records", "load_events", "load_path"]


class ParseError(ValueError):
    """Raised when a CloudTrail payload cannot be decoded."""


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return False


def parse_time(value: Any) -> datetime:
    """Parse a CloudTrail timestamp into an aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        raise ParseError("missing eventTime")
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ParseError(f"bad eventTime: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _principal(identity: dict) -> tuple[str, str]:
    """Return (principal_label, principal_type)."""
    ptype = str(identity.get("type") or "Unknown")
    arn = identity.get("arn")
    if ptype == "Root" or (arn or "").endswith(":root"):
        account = identity.get("accountId") or "(unknown)"
        return f"root:{account}", "Root"
    if arn:
        return str(arn), ptype
    if ptype == "AWSService":
        return f"service:{identity.get('invokedBy') or 'unknown'}", ptype
    if ptype == "AWSAccount":
        return f"account:{identity.get('accountId') or 'unknown'}", ptype
    pid = identity.get("principalId") or identity.get("userName") or "anonymous"
    return str(pid), ptype


@dataclass(frozen=True)
class Event:
    """A normalized CloudTrail event."""

    event_id: str
    time: datetime
    name: str
    source: str
    account_id: str
    principal: str
    principal_type: str
    access_key_id: str
    source_ip: str
    user_agent: str
    region: str
    error_code: str
    mfa_authenticated: bool
    resources: tuple[str, ...] = ()
    request_parameters: dict = field(default_factory=dict, compare=False)
    response_elements: dict = field(default_factory=dict, compare=False)

    @property
    def failed(self) -> bool:
        return bool(self.error_code)

    @property
    def service(self) -> str:
        return self.source.split(".")[0] if self.source else ""

    @property
    def action(self) -> str:
        return f"{self.service}:{self.name}"

    @property
    def is_service_principal(self) -> bool:
        return self.principal_type == "AWSService"

    @property
    def is_internal_ip(self) -> bool:
        """True for AWS-internal or RFC1918 style origins."""
        ip = self.source_ip
        if not ip:
            return True
        if ip in {"AWS Internal", "AWS Console", "127.0.0.1", "::1"}:
            return True
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."):
            return True
        if ip.startswith("172."):
            try:
                second = int(ip.split(".")[1])
            except (IndexError, ValueError):
                return False
            return 16 <= second <= 31
        return False


def _resources(raw: Any) -> tuple[str, ...]:
    items: list[str] = []
    if isinstance(raw, list):
        for res in raw:
            if not isinstance(res, dict):
                continue
            kind = res.get("type") or ""
            name = res.get("ARN") or res.get("ARN") or res.get("name") or ""
            label = f"{kind}:{name}" if kind and name else (name or kind)
            if label:
                items.append(str(label))
    return tuple(items)


def parse_record(record: dict) -> Event:
    """Turn one raw CloudTrail record into an :class:`Event`."""
    if not isinstance(record, dict):
        raise ParseError("record is not an object")
    identity = record.get("userIdentity") or {}
    if not isinstance(identity, dict):
        identity = {}
    principal, ptype = _principal(identity)

    attributes = ((identity.get("sessionContext") or {}).get("attributes") or {})
    mfa = _as_bool(attributes.get("mfaAuthenticated")) if isinstance(attributes, dict) else False

    name = record.get("eventName")
    if not name:
        raise ParseError("record has no eventName")

    return Event(
        event_id=str(record.get("eventID") or record.get("eventId") or ""),
        time=parse_time(record.get("eventTime")),
        name=str(name),
        source=str(record.get("eventSource") or ""),
        account_id=str(record.get("recipientAccountId") or identity.get("accountId") or ""),
        principal=principal,
        principal_type=ptype,
        access_key_id=str(identity.get("accessKeyId") or ""),
        source_ip=str(record.get("sourceIPAddress") or ""),
        user_agent=str(record.get("userAgent") or ""),
        region=str(record.get("awsRegion") or ""),
        error_code=str(record.get("errorCode") or ""),
        mfa_authenticated=mfa,
        resources=_resources(record.get("resources")),
        request_parameters=record.get("requestParameters") or {},
        response_elements=record.get("responseElements") or {},
    )


def parse_records(payload: Any) -> list[Event]:
    """Normalize a decoded CloudTrail payload (dict, list or ``Records`` envelope)."""
    if isinstance(payload, dict):
        if isinstance(payload.get("Records"), list):
            payload = payload["Records"]
        else:
            payload = [payload]
    if not isinstance(payload, list):
        raise ParseError("payload is neither a record, a list nor a Records envelope")

    events: list[Event] = []
    for record in payload:
        try:
            events.append(parse_record(record))
        except ParseError:
            continue
    return events


def _read_text(path: str) -> str:
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def load_events(path: str) -> list[Event]:
    """Load events from one file, tolerating both pretty JSON and JSON lines."""
    try:
        text = _read_text(path)
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc
    if not text.strip():
        return []
    try:
        return parse_records(json.loads(text))
    except json.JSONDecodeError:
        pass

    events: list[Event] = []
    decoder = json.JSONDecoder()
    index, length = 0, len(text)
    while index < length:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        try:
            obj, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            line_end = text.find("\n", index)
            if line_end == -1:
                break
            index = line_end + 1
            continue
        try:
            events.extend(parse_records(obj))
        except ParseError:
            continue
    if not events:
        raise ParseError(f"no CloudTrail records found in {path}")
    return events


def _iter_files(root: str) -> Iterator[str]:
    for base, _dirs, files in os.walk(root):
        for name in sorted(files):
            if name.endswith((".json", ".jsonl", ".log", ".json.gz", ".log.gz")):
                yield os.path.join(base, name)


def load_path(path: str) -> tuple[list[Event], list[str]]:
    """Load from a file or directory. Returns (events, warnings)."""
    warnings: list[str] = []
    if not os.path.exists(path):
        raise ParseError(f"path does not exist: {path}")
    files = list(_iter_files(path)) if os.path.isdir(path) else [path]
    if not files:
        raise ParseError(f"no CloudTrail files under {path}")

    events: list[Event] = []
    for file_path in files:
        try:
            loaded = load_events(file_path)
        except ParseError as exc:
            warnings.append(str(exc))
            continue
        if not loaded:
            warnings.append(f"no CloudTrail records found in {file_path}")
        events.extend(loaded)
    events.sort(key=lambda ev: (ev.time, ev.event_id))
    return events, warnings
