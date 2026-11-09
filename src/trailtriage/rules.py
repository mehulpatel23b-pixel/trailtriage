"""Detection rules and multi-stage chain correlation for CloudTrail events.

Design notes
------------
* Every rule is a small, pure function over one principal's events. No I/O, no clock,
  no randomness, so the whole engine is deterministic and unit-testable.
* Single-event rules ("signals") catch *what* happened. Chain rules catch *sequence*,
  which is where real AWS identity attacks live: a lone ``CreateAccessKey`` is a
  Monday; ``CreateAccessKey`` followed by that new key doing ``GetObject`` on 4,000
  objects inside an hour is an intrusion.
* Severity is an integer 1-4 (low..critical) so it sorts and sums predictably.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Iterable, Sequence

from .events import Event

__all__ = [
    "Finding",
    "SEVERITY_LABEL",
    "SEVERITY_WEIGHT",
    "run_rules",
    "RULES",
]

SEVERITY_LABEL = {1: "low", 2: "medium", 3: "high", 4: "critical"}
SEVERITY_WEIGHT = {1: 1.0, 2: 3.0, 3: 7.0, 4: 15.0}


@dataclass
class Finding:
    """One detection result, scoped to a principal (and optionally a chain)."""

    rule_id: str
    title: str
    severity: int
    technique: str
    principal: str
    principal_type: str
    first_seen: str
    last_seen: str
    event_count: int
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    chain: str = ""

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABEL.get(self.severity, "low")

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity_label,
            "severity_score": self.severity,
            "technique": self.technique,
            "principal": self.principal,
            "principal_type": self.principal_type,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "chain": self.chain,
        }


def _ts(value) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _make(
    rule_id: str,
    title: str,
    severity: int,
    technique: str,
    principal: str,
    principal_type: str,
    events: Sequence[Event],
    evidence: Iterable[str],
    remediation: str,
    chain: str = "",
) -> Finding:
    ordered = sorted(events, key=lambda ev: ev.time)
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        technique=technique,
        principal=principal,
        principal_type=principal_type,
        first_seen=_ts(ordered[0].time),
        last_seen=_ts(ordered[-1].time),
        event_count=len(ordered),
        evidence=list(evidence),
        remediation=remediation,
        chain=chain,
    )


def _actions(events: Iterable[Event]) -> set[str]:
    return {ev.action for ev in events}


def _withevidence(events: Sequence[Event], actions: Sequence[str], limit: int = 6) -> list[str]:
    """Human-readable one-liners for the given action list, capped for reports."""
    wanted = set(actions)
    lines: list[str] = []
    for ev in sorted(events, key=lambda e: e.time):
        if ev.action in wanted:
            verdict = f"FAILED ({ev.error_code})" if ev.failed else "ok"
            lines.append(f"{_ts(ev.time)} {ev.action} from {ev.source_ip or 'unknown'} [{verdict}]")
            if len(lines) >= limit:
                break
    return lines


# --------------------------------------------------------------------------------------
# Signal rules: (event) -> bool, evaluated per principal
# --------------------------------------------------------------------------------------

def _root_no_mfa(events: list[Event]) -> list[Finding]:
    hits = [ev for ev in events if ev.principal_type == "Root" and not ev.failed]
    if not hits:
        return []
    unauthenticated = [ev for ev in hits if not ev.mfa_authenticated]
    severity = 4 if unauthenticated else 3
    return [
        _make(
            "TRAIL-001",
            "Root account activity" + (" without MFA" if unauthenticated else ""),
            severity,
            "T1562 / Valid Accounts: Cloud Accounts (T1078.004)",
            hits[0].principal,
            "Root",
            hits,
            _withevidence(hits, [ev.action for ev in hits]),
            "Root should never be used for day-to-day work. Move to a federated admin role, "
            "enforce hardware MFA on the root user, and rotate the root password immediately.",
        )
    ]


_TRAIL_TAMPER = {
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "cloudtrail:PutEventSelectors",
    "cloudtrail:DeleteEventDataStore",
    "cloudtrail:PutInsightSelectors",
}

_DETECTION_DISABLE = {
    "guardduty:DeleteDetector",
    "guardduty:UpdateDetector",
    "guardduty:DisassociateFromMasterAccount",
    "config:DeleteConfigurationRecorder",
    "config:StopConfigurationRecorder",
    "config:DeleteDeliveryChannel",
    "securityhub:DisableSecurityHub",
    "securityhub:DeleteMembers",
    "ec2:DeleteFlowLogs",
    "logs:DeleteLogGroup",
    "logs:DeleteLogStream",
    "access-analyzer:DeleteAnalyzer",
}


def _rule_tamper(rule_id: str, title: str, severity: int, technique: str, actions: set[str],
                 events: list[Event], remediation: str) -> Callable[[list[Event]], list[Finding]]:
    """Build a rule that fires when any of ``actions`` succeeds."""

    def rule(batch: list[Event]) -> list[Finding]:
        hits = [ev for ev in batch if ev.action in actions and not ev.failed]
        if not hits:
            return []
        return [
            _make(
                rule_id,
                title,
                severity,
                technique,
                hits[0].principal,
                hits[0].principal_type,
                hits,
                _withevidence(hits, [ev.action for ev in hits]),
                remediation,
            )
        ]

    return rule


_rule_cloudtrail_tamper = _rule_tamper(
    "TRAIL-002",
    "CloudTrail logging tampered with",
    4,
    "T1562.008 Impair Defenses: Disable Cloud Logs",
    _TRAIL_TAMPER,
    [],
    "Re-enable the trail immediately, check for a parallel trail the attacker created, and "
    "ship CloudTrail to a separate, write-once account so a compromised admin cannot erase it.",
)

_rule_detection_disable = _rule_tamper(
    "TRAIL-003",
    "Security monitoring disabled (GuardDuty, Config, Security Hub, flow logs, Access Analyzer)",
    4,
    "T1562.001 Impair Defenses: Disable or Modify Tools",
    _DETECTION_DISABLE,
    [],
    "Detection was turned off before or during an intrusion. Re-enable every service touched, "
    "review what ran in the blind window, and alert on these API calls going forward.",
)

_IAM_PERSISTENCE = {
    "iam:CreateAccessKey",
    "iam:CreateUser",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:CreateServiceSpecificCredential",
    "iam:UploadSSHPublicKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreateRole",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "sts:GetFederationToken",
}


def _rule_iam_persistence(events: list[Event]) -> list[Finding]:
    hits = [ev for ev in events if ev.action in _IAM_PERSISTENCE and not ev.failed]
    if not hits:
        return []
    counts = Counter(ev.action for ev in hits)
    evidence = _withevidence(hits, list(counts))
    evidence.append("Action mix: " + ", ".join(f"{a} x{c}" for a, c in counts.most_common(5)))
    return [
        _make(
            "TRAIL-004",
            "IAM persistence primitives used",
            3,
            "T1098 Account Manipulation",
            hits[0].principal,
            hits[0].principal_type,
            hits,
            evidence,
            "Inventory every credential, policy attachment and trust-policy change made here. "
            "Delete anything you did not intend, and require change-management approval for IAM writes.",
        )
    ]


_MFA_TAMPER = {
    "iam:DeactivateMFADevice",
    "iam:DeleteVirtualMFADevice",
    "iam:CreateVirtualMFADevice",
    "iam:ResyncMFADevice",
}


def _rule_mfa_tamper(events: list[Event]) -> list[Finding]:
    hits = [ev for ev in events if ev.action in _MFA_TAMPER and not ev.failed]
    if not hits:
        return []
    return [
        _make(
            "TRAIL-005",
            "MFA device removed or re-registered",
            4,
            "T1556.006 Modify Authentication Process: Multi-Factor Authentication",
            hits[0].principal,
            hits[0].principal_type,
            hits,
            _withevidence(hits, [ev.action for ev in hits]),
            "MFA changes are a classic account-takeover step. Contact the account owner out of "
            "band, force a password reset, and re-register MFA on a trusted device.",
        )
    ]


_PUBLIC_EXPOSURE = {
    "ec2:ModifySnapshotAttribute",
    "s3:PutBucketAcl",
    "s3:PutObjectAcl",
    "s3:PutBucketPolicy",
    "s3:DeletePublicAccessBlock",
    "ecr:SetRepositoryPolicy",
    "rds:ModifyDBClusterSnapshotAttribute",
    "efs:PutFileSystemPolicy",
}


def _rule_public_exposure(events: list[Event]) -> list[Finding]:
    hits: list[Event] = []
    for ev in events:
        if ev.failed or ev.action not in _PUBLIC_EXPOSURE:
            continue
        blob = f"{ev.request_parameters} {ev.response_elements}".lower()
        blob = " ".join(blob.split())
        public_markers = (
            "allusers",
            "authenticatedusers",
            "0.0.0.0/0",
            "::/0",
            "group/public",
            "principal': '*'",
            'principal":"*',
            "principal: *",
        )
        if any(marker in blob for marker in public_markers):
            hits.append(ev)
    if not hits:
        return []
    return [
        _make(
            "TRAIL-006",
            "Data store made public",
            4,
            "T1530 Data from Cloud Storage / T1567 Exfiltration Over Web Service",
            hits[0].principal,
            hits[0].principal_type,
            hits,
            _withevidence(hits, [ev.action for ev in hits]),
            "Revert the policy, restore Block Public Access on the bucket or snapshot, and check "
            "access logs for reads from unfamiliar IPs while it was exposed.",
        )
    ]


_EXFIL_READS = {
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:ListBucket",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "kms:Decrypt",
    "dynamodb:Scan",
    "rds:DescribeDBSnapshots",
    "ec2:CreateSnapshot",
}


def _rule_exfil_volume(events: list[Event], threshold: int = 50) -> list[Finding]:
    hits = [ev for ev in events if ev.action in _EXFIL_READS and not ev.failed]
    if len(hits) < threshold:
        return []
    ordered = sorted(hits, key=lambda ev: ev.time)
    span = (ordered[-1].time - ordered[0].time).total_seconds() or 1.0
    counts = Counter(ev.action for ev in hits)
    rate = len(hits) / (span / 3600.0)
    evidence = _withevidence(ordered, list(counts), limit=4)
    evidence.append(f"{len(hits)} sensitive reads in {span / 60:.0f} min (about {rate:.0f}/hour)")
    evidence.append("Action mix: " + ", ".join(f"{a} x{c}" for a, c in counts.most_common(4)))
    return [
        _make(
            "TRAIL-007",
            "Bulk sensitive-data reads (possible exfiltration staging)",
            3,
            "T1530 Data from Cloud Storage",
            ordered[0].principal,
            ordered[0].principal_type,
            ordered,
            evidence,
            "Confirm the principal and the workload behind it. If unexpected, revoke its session "
            "immediately and compare against the bucket's data-transfer volume.",
        )
    ]


_RECON_PREFIXES = ("Describe", "List", "Get", "Head")


def _rule_recon(events: list[Event], threshold: int = 25) -> list[Finding]:
    hits = [ev for ev in events if not ev.failed and ev.name.startswith(_RECON_PREFIXES)]
    distinct = {ev.action for ev in hits}
    if len(distinct) < threshold:
        return []
    ordered = sorted(hits, key=lambda ev: ev.time)
    services = Counter(ev.service for ev in hits)
    evidence = [
        f"{len(distinct)} distinct discovery calls across {len(services)} services",
        "Top services: " + ", ".join(f"{s} x{c}" for s, c in services.most_common(5)),
    ]
    evidence.extend(_withevidence(ordered, list(distinct)[:4], limit=3))
    return [
        _make(
            "TRAIL-008",
            "Broad discovery sweep (reconnaissance)",
            2,
            "T1526 Cloud Service Discovery / T1580 Cloud Infrastructure Discovery",
            ordered[0].principal,
            ordered[0].principal_type,
            ordered,
            evidence,
            "Broad read-only enumeration is often the first stage of an intrusion. Baseline normal "
            "tooling for this principal and alert when the discovery surface suddenly widens.",
        )
    ]


_DENIED_BURST_THRESHOLD = 10


def _rule_denied_burst(events: list[Event]) -> list[Finding]:
    hits = [ev for ev in events if ev.error_code in {"AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"}]
    if len(hits) < _DENIED_BURST_THRESHOLD:
        return []
    ordered = sorted(hits, key=lambda ev: ev.time)
    attempted = Counter(ev.action for ev in hits)
    evidence = [f"{len(hits)} access denials, {len(attempted)} distinct API calls attempted"]
    evidence.extend(_withevidence(ordered, list(attempted)[:4], limit=4))
    return [
        _make(
            "TRAIL-009",
            "Repeated access denials (permission probing)",
            2,
            "T1069 Permission Groups Discovery / T1078.004 Valid Accounts",
            ordered[0].principal,
            ordered[0].principal_type,
            ordered,
            evidence,
            "A burst of denials means something is testing its boundaries, often a misused valid "
            "credential or a broken automation. Identify the caller and confirm it is expected.",
        )
    ]


_KMS_TAMPER = {
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
    "kms:PutKeyPolicy",
    "kms:DisableKeyRotation",
    "kms:CreateGrant",
}


def _rule_kms_tamper(events: list[Event]) -> list[Finding]:
    hits = [ev for ev in events if ev.action in _KMS_TAMPER and not ev.failed]
    if not hits:
        return []
    return [
        _make(
            "TRAIL-010",
            "KMS key policy or lifecycle changed",
            3,
            "T1486 Data Encrypted for Impact / T1562 Impair Defenses",
            hits[0].principal,
            hits[0].principal_type,
            hits,
            _withevidence(hits, [ev.action for ev in hits]),
            "Key policy changes control who can decrypt everything downstream. Verify the change "
            "was approved, and cancel any scheduled deletion before data becomes unrecoverable.",
        )
    ]


def _rule_console_no_mfa(events: list[Event]) -> list[Finding]:
    hits = [
        ev
        for ev in events
        if ev.action == "signin:ConsoleLogin" and not ev.failed and not ev.mfa_authenticated
    ]
    if not hits:
        return []
    return [
        _make(
            "TRAIL-011",
            "Console login without MFA",
            3,
            "T1078.004 Valid Accounts: Cloud Accounts",
            hits[0].principal,
            hits[0].principal_type,
            hits,
            _withevidence(hits, ["signin:ConsoleLogin"]),
            "Enforce MFA for every human identity via an identity-provider policy. Password-only "
            "console access is the easiest entry point into an AWS account.",
        )
    ]


def _rule_iam_policy_exfil(events: list[Event]) -> list[Finding]:
    """Account-level IAM policy detached or permissive policy attached at scale."""
    hits = [
        ev
        for ev in events
        if ev.action in {"iam:DetachRolePolicy", "iam:DetachUserPolicy", "iam:DeletePolicyVersion"}
        and not ev.failed
    ]
    if not hits:
        return []
    return [
        _make(
            "TRAIL-012",
            "Guardrail policy detached",
            3,
            "T1562.001 Impair Defenses: Disable or Modify Tools",
            hits[0].principal,
            hits[0].principal_type,
            hits,
            _withevidence(hits, [ev.action for ev in hits]),
            "Service-control and permission-boundary detachments widen blast radius. Use SCPs so "
            "no principal inside the account can remove its own guardrails.",
        )
    ]


RULES: list[Callable[[list[Event]], list[Finding]]] = [
    _root_no_mfa,
    _rule_cloudtrail_tamper,
    _rule_detection_disable,
    _rule_iam_persistence,
    _rule_mfa_tamper,
    _rule_public_exposure,
    _rule_exfil_volume,
    _rule_recon,
    _rule_denied_burst,
    _rule_kms_tamper,
    _rule_console_no_mfa,
    _rule_iam_policy_exfil,
]


# --------------------------------------------------------------------------------------
# Chain rules: ordered, time-bounded sequences per principal
# --------------------------------------------------------------------------------------

def _within(events: Sequence[Event], window: timedelta) -> bool:
    if len(events) < 2:
        return True
    ordered = sorted(events, key=lambda ev: ev.time)
    return (ordered[-1].time - ordered[0].time) <= window


def _chain_cred_then_use(batch: list[Event], window: timedelta) -> list[Finding]:
    """New access key minted, then that same key immediately does sensitive reads."""
    created: dict[str, Event] = {}
    for ev in batch:
        if ev.action != "iam:CreateAccessKey" or ev.failed:
            continue
        params = ev.request_parameters or {}
        key = ""
        response = ev.response_elements or {}
        creds = response.get("accessKey") or {}
        if isinstance(creds, dict):
            key = str(creds.get("accessKeyId") or "")
        if not key:
            key = str(params.get("accessKeyId") or "")
        if key:
            created[key] = ev
    if not created:
        return []

    findings: list[Finding] = []
    for key, mint_event in created.items():
        later = [
            ev
            for ev in batch
            if ev.access_key_id == key
            and ev.time > mint_event.time
            and ev.action in _EXFIL_READS
            and not ev.failed
        ]
        if not later or not _within([mint_event, *later], window):
            continue
        chain_events = [mint_event, *later]
        evidence = [f"{_ts(mint_event.time)} iam:CreateAccessKey minted key {key[:8]}****"]
        evidence.extend(_withevidence(later, [ev.action for ev in later], limit=4))
        evidence.append(f"New key used {len(later)} times within the correlation window")
        findings.append(
            _make(
                "CHAIN-001",
                "Persistence then data access: fresh access key used immediately",
                4,
                "T1098.001 Account Manipulation: Additional Cloud Credentials",
                mint_event.principal,
                mint_event.principal_type,
                chain_events,
                evidence,
                "Treat the principal as compromised. Disable the new key, revoke all sessions for the "
                "user or role, rotate every secret it could read, and pull CloudTrail for the key's full history.",
                chain="persistence-to-data-access",
            )
        )
    return findings


def _chain_go_dark_then_exfil(batch: list[Event], window: timedelta) -> list[Finding]:
    """Detection disabled first, sensitive reads after. Classic fly-under-the-radar order."""
    dark = [ev for ev in batch if ev.action in (_TRAIL_TAMPER | _DETECTION_DISABLE) and not ev.failed]
    if not dark:
        return []
    first_dark = min(dark, key=lambda ev: ev.time)
    reads = [
        ev
        for ev in batch
        if ev.time > first_dark.time and ev.action in _EXFIL_READS and not ev.failed
    ]
    if len(reads) < 5 or not _within([first_dark, *reads], window):
        return []

    evidence = _withevidence(dark, [ev.action for ev in dark], limit=3)
    evidence.append(f"Then {len(reads)} sensitive reads by the same principal")
    evidence.extend(_withevidence(reads, [ev.action for ev in reads], limit=3))
    return [
        _make(
            "CHAIN-002",
            "Defense evasion then data collection",
            4,
            "T1562 Impair Defenses then T1530 Data from Cloud Storage",
            first_dark.principal,
            first_dark.principal_type,
            [*dark, *reads],
            evidence,
            "This is an active intrusion pattern, not a misconfiguration. Isolate the credentials, "
            "assume telemetry is incomplete for the window, and rebuild detection from the immutable copy.",
            chain="evasion-to-collection",
        )
    ]


def _chain_recon_then_escalate(batch: list[Event], window: timedelta) -> list[Finding]:
    """Discovery sweep followed by an IAM write."""
    recon = [ev for ev in batch if ev.name.startswith(_RECON_PREFIXES) and not ev.failed]
    if len({ev.action for ev in recon}) < 25:
        return []
    first_recon = min(recon, key=lambda ev: ev.time)
    escalate = [ev for ev in batch if ev.action in _IAM_PERSISTENCE and not ev.failed and ev.time >= first_recon.time]
    if not escalate or not _within([first_recon, *escalate], window):
        return []

    evidence = [f"{len({ev.action for ev in recon})} discovery calls across {len({ev.service for ev in recon})} services"]
    evidence.extend(_withevidence(escalate, [ev.action for ev in escalate], limit=4))
    return [
        _make(
            "CHAIN-003",
            "Reconnaissance then privilege escalation",
            3,
            "T1580 Cloud Infrastructure Discovery then T1098 Account Manipulation",
            first_recon.principal,
            first_recon.principal_type,
            [*recon, *escalate],
            evidence,
            "Map what the caller could already see, then remove every IAM change it made. If the "
            "principal is an automation identity, its credentials are probably in a compromised workload.",
            chain="recon-to-escalation",
        )
    ]


def _chain_root_mfa_then_creds(batch: list[Event], window: timedelta) -> list[Finding]:
    """Root login without MFA, then IAM credential creation."""
    root = [ev for ev in batch if ev.principal_type == "Root" and not ev.mfa_authenticated and not ev.failed]
    if not root:
        return []
    first = min(root, key=lambda ev: ev.time)
    creds = [ev for ev in batch if ev.action in _IAM_PERSISTENCE and not ev.failed and ev.time >= first.time]
    if not creds or not _within([first, *creds], window):
        return []
    evidence = [f"{_ts(first.time)} root activity without MFA: {first.action}"]
    evidence.extend(_withevidence(creds, [ev.action for ev in creds], limit=4))
    return [
        _make(
            "CHAIN-004",
            "Root used without MFA then credentials created",
            4,
            "T1078.004 Valid Accounts: Cloud Accounts then T1098",
            first.principal,
            "Root",
            [first, *creds],
            evidence,
            "Assume full account compromise. Rotate the root password and MFA from a clean device, "
            "audit all IAM changes, and enable CloudTrail organization trails in a separate account.",
            chain="root-takeover",
        )
    ]


CHAIN_RULES: list[Callable[[list[Event], timedelta], list[Finding]]] = [
    _chain_cred_then_use,
    _chain_go_dark_then_exfil,
    _chain_recon_then_escalate,
    _chain_root_mfa_then_creds,
]


def run_rules(events: Iterable[Event], window_hours: int = 24) -> list[Finding]:
    """Run every signal and chain rule, grouped per principal.

    AWS service principals are skipped for signal rules: ``Describe`` sweeps by
    ``autoscaling.amazonaws.com`` are noise, and burying real findings in noise is how
    triage tools get abandoned.
    """
    window = timedelta(hours=max(1, window_hours))
    by_principal: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        by_principal[ev.principal].append(ev)

    findings: list[Finding] = []
    for principal, batch in by_principal.items():
        if not batch or batch[0].principal_type == "AWSService":
            continue
        for rule in RULES:
            findings.extend(rule(batch))

    # Chains are inherently cross-principal: a key is minted by one identity and used by
    # another, so they run over the whole corpus rather than one principal's events.
    all_events = list(events)
    for chain in CHAIN_RULES:
        findings.extend(chain(all_events, window))

    findings.sort(key=lambda f: (-f.severity, f.first_seen, f.rule_id))
    return findings
