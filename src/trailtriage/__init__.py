"""trailtriage - offline CloudTrail triage for identity-based attacks."""

__version__ = "0.1.0"

from .events import Event, load_events, load_path  # noqa: F401
from .rules import Finding, run_rules  # noqa: F401
from .scoring import score_principals  # noqa: F401
