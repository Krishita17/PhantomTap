"""PhantomTap -- ML-guided RFID/NFC fuzzing & access-control auditing.

A Flipper Zero that stops guessing and starts reasoning: an ML-guided RFID/NFC
fuzzer and access-control auditor that turns raw card reads into a prioritized,
explainable security assessment.

This is a **defensive** auditing tool. See ``docs/threat_model.md``.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Krishita Sanjay Choksi"

from .formats import (  # noqa: F401
    ALL_FORMATS,
    REGISTRY,
    DecodedCredential,
    WiegandFormat,
    get_format,
)
from .population import (  # noqa: F401
    CardFamily,
    Credential,
    Deployment,
    NumberingScheme,
    generate_deployment,
)
from .reader import SimulatedReader  # noqa: F401
from .inference import FormatHypothesis, infer_format  # noqa: F401
from .generator import (  # noqa: F401
    CharacterizationResult,
    bruteforce_characterize,
    dictionary_characterize,
    ml_characterize,
    run_all_methods,
)
from .bayes import RangeEstimate, estimate_population  # noqa: F401
from .entropy import Guessability, assess_guessability  # noqa: F401
from .monitor import (  # noqa: F401
    Alert,
    BadgeEvent,
    RedBlueResult,
    analyze,
    red_vs_blue,
    synthetic_stream,
)
from .audit import (  # noqa: F401
    AuditResult,
    Finding,
    audit_deployment,
    quick_risk_score,
    render_markdown,
)
from .remediation import Fix, candidate_fixes, prioritized_plan  # noqa: F401
from .fleet import (  # noqa: F401
    FacilityAudit,
    FleetResult,
    audit_fleet,
    render_fleet_markdown,
)
from .sarif import to_sarif  # noqa: F401

__all__ = [
    "__version__",
    "__author__",
    "ALL_FORMATS",
    "REGISTRY",
    "WiegandFormat",
    "DecodedCredential",
    "get_format",
    "CardFamily",
    "Credential",
    "Deployment",
    "NumberingScheme",
    "generate_deployment",
    "SimulatedReader",
    "FormatHypothesis",
    "infer_format",
    "CharacterizationResult",
    "bruteforce_characterize",
    "dictionary_characterize",
    "ml_characterize",
    "run_all_methods",
    "RangeEstimate",
    "estimate_population",
    "Guessability",
    "assess_guessability",
    "Alert",
    "BadgeEvent",
    "RedBlueResult",
    "analyze",
    "red_vs_blue",
    "synthetic_stream",
    "AuditResult",
    "Finding",
    "audit_deployment",
    "quick_risk_score",
    "render_markdown",
    "Fix",
    "candidate_fixes",
    "prioritized_plan",
    "FacilityAudit",
    "FleetResult",
    "audit_fleet",
    "render_fleet_markdown",
    "to_sarif",
]
