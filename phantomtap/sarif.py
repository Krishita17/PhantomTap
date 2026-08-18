"""SARIF export for PhantomTap findings.

SARIF (Static Analysis Results Interchange Format, OASIS standard, used by
GitHub code scanning and most security dashboards) is the lingua franca for
tool findings. Emitting it lets a physical-security audit flow into the same
pipelines that track software vulnerabilities -- so badge-system risk shows up
next to code risk, tracked and triaged the same way.

``to_sarif`` maps each :class:`~phantomtap.audit.Finding` to a SARIF result and
each factor to a SARIF rule.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import __version__

if TYPE_CHECKING:  # pragma: no cover
    from .audit import AuditResult

# severity -> SARIF level
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_RULE_HELP = {
    "format": "Credential format strength (bit width, facility/card space).",
    "numbering": "Predictability of card-number issuance.",
    "clonability": "How easily a credential can be cloned/replayed.",
    "keys": "Sector key hygiene (default/shared keys).",
    "characterization": "How cheaply the population can be mapped.",
    "guessability": "Information-theoretic guessing-resistance (bits).",
}


def to_sarif(result: "AuditResult") -> dict:
    """Render an :class:`AuditResult` as a SARIF 2.1.0 document (as a dict)."""
    factors = []
    seen = set()
    for f in result.findings:
        if f.factor in seen:
            continue
        seen.add(f.factor)
        factors.append(f.factor)

    rules = [
        {
            "id": factor,
            "name": factor,
            "shortDescription": {"text": _RULE_HELP.get(factor, factor)},
            "defaultConfiguration": {"level": "warning"},
        }
        for factor in factors
    ]

    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.factor,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title} — {f.detail}"},
            "properties": {
                "severity": f.severity,
                "subScore": f.score,
                "remediation": f.remediation,
            },
            "locations": [{
                "logicalLocations": [{
                    "name": result.deployment,
                    "kind": "resource",
                }]
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PhantomTap",
                    "informationUri": "https://github.com/Krishita17/PhantomTap",
                    "version": __version__,
                    "rules": rules,
                }
            },
            "properties": {
                "compositeRiskScore": result.risk_score,
                "riskBand": result.risk_band,
                "deployment": result.deployment,
            },
            "results": results,
        }],
    }
