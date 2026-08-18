"""Fleet auditing: scoring a multi-facility deployment as one estate.

A single badge system rarely stands alone. A campus, a hospital, or an office
tower runs *several* facility codes -- one per building or department -- often on
the same reader technology. An attacker doesn't need the strongest door; they
walk in through the weakest building. So a fleet's risk is dominated by its
worst facility, tempered by the estate average.

:func:`audit_fleet` runs the full single-facility audit on each deployment and
rolls the results up into a :class:`FleetResult` with a weakest-link composite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .audit import AuditResult, audit_deployment, render_markdown
from .population import Deployment


@dataclass
class FacilityAudit:
    facility_code: int
    name: str
    result: AuditResult


@dataclass
class FleetResult:
    name: str
    facilities: List[FacilityAudit]
    fleet_risk: int
    fleet_band: str
    worst_facility: int
    total_credentials: int

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "fleet_risk": self.fleet_risk,
            "fleet_band": self.fleet_band,
            "worst_facility": self.worst_facility,
            "total_credentials": self.total_credentials,
            "facilities": [
                {"facility_code": f.facility_code, "name": f.name,
                 "risk_score": f.result.risk_score,
                 "risk_band": f.result.risk_band}
                for f in self.facilities
            ],
        }


def _band(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "MINIMAL"


def audit_fleet(deployments: List[Deployment], name: str = "fleet",
                n_observations: int = 8) -> FleetResult:
    """Audit each facility and roll up to a weakest-link fleet score."""
    if not deployments:
        raise ValueError("need at least one deployment")
    audits: List[FacilityAudit] = []
    for d in deployments:
        res = audit_deployment(d, n_observations=n_observations)
        audits.append(FacilityAudit(d.facility_code, d.name, res))

    risks = [a.result.risk_score for a in audits]
    # Weakest-link: the worst building dominates, tempered by the estate mean.
    fleet_risk = int(round(0.7 * max(risks) + 0.3 * (sum(risks) / len(risks))))
    worst = max(audits, key=lambda a: a.result.risk_score)
    total = sum(a.result.metrics.get("issued", 0) for a in audits)

    return FleetResult(
        name=name,
        facilities=sorted(audits, key=lambda a: a.result.risk_score, reverse=True),
        fleet_risk=fleet_risk,
        fleet_band=_band(fleet_risk),
        worst_facility=worst.facility_code,
        total_credentials=total,
    )


def render_fleet_markdown(fleet: FleetResult) -> str:
    lines: List[str] = []
    lines.append(f"# PhantomTap Fleet Audit — {fleet.name}")
    lines.append("")
    lines.append(f"**Fleet risk (weakest-link):** **{fleet.fleet_risk}/100** → "
                 f"**{fleet.fleet_band}**  ")
    lines.append(f"**Facilities:** {len(fleet.facilities)} · "
                 f"**Total credentials:** {fleet.total_credentials:,} · "
                 f"**Weakest facility code:** {fleet.worst_facility}  ")
    lines.append("")
    lines.append("> A fleet is only as strong as its weakest building: the "
                 "composite weights the worst facility at 70%.")
    lines.append("")
    lines.append("## Per-facility risk")
    lines.append("")
    lines.append("| Facility code | Deployment | Risk | Band | Top finding |")
    lines.append("|--------------:|------------|-----:|------|-------------|")
    for f in fleet.facilities:
        top = f.result.findings[0].title if f.result.findings else "—"
        lines.append(f"| {f.facility_code} | `{f.name}` | "
                     f"{f.result.risk_score} | {f.result.risk_band} | {top} |")
    lines.append("")
    lines.append("## Highest-risk facility in detail")
    lines.append("")
    worst = fleet.facilities[0]
    lines.append(render_markdown(worst.result))
    return "\n".join(lines)
