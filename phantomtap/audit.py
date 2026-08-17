"""Risk scoring and audit-report generation -- PhantomTap's deliverable.

The whole pipeline exists to produce *this*: an explainable, prioritized
access-control risk assessment.  Given a deployment (in practice: what the
inference and characterization stages recovered), the auditor scores weakness
across independent factors, emits ranked findings with severity and
remediation, and renders a Markdown report a building owner could act on.

Scores run 0-100 where **higher = weaker / more auditable = worse**.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional

from . import keys as keymod
from .bayes import estimate_population
from .entropy import assess_guessability
from .generator import run_all_methods
from .population import CardFamily, Deployment, NumberingScheme, sector_key_posture
from .reader import SimulatedReader


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    factor: str
    severity: str
    score: int          # 0-100 contribution weight-normalised
    title: str
    detail: str
    remediation: str

    def as_dict(self) -> dict:
        return {
            "factor": self.factor,
            "severity": self.severity,
            "score": self.score,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class AuditResult:
    deployment: str
    risk_score: int
    risk_band: str
    findings: List[Finding]
    metrics: dict

    def as_dict(self) -> dict:
        return {
            "deployment": self.deployment,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "findings": [f.as_dict() for f in self.findings],
            "metrics": self.metrics,
        }


# Weight each factor's contribution to the composite score. Weights sum to 1.0.
WEIGHTS = {
    "format": 0.16,
    "numbering": 0.22,
    "clonability": 0.18,
    "keys": 0.22,
    "characterization": 0.07,
    "guessability": 0.15,
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


def _format_factor(dep: Deployment) -> Finding:
    bits = dep.fmt.total_bits
    card_bits = dep.fmt.card_bits
    # Shorter formats & smaller card spaces are weaker.
    sub = max(0, min(100, int(100 * (37 - bits) / 11) + max(0, (16 - card_bits)) * 4))
    if bits <= 26:
        sev = "high"
    elif bits <= 34:
        sev = "medium"
    else:
        sev = "low"
    return Finding(
        factor="format",
        severity=sev,
        score=sub,
        title=f"Credential format: {dep.fmt.name} ({bits}-bit)",
        detail=(
            f"{dep.fmt.description} The card-number field is {card_bits} bits "
            f"(max {dep.fmt.max_card:,}), and the facility-code field is "
            f"{dep.fmt.facility_bits} bits (max {dep.fmt.max_facility})."
        ),
        remediation=(
            "Migrate to a high-bit-count, cryptographically authenticated "
            "credential (e.g. Seos / DESFire EV2/EV3, iCLASS SE) rather than a "
            "static Wiegand format that can be read and replayed."
        ),
    )


def _numbering_factor(dep: Deployment) -> Finding:
    scheme = dep.numbering
    mapping = {
        NumberingScheme.SEQUENTIAL: (92, "critical",
            "Card numbers are issued strictly sequentially. Knowing one valid "
            "card lets an assessor predict every neighbour with near certainty."),
        NumberingScheme.SEQUENTIAL_GAPS: (78, "high",
            "Card numbers are near-sequential with small gaps -- neighbours are "
            "still highly predictable from a handful of reads."),
        NumberingScheme.CLUSTERED: (58, "high",
            "Card numbers are issued in a few contiguous departmental blocks; "
            "each block is internally predictable."),
        NumberingScheme.RANDOM: (18, "low",
            "Card numbers are randomised across the space, defeating "
            "neighbour-prediction (though the format itself may still be weak)."),
    }
    score, sev, detail = mapping[scheme]
    return Finding(
        factor="numbering",
        severity=sev,
        score=score,
        title=f"Numbering scheme: {scheme.value}",
        detail=detail,
        remediation=(
            "Issue card numbers from a cryptographically random, non-guessable "
            "pool and decouple them from any physical/temporal issuance order."
        ),
    )


def _clonability_factor(dep: Deployment) -> Finding:
    if dep.family == CardFamily.UID_ONLY:
        return Finding(
            factor="clonability", severity="critical", score=95,
            title="Card family: UID-only (no authentication)",
            detail="Credentials are UID-only low-frequency prox / read-only "
                   "cards. They carry no secret and can be cloned to a blank in "
                   "seconds by any reader.",
            remediation="Replace UID-only prox with a challenge-response smart "
                        "credential; never authorise access on UID alone.",
        )
    return Finding(
        factor="clonability", severity="medium", score=45,
        title="Card family: MIFARE Classic (sectored)",
        detail="Sectored cards carry per-sector keys, so cloning depends on "
               "key strength. MIFARE Classic's Crypto-1 cipher is itself "
               "academically broken, so weak/default keys are decisive.",
        remediation="Move off MIFARE Classic/Crypto-1 to AES-authenticated "
                    "DESFire-class credentials.",
    )


def _keys_factor(dep: Deployment) -> Finding:
    if dep.family != CardFamily.MIFARE_CLASSIC:
        return Finding(
            factor="keys", severity="info", score=0,
            title="Sector keys: not applicable",
            detail="UID-only credentials have no sector key material.",
            remediation="n/a",
        )
    posture = sector_key_posture(dep)
    default_sectors = [k for k in posture if keymod.is_default_key(k)]
    frac = len(default_sectors) / len(posture)
    shared = not dep.key_diversified
    score = int(min(100, frac * 70 + (30 if shared else 0)))
    if frac >= 0.5 or (shared and frac > 0):
        sev = "critical"
    elif frac > 0:
        sev = "high"
    else:
        sev = "low" if shared else "info"
    detail = (
        f"{len(default_sectors)}/{len(posture)} sectors "
        f"({frac:.0%}) still carry publicly documented default keys "
        f"(e.g. {', '.join(sorted(set(default_sectors))[:3]) or 'none'}). "
        + ("Keys are shared across the population, so recovering one card "
           "compromises all." if shared else
           "Keys are diversified per card, limiting blast radius.")
    )
    return Finding(
        factor="keys", severity=sev, score=score,
        title="Sector key hygiene",
        detail=detail,
        remediation=(
            "Rotate every sector off factory/default keys, use per-card "
            "diversified keys derived from a master + UID, and store no key "
            "material in the clear."
        ),
    )


def _characterization_factor(dep: Deployment, methods: dict) -> Finding:
    ml = methods["ml"]
    bf = methods["bruteforce"]
    ml_q = ml.queries_to_target
    bf_q = bf.queries_to_target or 1
    if ml_q is None:
        score = 20
        detail = ("Even the guided auditor could not characterise 90% of the "
                  "population within budget -- the deployment resists mapping.")
        sev = "low"
    else:
        # Fewer attempts to characterise => more auditable => weaker.
        savings = bf_q / max(ml_q, 1)
        score = int(min(100, 30 + math.log10(max(savings, 1)) * 20))
        sev = "high" if savings > 100 else "medium"
        detail = (
            f"Guided search characterised 90% of the issued population in "
            f"{ml_q:,} reader queries versus ~{bf_q:,} for brute force "
            f"(~{savings:,.0f}x fewer attempts). Low attempts-to-characterize "
            f"is itself a weakness signal."
        )
    return Finding(
        factor="characterization", severity=sev, score=score,
        title="Attempts-to-characterize",
        detail=detail,
        remediation=("Randomised numbering and authenticated credentials both "
                     "raise the query cost of mapping the population."),
    )


def _guessability_factor(dep: Deployment) -> Finding:
    g = assess_guessability(dep)
    # Fewer bits of guessing an informed adversary faces => weaker.
    score = int(min(100, max(0, (18 - g.informed_guess_bits) / 18 * 100)))
    if g.informed_guess_bits < 4:
        sev = "critical"
    elif g.informed_guess_bits < 8:
        sev = "high"
    elif g.informed_guess_bits < 14:
        sev = "medium"
    else:
        sev = "low"
    return Finding(
        factor="guessability", severity=sev, score=score,
        title=f"Credential guessing-resistance: {g.informed_guess_bits:.1f} bits "
              f"({g.rating})",
        detail=(
            f"A blind adversary faces ~{g.naive_guess_bits:.1f} bits of guessing "
            f"to forge a valid credential; one that reasons about structure "
            f"(locked facility code + bounded {g.issued_range:,}-wide range at "
            f"{g.density:.1%} density) faces only ~{g.informed_guess_bits:.1f} "
            f"bits. This deployment therefore **leaks ~{g.leaked_bits:.1f} bits** "
            f"of credential security to a structure-aware attacker."),
        remediation=(
            "Widen the effective key space that survives inference: randomise "
            "card numbers across the full field and authenticate the credential "
            "so a guessed number alone is worthless."),
    )


def audit_deployment(dep: Deployment, n_observations: int = 8) -> AuditResult:
    methods = run_all_methods(dep, n_observations=n_observations)
    findings = [
        _format_factor(dep),
        _numbering_factor(dep),
        _clonability_factor(dep),
        _keys_factor(dep),
        _characterization_factor(dep, methods),
        _guessability_factor(dep),
    ]
    composite = sum(WEIGHTS[f.factor] * f.score for f in findings)
    risk = int(round(composite))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.score))

    # Bayesian population sizing: how cheaply can the population be estimated?
    est_reader = SimulatedReader.from_deployment(dep)
    seed_cn = dep.observed_sample(n_observations)[0].card_number
    est = estimate_population(est_reader, dep.fmt, dep.facility_code, seed_cn)
    issued = len(dep.credentials)

    g = assess_guessability(dep)
    metrics = {
        "bruteforce_queries": methods["bruteforce"].queries_to_target,
        "dictionary_queries": methods["dictionary"].queries_to_target,
        "ml_queries": methods["ml"].queries_to_target,
        "ml_fraction_found": round(methods["ml"].fraction_found, 3),
        "issued": issued,
        "population_estimate": est.count_est,
        "population_estimate_queries": est.queries,
        "population_estimate_error": round(abs(est.count_est - issued) / issued, 3),
        "naive_guess_bits": round(g.naive_guess_bits, 2),
        "informed_guess_bits": round(g.informed_guess_bits, 2),
        "leaked_bits": round(g.leaked_bits, 2),
        "guessability_rating": g.rating,
    }
    return AuditResult(
        deployment=dep.name,
        risk_score=risk,
        risk_band=_band(risk),
        findings=findings,
        metrics=metrics,
    )


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------
_BADGE = {
    "critical": "🟥 CRITICAL",
    "high": "🟧 HIGH",
    "medium": "🟨 MEDIUM",
    "low": "🟩 LOW",
    "info": "⬜ INFO",
}


def render_markdown(result: AuditResult, dep: Optional[Deployment] = None) -> str:
    lines: List[str] = []
    lines.append(f"# PhantomTap Access-Control Audit Report")
    lines.append("")
    lines.append(f"**Deployment:** `{result.deployment}`  ")
    lines.append(f"**Composite risk score:** **{result.risk_score}/100** "
                 f"→ **{result.risk_band}**  ")
    if dep is not None:
        s = dep.summary()
        lines.append(f"**Format:** {s['format']} · **Facility code:** "
                     f"{s['facility_code']} · **Numbering:** {s['numbering']} · "
                     f"**Family:** {s['family']} · **Issued:** {s['issued']:,}  ")
    lines.append("")
    lines.append("> Higher score = weaker / more easily audited deployment. "
                 "This assessment was produced against a synthetic or "
                 "author-owned system for defensive evaluation only.")
    lines.append("")
    lines.append("## Findings (most severe first)")
    lines.append("")
    lines.append("| # | Severity | Factor | Finding |")
    lines.append("|---|----------|--------|---------|")
    for i, f in enumerate(result.findings, 1):
        lines.append(f"| {i} | {_BADGE.get(f.severity, f.severity)} | "
                     f"`{f.factor}` | {f.title} |")
    lines.append("")
    for i, f in enumerate(result.findings, 1):
        lines.append(f"### {i}. {f.title}  {_BADGE.get(f.severity, f.severity)}")
        lines.append("")
        lines.append(f"- **Factor:** `{f.factor}` (sub-score {f.score}/100)")
        lines.append(f"- **Detail:** {f.detail}")
        lines.append(f"- **Remediation:** {f.remediation}")
        lines.append("")
    lines.append("## Efficiency evidence")
    lines.append("")
    m = result.metrics
    lines.append("| Strategy | Reader queries to characterize 90% |")
    lines.append("|----------|-----------------------------------:|")
    lines.append(f"| Brute force | {_fmt_q(m['bruteforce_queries'])} |")
    lines.append(f"| Static dictionary | {_fmt_q(m['dictionary_queries'])} |")
    lines.append(f"| **PhantomTap (ML-guided)** | **{_fmt_q(m['ml_queries'])}** |")
    lines.append("")
    if m["ml_queries"] and m["bruteforce_queries"]:
        factor = m["bruteforce_queries"] / max(m["ml_queries"], 1)
        lines.append(f"PhantomTap characterized the population with roughly "
                     f"**{factor:,.0f}× fewer** reader interactions than blind "
                     f"brute force.")
    lines.append("")
    lines.append("### Bayesian population sizing")
    lines.append("")
    lines.append(
        f"Active-learning boundary search estimated **~{m['population_estimate']:,} "
        f"issued credentials** (true: {m['issued']:,}, error "
        f"{m['population_estimate_error']:.0%}) in just "
        f"**{m['population_estimate_queries']:,} reader queries** — recovering the "
        f"population size in O(log N) rather than scanning O(N). "
        f"{'A low error here is itself a weakness: the population is compact and predictable.' if m['population_estimate_error'] < 0.2 else 'The high error reflects randomised numbering that resists reconnaissance — a positive sign.'}")
    lines.append("")
    lines.append("### Information-theoretic guessing-resistance")
    lines.append("")
    lines.append(
        f"A blind adversary faces **~{m['naive_guess_bits']:.1f} bits** of guessing "
        f"to forge a valid credential; a structure-aware one faces only "
        f"**~{m['informed_guess_bits']:.1f} bits** ({m['guessability_rating']}). "
        f"The deployment **leaks ~{m['leaked_bits']:.1f} bits** of credential "
        f"security to anyone who reasons about its structure instead of brute-forcing.")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by PhantomTap. Authorized, defensive use only.*")
    return "\n".join(lines)


def _fmt_q(q: Optional[int]) -> str:
    if q is None:
        return "not reached (budget-limited)"
    return f"{q:,}"
