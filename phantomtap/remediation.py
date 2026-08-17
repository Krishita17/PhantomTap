"""Prioritized remediation planning: which single fix buys the most safety?

An audit that only scores a deployment leaves the owner asking "so what do I do
first?". PhantomTap answers it. For each candidate hardening step it builds a
*counterfactual* deployment with that one knob changed, re-scores it, and ranks
the fixes by **risk reduction per fix** -- a prioritized roadmap where the top
line is the highest-leverage change.

The scoring uses :func:`phantomtap.audit.quick_risk_score` so a full plan is
cheap to compute (no per-variant characterization sweep).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .audit import quick_risk_score
from .population import (
    CardFamily,
    Deployment,
    NumberingScheme,
    generate_deployment,
)


@dataclass
class Fix:
    action: str
    detail: str
    new_risk: int
    delta: int          # risk points removed by this fix (vs. current baseline)

    def as_dict(self) -> dict:
        return {"action": self.action, "detail": self.detail,
                "new_risk": self.new_risk, "delta": self.delta}


def _clone(dep: Deployment, **overrides) -> Deployment:
    """Rebuild a deployment with the same knobs except the given overrides."""
    kw = dict(
        fmt_name=dep.fmt.name,
        numbering=dep.numbering,
        family=dep.family,
        issued=len(dep.credentials),
        facility_code=dep.facility_code,
        uses_default_keys=dep.uses_default_keys,
        default_key_fraction=dep.default_key_fraction,
        key_diversified=dep.key_diversified,
        seed=dep.seed,
    )
    kw.update(overrides)
    # facility_code may be out of range for a stronger/weaker format swap; drop
    # it so the generator picks a valid one for the new format.
    if "fmt_name" in overrides:
        kw["facility_code"] = None
    return generate_deployment(**kw)


def candidate_fixes(dep: Deployment) -> List[Fix]:
    """All applicable single-step hardening fixes, each scored independently."""
    base = quick_risk_score(dep)
    out: List[Fix] = []

    def add(action: str, detail: str, variant: Deployment) -> None:
        r = quick_risk_score(variant)
        out.append(Fix(action, detail, r, base - r))

    if dep.numbering != NumberingScheme.RANDOM:
        add("Randomize card numbering",
            "Issue card numbers from a cryptographically random pool so "
            "neighbours can't be predicted from a few reads.",
            _clone(dep, numbering=NumberingScheme.RANDOM))

    if dep.family == CardFamily.MIFARE_CLASSIC and dep.uses_default_keys:
        add("Rotate off default keys",
            "Replace every factory/default sector key with a unique secret.",
            _clone(dep, uses_default_keys=False, default_key_fraction=0.0))

    if dep.family == CardFamily.MIFARE_CLASSIC and not dep.key_diversified:
        add("Diversify keys per card",
            "Derive a unique per-card key (master + UID) so one recovered card "
            "doesn't compromise the whole population.",
            _clone(dep, key_diversified=True))

    if dep.family == CardFamily.UID_ONLY:
        add("Replace UID-only credentials",
            "Move from clonable read-only prox to an authenticated smart "
            "credential; never authorise on UID alone.",
            _clone(dep, family=CardFamily.MIFARE_CLASSIC))

    if dep.fmt.total_bits < 37:
        add("Upgrade credential format",
            "Adopt a wider, authenticated credential (e.g. 37-bit / DESFire) to "
            "enlarge the key space that survives inference.",
            _clone(dep, fmt_name="H10304-37"))

    out.sort(key=lambda f: f.delta, reverse=True)
    return out


def prioritized_plan(dep: Deployment) -> List[Fix]:
    """Greedy cumulative roadmap: apply the best remaining fix, re-rank, repeat.

    Returns the ordered list of fixes with ``new_risk`` reflecting the *running*
    risk after each step (a realistic remediation sequence, not independent
    deltas).
    """
    current = dep
    plan: List[Fix] = []
    applied: set = set()
    while True:
        base = quick_risk_score(current)
        best = None
        for fix in candidate_fixes(current):
            if fix.action in applied:
                continue
            if best is None or fix.delta > best.delta:
                best = fix
        if best is None or best.delta <= 0:
            break
        applied.add(best.action)
        # rebuild `current` with this fix applied so subsequent deltas compound
        current = _apply(current, best.action)
        new_risk = quick_risk_score(current)
        plan.append(Fix(best.action, best.detail, new_risk, base - new_risk))
    return plan


def _apply(dep: Deployment, action: str) -> Deployment:
    if action == "Randomize card numbering":
        return _clone(dep, numbering=NumberingScheme.RANDOM)
    if action == "Rotate off default keys":
        return _clone(dep, uses_default_keys=False, default_key_fraction=0.0)
    if action == "Diversify keys per card":
        return _clone(dep, key_diversified=True)
    if action == "Replace UID-only credentials":
        return _clone(dep, family=CardFamily.MIFARE_CLASSIC)
    if action == "Upgrade credential format":
        return _clone(dep, fmt_name="H10304-37")
    return dep
