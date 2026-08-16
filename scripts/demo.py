"""A guided, end-to-end PhantomTap demo on one synthetic deployment.

Run::

    python -m scripts.demo

It walks the whole pipeline: fabricate a deployment -> capture a few reads ->
infer structure -> guided characterization vs. baselines -> audit report.
Also writes ``examples/sample_audit_report.md`` and a JSON result.
"""

from __future__ import annotations

import json
from pathlib import Path

from phantomtap.audit import audit_deployment, render_markdown
from phantomtap.generator import run_all_methods
from phantomtap.inference import infer_format
from phantomtap.population import CardFamily, NumberingScheme, generate_deployment

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    dep = generate_deployment(
        fmt_name="H10301-26",
        numbering=NumberingScheme.SEQUENTIAL,
        family=CardFamily.MIFARE_CLASSIC,
        issued=500,
        uses_default_keys=True,
        default_key_fraction=0.6,
        key_diversified=False,
        seed=7,
    )
    print("=" * 70)
    print("1. Synthetic deployment (ground truth hidden from the auditor):")
    print(json.dumps(dep.summary(), indent=2))

    obs = [c.raw for c in dep.observed_sample(8)]
    print("\n2. Auditor captures 8 card reads:")
    for r in obs:
        print("   ", dep.fmt.decode(r))

    hyp = infer_format(obs)
    print("\n3. Inferred structure from those 8 reads:")
    print(json.dumps(hyp.as_dict(), indent=2))

    print("\n4. Attempts-to-characterize (queries to map 90% of the population):")
    methods = run_all_methods(dep, n_observations=8, seed=7)
    for name in ("bruteforce", "dictionary", "ml"):
        q = methods[name].queries_to_target
        print(f"   {name:>12}: {q:,}" if q else f"   {name:>12}: not reached")
    bf, ml = methods["bruteforce"].queries_to_target, methods["ml"].queries_to_target
    print(f"   -> PhantomTap is ~{bf/max(ml,1):,.0f}x more efficient.")

    result = audit_deployment(dep, n_observations=8)
    report = render_markdown(result, dep)
    (ROOT / "examples").mkdir(exist_ok=True)
    (ROOT / "examples" / "sample_audit_report.md").write_text(report)
    (ROOT / "examples" / "sample_audit_result.json").write_text(
        json.dumps(result.as_dict(), indent=2))
    print(f"\n5. Audit report -> examples/sample_audit_report.md")
    print(f"   Composite risk: {result.risk_score}/100 ({result.risk_band})")
    print("=" * 70)


if __name__ == "__main__":
    main()
