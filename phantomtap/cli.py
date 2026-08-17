"""PhantomTap command-line interface.

Subcommands:

    phantomtap demo        end-to-end walkthrough on a synthetic deployment
    phantomtap audit       score a synthetic deployment and print/save a report
    phantomtap benchmark   attempts-to-characterize: ML vs dictionary vs brute
    phantomtap monitor     blue-team: detect clone/scan/off-hours/rogue events
    phantomtap figures     regenerate all charts into docs/figures/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .audit import audit_deployment, render_markdown
from .inference import infer_format
from .population import CardFamily, NumberingScheme, generate_deployment


def _dep_from_args(args) -> "Deployment":
    return generate_deployment(
        fmt_name=args.format,
        numbering=NumberingScheme(args.numbering),
        family=CardFamily(args.family),
        issued=args.issued,
        seed=args.seed,
    )


def cmd_demo(args) -> int:
    dep = _dep_from_args(args)
    print(f"== PhantomTap demo ==\nDeployment: {dep.name}")
    print(json.dumps(dep.summary(), indent=2))
    obs = [c.raw for c in dep.observed_sample(args.observations)]
    print(f"\nCaptured {len(obs)} card reads (as an auditor would):")
    for r in obs[:8]:
        print(f"  raw=0x{r:X}  {dep.fmt.decode(r)}")
    hyp = infer_format(obs)
    print("\nInferred structure from those reads:")
    print(json.dumps(hyp.as_dict(), indent=2))
    result = audit_deployment(dep, n_observations=args.observations)
    print(f"\nComposite risk: {result.risk_score}/100 ({result.risk_band})")
    print("Top findings:")
    for f in result.findings[:3]:
        print(f"  [{f.severity.upper():8}] {f.title}")
    return 0


def cmd_audit(args) -> int:
    dep = _dep_from_args(args)
    result = audit_deployment(dep, n_observations=args.observations)
    report = render_markdown(result, dep)
    if args.out:
        Path(args.out).write_text(report)
        print(f"wrote report to {args.out}")
    else:
        print(report)
    if args.json:
        Path(args.json).write_text(json.dumps(result.as_dict(), indent=2))
        print(f"wrote json to {args.json}")
    return 0


def cmd_benchmark(args) -> int:
    from .generator import run_all_methods

    dep = _dep_from_args(args)
    methods = run_all_methods(dep, n_observations=args.observations)
    print(f"Deployment: {dep.name}  (issued={len(dep.credentials)})")
    print(f"{'method':>12} | queries-to-90%")
    print("-" * 34)
    for name in ("bruteforce", "dictionary", "ml"):
        r = methods[name]
        q = r.queries_to_target
        print(f"{name:>12} | {q if q is not None else 'not reached':>14}")
    ml_q = methods["ml"].queries_to_target
    bf_q = methods["bruteforce"].queries_to_target
    if ml_q and bf_q:
        print(f"\nML-guided is ~{bf_q / max(ml_q,1):,.0f}x more efficient than brute force.")
    return 0


def cmd_monitor(args) -> int:
    from .monitor import analyze, red_vs_blue, synthetic_stream

    dep = _dep_from_args(args)
    events, injected = synthetic_stream(dep, seed=args.seed)
    alerts = analyze(events, dep=dep)
    print(f"== PhantomTap blue-team monitor ==")
    print(f"Deployment: {dep.name}")
    print(f"Analysed {len(events)} badge events; injected attacks: "
          f"{', '.join(injected)}")
    print(f"\n{len(alerts)} alert(s):")
    for a in alerts:
        print(f"  [{a.severity.upper():8}] {a.kind:18} t={a.t/3600:05.2f}h  {a.detail}")

    kinds_found = {a.kind for a in alerts}
    caught = [k for k in injected if k in kinds_found]
    print(f"\nDetection coverage: {len(caught)}/{len(injected)} injected attack "
          f"types caught ({', '.join(caught) or 'none'}).")

    rb = red_vs_blue(dep, rate_per_min=40.0)
    print(f"\nRed-vs-blue: PhantomTap's own ML auditor made {rb.attempts_total:,} "
          f"reader presentations; the enumeration detector "
          + (f"flagged it after {rb.detected_after_attempts} attempts."
             if rb.detected else "did not flag it."))
    return 0


def cmd_figures(args) -> int:
    from scripts import make_figures  # type: ignore

    make_figures.main()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phantomtap", description=__doc__)
    p.add_argument("--version", action="version", version=f"phantomtap {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("--format", default="H10301-26",
                        help="Wiegand format name (default: H10301-26)")
        sp.add_argument("--numbering", default="sequential",
                        choices=[n.value for n in NumberingScheme])
        sp.add_argument("--family", default="mifare_classic",
                        choices=[c.value for c in CardFamily])
        sp.add_argument("--issued", type=int, default=500)
        sp.add_argument("--observations", type=int, default=8)
        sp.add_argument("--seed", type=int, default=0)

    sp = sub.add_parser("demo", help="end-to-end walkthrough")
    add_common(sp)
    sp.set_defaults(func=cmd_demo)

    sp = sub.add_parser("audit", help="score a deployment and render a report")
    add_common(sp)
    sp.add_argument("--out", help="write Markdown report to this path")
    sp.add_argument("--json", help="write JSON result to this path")
    sp.set_defaults(func=cmd_audit)

    sp = sub.add_parser("benchmark", help="attempts-to-characterize comparison")
    add_common(sp)
    sp.set_defaults(func=cmd_benchmark)

    sp = sub.add_parser("monitor", help="blue-team detection over a badge stream")
    add_common(sp)
    sp.set_defaults(func=cmd_monitor)

    sp = sub.add_parser("figures", help="regenerate charts into docs/figures/")
    sp.set_defaults(func=cmd_figures)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
