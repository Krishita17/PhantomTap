"""Full attempts-to-characterize benchmark -> results table (Markdown + JSON).

Sweeps every (format x numbering) combination over several seeds and records:

* median reader queries to characterize 90% for each strategy,
* the ML efficiency factor vs. brute force,
* inference accuracy (format + numbering class),
* the resulting composite risk score.

Run::

    python -m scripts.run_benchmark
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from phantomtap.audit import audit_deployment
from phantomtap.formats import ALL_FORMATS
from phantomtap.generator import run_all_methods
from phantomtap.inference import infer_format
from phantomtap.population import NumberingScheme, generate_deployment

OUT = Path(__file__).resolve().parents[1] / "docs"
SEEDS = range(8)
N_OBS = 8


def _numbering_class(scheme: NumberingScheme) -> str:
    if scheme in (NumberingScheme.SEQUENTIAL, NumberingScheme.SEQUENTIAL_GAPS):
        return "sequential-like"
    return scheme.value


def run() -> list:
    rows = []
    for fmt in ALL_FORMATS:
        for scheme in NumberingScheme:
            bf, dct, ml = [], [], []
            fmt_ok, num_ok, risk = [], [], []
            for s in SEEDS:
                dep = generate_deployment(fmt_name=fmt.name, numbering=scheme,
                                          issued=400, seed=s)
                res = run_all_methods(dep, n_observations=N_OBS, seed=s)
                bf.append(res["bruteforce"].queries_to_target)
                dct.append(res["dictionary"].queries_to_target)
                ml.append(res["ml"].queries_to_target)
                obs = [c.raw for c in dep.observed_sample(N_OBS)]
                hyp = infer_format(obs)
                # "Recovered" = the true format is among the parity-consistent
                # set (exact width is only identifiable when high bits are used).
                fmt_ok.append(1 if fmt.name in hyp.consistent_formats else 0)
                num_ok.append(1 if _numbering_class(hyp.numbering) ==
                              _numbering_class(scheme) else 0)
                risk.append(audit_deployment(dep).risk_score)
            mbf = statistics.median([x for x in bf if x])
            mml = statistics.median([x for x in ml if x])
            rows.append({
                "format": fmt.name,
                "numbering": scheme.value,
                "bruteforce_q": int(mbf),
                "dictionary_q": int(statistics.median([x for x in dct if x])),
                "ml_q": int(mml),
                "ml_speedup": round(mbf / max(mml, 1), 1),
                "fmt_acc": round(statistics.mean(fmt_ok), 3),
                "num_acc": round(statistics.mean(num_ok), 3),
                "risk": round(statistics.mean(risk), 1),
            })
    return rows


def to_markdown(rows: list) -> str:
    lines = ["# PhantomTap benchmark results", "",
             f"Median over {len(list(SEEDS))} seeds · {N_OBS} observed cards · "
             "400 issued credentials per deployment.", "",
             "| Format | Numbering | Brute force | Dictionary | "
             "**ML (PhantomTap)** | Speedup | Fmt acc | Num acc | Risk |",
             "|--------|-----------|------------:|-----------:|"
             "--------------------:|--------:|--------:|--------:|-----:|"]
    for r in rows:
        lines.append(
            f"| {r['format']} | {r['numbering']} | {r['bruteforce_q']:,} | "
            f"{r['dictionary_q']:,} | **{r['ml_q']:,}** | "
            f"{r['ml_speedup']:,}× | {r['fmt_acc']:.2f} | {r['num_acc']:.2f} | "
            f"{r['risk']:.0f} |")
    lines.append("")
    speedups = [r["ml_speedup"] for r in rows]
    lines.append(f"**Median ML speedup across all configs: "
                 f"{statistics.median(speedups):,.0f}×** "
                 f"(min {min(speedups):,.0f}×, max {max(speedups):,.0f}×).")
    return "\n".join(lines)


def main() -> None:
    rows = run()
    (OUT / "benchmark_results.json").write_text(json.dumps(rows, indent=2))
    md = to_markdown(rows)
    (OUT / "benchmark_results.md").write_text(md)
    print(md)
    print(f"\nwrote {OUT/'benchmark_results.md'} and .json")


if __name__ == "__main__":
    main()
