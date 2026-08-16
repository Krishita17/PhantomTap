"""Generate every chart in the PhantomTap paper/README.

Run::

    python -m scripts.make_figures      # or: phantomtap figures

Outputs PNG + SVG into ``docs/figures/``.  All numbers are produced live by the
pipeline -- there is no hand-authored data here.
"""

from __future__ import annotations

import math
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from phantomtap.audit import audit_deployment
from phantomtap.bayes import estimate_population
from phantomtap.generator import (
    ml_characterize,
    run_all_methods,
)
from phantomtap.inference import infer_format
from phantomtap.population import CardFamily, NumberingScheme, generate_deployment
from phantomtap.reader import SimulatedReader

FIG = Path(__file__).resolve().parents[1] / "docs" / "figures"
FIG.mkdir(parents=True, exist_ok=True)

# A restrained, colour-blind-safe palette used across all figures.
C_ML = "#1b7837"      # green  -> PhantomTap
C_DICT = "#762a83"    # purple -> dictionary
C_BF = "#b2182b"      # red    -> brute force
C_ACCENT = "#2166ac"  # blue   -> accent / secondary
GRID = "#d9d9d9"

plt.rcParams.update({
    "figure.dpi": 130,
    "savefig.dpi": 130,
    "font.size": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.8,
    "axes.axisbelow": True,
})


def _save(fig, name: str) -> None:
    for ext in ("png", "svg"):
        fig.savefig(FIG / f"{name}.{ext}", bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {name}.png / .svg")


# ---------------------------------------------------------------------------
def fig_attempts_to_characterize() -> None:
    """Headline: queries-to-90% across numbering schemes, three strategies."""
    schemes = [
        (NumberingScheme.SEQUENTIAL, "sequential"),
        (NumberingScheme.SEQUENTIAL_GAPS, "seq+gaps"),
        (NumberingScheme.CLUSTERED, "clustered"),
        (NumberingScheme.RANDOM, "random"),
    ]
    seeds = range(6)
    bf, dct, ml = [], [], []
    for scheme, _ in schemes:
        bfs, ds, ms = [], [], []
        for s in seeds:
            dep = generate_deployment(numbering=scheme, issued=400, seed=s)
            res = run_all_methods(dep, seed=s)
            bfs.append(res["bruteforce"].queries_to_target or np.nan)
            ds.append(res["dictionary"].queries_to_target or np.nan)
            ms.append(res["ml"].queries_to_target or np.nan)
        bf.append(np.nanmedian(bfs))
        dct.append(np.nanmedian(ds))
        ml.append(np.nanmedian(ms))

    x = np.arange(len(schemes))
    w = 0.26
    fig, ax = plt.subplots(figsize=(8.2, 4.6))
    ax.bar(x - w, bf, w, label="Brute force", color=C_BF)
    ax.bar(x, dct, w, label="Static dictionary", color=C_DICT)
    ax.bar(x + w, ml, w, label="PhantomTap (ML-guided)", color=C_ML)
    ax.set_yscale("log")
    ax.set_ylabel("Reader queries to characterize 90%  (log scale)")
    ax.set_xticks(x, [s[1] for s in schemes])
    ax.set_xlabel("Numbering scheme")
    ax.set_title("Attempts-to-characterize: ML guidance vs. baselines",
                 fontweight="bold")
    ax.legend(frameon=False, loc="upper right")
    for xi, mlv, bfv in zip(x, ml, bf):
        if mlv and bfv:
            ax.annotate(f"{bfv/mlv:,.0f}×\nfewer", (xi + w, mlv),
                        textcoords="offset points", xytext=(0, 6),
                        ha="center", fontsize=8, color=C_ML, fontweight="bold")
    _save(fig, "attempts_to_characterize")


def fig_inference_vs_n() -> None:
    """Inference accuracy (format + numbering) vs. number of observed cards."""
    ns = list(range(2, 21))
    fmt_acc, num_acc = [], []
    trials = 60
    for n in ns:
        fok = nok = 0
        for t in range(trials):
            scheme = [NumberingScheme.SEQUENTIAL, NumberingScheme.CLUSTERED,
                      NumberingScheme.RANDOM][t % 3]
            fmtname = ["H10301-26", "N10002-34", "H10304-37",
                       "H10302-37"][t % 4]
            dep = generate_deployment(fmt_name=fmtname, numbering=scheme,
                                      issued=500, seed=1000 + t)
            obs = [c.raw for c in dep.observed_sample(n)]
            hyp = infer_format(obs)
            if dep.fmt.name in hyp.consistent_formats:
                fok += 1
            if _numbering_class(hyp.numbering) == _numbering_class(dep.numbering):
                nok += 1
        fmt_acc.append(fok / trials)
        num_acc.append(nok / trials)

    fig, ax = plt.subplots(figsize=(7.6, 4.4))
    ax.plot(ns, fmt_acc, "-o", color=C_ACCENT, label="Format recovery", ms=4)
    ax.plot(ns, num_acc, "-s", color=C_ML, label="Numbering-class recovery", ms=4)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("Number of observed cards")
    ax.set_ylabel("Accuracy")
    ax.set_title("Inference accuracy vs. observations", fontweight="bold")
    ax.legend(frameon=False, loc="lower right")
    _save(fig, "inference_vs_n")


def _numbering_class(scheme: NumberingScheme) -> str:
    if scheme in (NumberingScheme.SEQUENTIAL, NumberingScheme.SEQUENTIAL_GAPS):
        return "sequential-like"
    return scheme.value


def fig_risk_vs_config() -> None:
    """Weakness sensitivity: risk score across deployment design choices."""
    configs = [
        ("26-bit / seq / UID-only / default keys",
         dict(fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
              family=CardFamily.UID_ONLY, uses_default_keys=True,
              default_key_fraction=0.9, key_diversified=False)),
        ("26-bit / seq / MIFARE / default keys",
         dict(fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
              family=CardFamily.MIFARE_CLASSIC, uses_default_keys=True,
              default_key_fraction=0.6, key_diversified=False)),
        ("34-bit / clustered / MIFARE / some defaults",
         dict(fmt_name="N10002-34", numbering=NumberingScheme.CLUSTERED,
              family=CardFamily.MIFARE_CLASSIC, uses_default_keys=True,
              default_key_fraction=0.3, key_diversified=False)),
        ("37-bit / random / MIFARE / diversified",
         dict(fmt_name="H10304-37", numbering=NumberingScheme.RANDOM,
              family=CardFamily.MIFARE_CLASSIC, uses_default_keys=False,
              default_key_fraction=0.0, key_diversified=True)),
    ]
    labels, scores = [], []
    for label, kw in configs:
        vals = []
        for s in range(5):
            dep = generate_deployment(issued=400, seed=s, **kw)
            vals.append(audit_deployment(dep).risk_score)
        labels.append(label)
        scores.append(statistics.mean(vals))

    colors = [C_BF if v >= 75 else "#f4a582" if v >= 55 else "#92c5de"
              if v >= 35 else C_ML for v in scores]
    fig, ax = plt.subplots(figsize=(8.6, 4.6))
    y = np.arange(len(labels))
    ax.barh(y, scores, color=colors)
    ax.set_yticks(y, labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Composite risk score (higher = weaker)")
    ax.set_title("Risk score vs. deployment configuration", fontweight="bold")
    for yi, v in zip(y, scores):
        ax.annotate(f"{v:.0f}", (v, yi), xytext=(4, 0),
                    textcoords="offset points", va="center", fontsize=9,
                    fontweight="bold")
    for xv, lbl in ((75, "CRIT"), (55, "HIGH"), (35, "MED")):
        ax.axvline(xv, color=GRID, lw=1, ls="--")
    _save(fig, "risk_vs_config")


def fig_learning_curve() -> None:
    """Tier-3: discovery trajectory of the active-learning generator."""
    fig, ax = plt.subplots(figsize=(7.8, 4.4))
    for scheme, color, name, style in [
        (NumberingScheme.SEQUENTIAL, C_ML, "sequential", "-"),
        (NumberingScheme.CLUSTERED, C_ACCENT, "clustered", "--"),
        (NumberingScheme.RANDOM, C_DICT, "random", "-."),
    ]:
        dep = generate_deployment(numbering=scheme, issued=400, seed=3)
        reader = SimulatedReader.from_deployment(dep)
        obs = [c.raw for c in dep.observed_sample(8)]
        res = ml_characterize(reader, dep, obs)
        traj = np.array([(max(q, 1), d) for q, d in res.trajectory])
        frac = traj[:, 1] / dep.summary()["issued"]
        ax.plot(traj[:, 0], frac, style, color=color, label=name, lw=2.0)
    ax.axhline(0.9, color=C_BF, ls=":", lw=1.2, label="90% target")
    ax.set_xscale("log")
    ax.set_xlim(1, None)
    ax.set_xlabel("Reader queries (log scale)")
    ax.set_ylabel("Fraction of population discovered")
    ax.set_ylim(0, 1.02)
    ax.set_title("Active-learning discovery curve", fontweight="bold")
    ax.legend(frameon=False, loc="lower right")
    _save(fig, "learning_curve")


def fig_population_estimation() -> None:
    """Bayesian active-learning: size a population in O(log N), not O(N).

    Left panel  -- reader queries to estimate the population size vs. the true
    size, for sequential numbering, against the O(N) exhaustive-scan reference.
    Right panel -- estimation error by numbering scheme: tight for
    sequential-like layouts, large for randomised numbering, which *resists*
    reconnaissance (a positive security property).
    """
    sizes = [100, 200, 400, 800, 1600, 3200, 6400]
    seeds = range(5)
    q_bayes = []
    for n in sizes:
        qs = []
        for s in seeds:
            dep = generate_deployment(numbering=NumberingScheme.SEQUENTIAL,
                                      issued=n, seed=100 + s)
            reader = SimulatedReader.from_deployment(dep)
            seed_cn = dep.observed_sample(8, )[0].card_number
            est = estimate_population(reader, dep.fmt, dep.facility_code, seed_cn)
            qs.append(est.queries)
        q_bayes.append(statistics.median(qs))

    schemes = [
        (NumberingScheme.SEQUENTIAL, "sequential"),
        (NumberingScheme.CLUSTERED, "clustered"),
        (NumberingScheme.RANDOM, "random"),
    ]
    errs, err_sd = [], []
    for scheme, _ in schemes:
        es = []
        for s in seeds:
            dep = generate_deployment(numbering=scheme, issued=800, seed=200 + s)
            reader = SimulatedReader.from_deployment(dep)
            seed_cn = dep.observed_sample(8)[0].card_number
            est = estimate_population(reader, dep.fmt, dep.facility_code, seed_cn)
            es.append(abs(est.count_est - len(dep.credentials)) / len(dep.credentials))
        errs.append(statistics.mean(es))
        err_sd.append(statistics.pstdev(es))

    fig, (axl, axr) = plt.subplots(1, 2, figsize=(11.4, 4.5))

    axl.plot(sizes, q_bayes, "-o", color=C_ML, lw=2, ms=5,
             label="Bayesian sizing (PhantomTap)")
    axl.plot(sizes, sizes, "--", color=C_BF, lw=1.6,
             label="Exhaustive scan  O(N)")
    axl.set_xscale("log"); axl.set_yscale("log")
    axl.set_xlabel("True issued population size N")
    axl.set_ylabel("Reader queries to size the population")
    axl.set_title("Population sizing cost: O(log N) vs O(N)", fontweight="bold")
    axl.legend(frameon=False, loc="upper left")
    axl.annotate("~flat: cost grows\nlogarithmically",
                 (sizes[-1], q_bayes[-1]), textcoords="offset points",
                 xytext=(-10, 18), ha="right", fontsize=8.5, color=C_ML,
                 fontweight="bold")

    x = np.arange(len(schemes))
    colors = [C_ML, C_ACCENT, C_BF]
    axr.bar(x, [e * 100 for e in errs], yerr=[e * 100 for e in err_sd],
            color=colors, capsize=4)
    axr.set_xticks(x, [s[1] for s in schemes])
    axr.set_ylabel("Population-size estimation error (%)")
    axr.set_xlabel("Numbering scheme")
    axr.set_title("Accuracy: predictable vs. resistant numbering",
                  fontweight="bold")
    for xi, e in zip(x, errs):
        axr.annotate(f"{e*100:.0f}%", (xi, e * 100), textcoords="offset points",
                     xytext=(0, 4), ha="center", fontsize=9, fontweight="bold")
    _save(fig, "population_estimation")


def main() -> None:
    print("Generating figures ->", FIG)
    fig_attempts_to_characterize()
    fig_inference_vs_n()
    fig_risk_vs_config()
    fig_learning_curve()
    fig_population_estimation()
    print("done.")


if __name__ == "__main__":
    main()
