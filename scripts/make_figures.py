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

from phantomtap.audit import WEIGHTS, audit_deployment
from phantomtap.bayes import estimate_population
from phantomtap.remediation import prioritized_plan
from phantomtap.entropy import assess_guessability
from phantomtap.generator import (
    ml_characterize,
    run_all_methods,
)
from phantomtap.inference import infer_format
from phantomtap.monitor import (
    BadgeEvent,
    analyze,
    detect_enumeration,
    red_vs_blue,
    synthetic_stream,
)
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


def fig_guessability() -> None:
    """Information-theoretic view: effective security vs. structure leakage."""
    schemes = [
        (NumberingScheme.SEQUENTIAL, "sequential"),
        (NumberingScheme.CLUSTERED, "clustered"),
        (NumberingScheme.RANDOM, "random"),
    ]
    informed, leaked = [], []
    for scheme, _ in schemes:
        gi, gl = [], []
        for s in range(6):
            dep = generate_deployment(numbering=scheme, issued=500, seed=s)
            g = assess_guessability(dep)
            gi.append(g.informed_guess_bits)
            gl.append(g.leaked_bits)
        informed.append(statistics.mean(gi))
        leaked.append(statistics.mean(gl))

    x = np.arange(len(schemes))
    w = 0.38
    fig, ax = plt.subplots(figsize=(7.8, 4.5))
    ax.bar(x - w / 2, informed, w, label="Effective security (bits an\ninformed"
           " attacker still faces)", color=C_ML)
    ax.bar(x + w / 2, leaked, w, label="Leaked to structure (bits)", color=C_BF)
    ax.set_xticks(x, [s[1] for s in schemes])
    ax.set_ylabel("Bits")
    ax.set_xlabel("Numbering scheme")
    ax.set_title("Credential guessing-resistance (information-theoretic)",
                 fontweight="bold")
    ax.legend(frameon=False, loc="upper center", fontsize=8.5, ncol=1)
    for xi, v in zip(x, informed):
        ax.annotate(f"{v:.1f}", (xi - w / 2, v), textcoords="offset points",
                    xytext=(0, 3), ha="center", fontsize=8.5, fontweight="bold")
    for xi, v in zip(x, leaked):
        ax.annotate(f"{v:.1f}", (xi + w / 2, v), textcoords="offset points",
                    xytext=(0, 3), ha="center", fontsize=8.5, fontweight="bold")
    _save(fig, "guessability")


def _random_probe_latency(dep, rate_per_min, burst=240, window_s=90.0):
    """Detection latency (attempts) for a *random* facility probe at a rate."""
    import random as _r
    rng = _r.Random(7)
    fmt = dep.fmt
    dt = 60.0 / rate_per_min
    events = []
    for i in range(burst):
        cn = rng.randint(0, min(fmt.max_card, 200_000))
        raw = fmt.encode(dep.facility_code, cn)
        events.append(BadgeEvent(i * dt, "target", raw, raw in dep.valid_raws, cn))
    alerts = detect_enumeration(events, window_s=window_s)
    if not alerts:
        return None
    return int(round(min(a.t for a in alerts) / dt)) + 1


def fig_purple_team() -> None:
    """Reflexive result: guided search is *unconditionally* noisier than slow
    random probing -- its structured footprint is caught fast at any pace."""
    rates = [2, 5, 10, 20, 40, 80]
    dep = generate_deployment(numbering=NumberingScheme.SEQUENTIAL, issued=500,
                              seed=3)
    ml_lat, rnd_lat = [], []
    for r in rates:
        ml_lat.append(red_vs_blue(dep, rate_per_min=r).detected_after_attempts)
        rnd_lat.append(_random_probe_latency(dep, r))

    fig, (axl, axr) = plt.subplots(1, 2, figsize=(11.6, 4.5))

    # left: attack coverage on a mixed stream
    events, injected = synthetic_stream(dep, seed=3)
    alerts = analyze(events, dep=dep)
    kinds = ["impossible_travel", "enumeration", "off_hours", "rogue_credential"]
    counts = [sum(1 for a in alerts if a.kind == k) for k in kinds]
    colors = [C_BF, C_DICT, C_ACCENT, "#e08214"]
    axl.barh(np.arange(len(kinds)), counts, color=colors)
    axl.set_yticks(np.arange(len(kinds)),
                   [k.replace("_", "\n") for k in kinds], fontsize=9)
    axl.invert_yaxis()
    axl.set_xlabel("Alerts raised")
    axl.set_title(f"Detection coverage: {len(set(a.kind for a in alerts) & set(injected))}"
                  f"/{len(injected)} injected attacks caught", fontweight="bold")
    for yi, c in enumerate(counts):
        axl.annotate(str(c), (c, yi), xytext=(4, 0), textcoords="offset points",
                     va="center", fontsize=9, fontweight="bold")

    # right: detection latency vs attacker rate
    ml_plot = [v if v is not None else np.nan for v in ml_lat]
    rnd_plot = [v if v is not None else np.nan for v in rnd_lat]
    top = np.nanmax(ml_plot + rnd_plot) * 1.25
    axr.plot(rates, ml_plot, "-o", color=C_ML, lw=2, ms=6,
             label="ML-guided (region-growing)")
    axr.plot(rates, rnd_plot, "-s", color=C_DICT, lw=2, ms=6,
             label="Random probing")
    # mark evaded points for random probing along the bottom
    for r, v in zip(rates, rnd_lat):
        if v is None:
            axr.scatter([r], [2], marker="x", color=C_DICT, s=45, zorder=5)
            axr.annotate("evades", (r, 2), color=C_DICT, fontsize=8,
                         ha="center", va="bottom", xytext=(0, 4),
                         textcoords="offset points", fontweight="bold")
    axr.set_xscale("log")
    axr.set_xticks(rates)
    axr.set_xticklabels([str(r) for r in rates])
    axr.xaxis.set_minor_formatter(plt.NullFormatter())
    axr.tick_params(axis="x", which="minor", length=0)
    axr.set_ylim(0, top)
    axr.set_xlabel("Attacker attempt rate (per minute)")
    axr.set_ylabel("Attempts until detected")
    axr.set_title("Guided search is caught fast at any pace", fontweight="bold")
    axr.legend(frameon=False, loc="center right", fontsize=9)
    _save(fig, "purple_team")


def fig_remediation() -> None:
    """Waterfall: composite risk falling as the roadmap is applied in order."""
    dep = generate_deployment(
        fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
        family=CardFamily.UID_ONLY, uses_default_keys=True,
        default_key_fraction=0.9, key_diversified=False, seed=1)
    from phantomtap.audit import quick_risk_score
    base = quick_risk_score(dep)
    plan = prioritized_plan(dep)

    labels = ["Current"] + [f.action.replace(" ", "\n", 1) for f in plan]
    risks = [base] + [f.new_risk for f in plan]

    fig, ax = plt.subplots(figsize=(9.2, 4.8))
    x = np.arange(len(risks))
    band = [C_BF if r >= 75 else "#f4a582" if r >= 55 else "#92c5de"
            if r >= 35 else C_ML for r in risks]
    ax.plot(x, risks, "-", color="#666", lw=1.5, zorder=1)
    ax.scatter(x, risks, c=band, s=170, zorder=3, edgecolor="white", linewidth=1.5)
    for i in range(1, len(risks)):
        drop = risks[i - 1] - risks[i]
        if drop:
            ax.annotate(f"−{drop}", (x[i], risks[i]), textcoords="offset points",
                        xytext=(0, -18), ha="center", fontsize=9,
                        color=C_ML, fontweight="bold")
    for xi, r in zip(x, risks):
        ax.annotate(str(r), (xi, r), textcoords="offset points", xytext=(0, 10),
                    ha="center", fontsize=9, fontweight="bold")
    ax.set_xticks(x, labels, fontsize=8.5)
    ax.set_ylim(0, 100)
    ax.set_ylabel("Composite risk score")
    ax.set_title("Prioritized remediation: risk reduction per fix",
                 fontweight="bold")
    for yv, lbl in ((75, "CRIT"), (55, "HIGH"), (35, "MED")):
        ax.axhline(yv, color=GRID, lw=1, ls="--")
        ax.annotate(lbl, (len(risks) - 0.5, yv + 1), fontsize=7.5, color="#999")
    _save(fig, "remediation")


def fig_risk_factors() -> None:
    """What drives the score: weighted factor contributions, weak vs. strong."""
    weak = generate_deployment(
        fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
        family=CardFamily.UID_ONLY, uses_default_keys=True,
        default_key_fraction=0.9, key_diversified=False, seed=1)
    strong = generate_deployment(
        fmt_name="H10304-37", numbering=NumberingScheme.RANDOM,
        family=CardFamily.MIFARE_CLASSIC, uses_default_keys=False,
        default_key_fraction=0.0, key_diversified=True, seed=1)

    order = ["numbering", "keys", "clonability", "guessability", "format",
             "characterization"]

    def contrib(dep):
        res = audit_deployment(dep)
        by = {f.factor: f.score for f in res.findings}
        return [WEIGHTS[k] * by.get(k, 0) for k in order], res.risk_score

    wv, wr = contrib(weak)
    sv, sr = contrib(strong)

    y = np.arange(len(order))
    h = 0.38
    fig, ax = plt.subplots(figsize=(8.8, 4.8))
    ax.barh(y - h / 2, wv, h, color=C_BF, label=f"Weak deployment (risk {wr})")
    ax.barh(y + h / 2, sv, h, color=C_ML, label=f"Strong deployment (risk {sr})")
    ax.set_yticks(y, [o.capitalize() for o in order])
    ax.invert_yaxis()
    ax.set_xlabel("Weighted contribution to composite risk (points)")
    ax.set_title("What drives the risk score", fontweight="bold")
    ax.legend(frameon=False, loc="lower right")
    _save(fig, "risk_factors")


def fig_fleet() -> None:
    """Multi-facility campus: per-building risk and the weakest-link roll-up."""
    from phantomtap.fleet import audit_fleet

    specs = [
        ("bldg-A (fc42)", dict(facility_code=42, fmt_name="H10301-26",
            numbering=NumberingScheme.SEQUENTIAL, family=CardFamily.UID_ONLY,
            uses_default_keys=True, default_key_fraction=0.9, seed=300)),
        ("bldg-B (fc118)", dict(facility_code=118, fmt_name="H10306-34",
            numbering=NumberingScheme.CLUSTERED, family=CardFamily.MIFARE_CLASSIC,
            uses_default_keys=True, default_key_fraction=0.4, seed=301)),
        ("bldg-C (fc205)", dict(facility_code=205, fmt_name="H10306-34",
            numbering=NumberingScheme.SEQUENTIAL, family=CardFamily.MIFARE_CLASSIC,
            uses_default_keys=True, default_key_fraction=0.2, seed=302)),
        ("bldg-D (fc250)", dict(facility_code=250, fmt_name="H10304-37",
            numbering=NumberingScheme.RANDOM, family=CardFamily.MIFARE_CLASSIC,
            uses_default_keys=False, default_key_fraction=0.0,
            key_diversified=True, seed=303)),
    ]
    deps = [generate_deployment(issued=120, name=n, **kw) for n, kw in specs]
    fleet = audit_fleet(deps, name="campus")
    names = [f.name for f in fleet.facilities]
    risks = [f.result.risk_score for f in fleet.facilities]

    fig, ax = plt.subplots(figsize=(8.6, 4.6))
    colors = [C_BF if r >= 75 else "#f4a582" if r >= 55 else "#92c5de"
              if r >= 35 else C_ML for r in risks]
    y = np.arange(len(names))
    ax.barh(y, risks, color=colors)
    ax.axvline(fleet.fleet_risk, color="#222", lw=2, ls="--",
               label=f"Fleet risk (weakest-link) = {fleet.fleet_risk}")
    ax.set_yticks(y, names, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Composite risk score")
    ax.set_title("Fleet audit: a campus is as weak as its weakest building",
                 fontweight="bold")
    ax.legend(frameon=False, loc="lower right")
    for yi, r in zip(y, risks):
        ax.annotate(str(r), (r, yi), xytext=(4, 0), textcoords="offset points",
                    va="center", fontsize=9, fontweight="bold")
    _save(fig, "fleet")


def fig_attack_path() -> None:
    """Attack-graph: the path of least resistance to the datacenter."""
    from phantomtap.attackgraph import build_campus_graph
    from phantomtap.audit import quick_risk_score

    buildings = {
        "lobby": dict(facility_code=42, fmt_name="H10301-26",
            numbering=NumberingScheme.SEQUENTIAL, family=CardFamily.UID_ONLY,
            uses_default_keys=True, default_key_fraction=0.9, seed=300),
        "garage": dict(facility_code=90, fmt_name="H10301-26",
            numbering=NumberingScheme.SEQUENTIAL, family=CardFamily.MIFARE_CLASSIC,
            uses_default_keys=True, default_key_fraction=0.5, seed=310),
        "east-wing": dict(facility_code=118, fmt_name="H10306-34",
            numbering=NumberingScheme.CLUSTERED, family=CardFamily.MIFARE_CLASSIC,
            uses_default_keys=True, default_key_fraction=0.4, seed=301),
        "west-wing": dict(facility_code=205, fmt_name="H10306-34",
            numbering=NumberingScheme.SEQUENTIAL, family=CardFamily.MIFARE_CLASSIC,
            uses_default_keys=True, default_key_fraction=0.2, seed=302),
        "datacenter": dict(facility_code=250, fmt_name="H10304-37",
            numbering=NumberingScheme.RANDOM, family=CardFamily.MIFARE_CLASSIC,
            uses_default_keys=False, key_diversified=True, seed=303),
    }
    risks = {z: quick_risk_score(generate_deployment(issued=120, **kw))
             for z, kw in buildings.items()}
    g = build_campus_graph(risks)
    path = g.cheapest_path("outside", "datacenter")
    chokes = g.harden_priorities("outside", "datacenter")
    top_choke = chokes[0].door if chokes else None
    pos = g.positions
    path_doors = set(path.doors)

    fig, ax = plt.subplots(figsize=(9.6, 5.0))
    # edges
    for d in g.doors:
        x0, y0 = pos[d.frm]
        x1, y1 = pos[d.to]
        on = d.name in path_doors
        ax.plot([x0, x1], [y0, y1], "-", lw=4 if on else 1.6,
                color=C_BF if on else GRID, zorder=1,
                solid_capstyle="round")
        mx, my = (x0 + x1) / 2, (y0 + y1) / 2
        lbl = f"{d.name}\ncost {d.breach_cost}"
        ax.annotate(lbl, (mx, my), fontsize=7,
                    color=C_BF if on else "#888", ha="center", va="center",
                    fontweight="bold" if on else "normal",
                    bbox=dict(boxstyle="round,pad=0.15", fc="white",
                              ec="none", alpha=0.85))
    # nodes
    for z, (x, y) in pos.items():
        risk = risks.get(z)
        is_target = z == "datacenter"
        is_entry = z == "outside"
        col = (C_ML if is_target else "#333" if is_entry else
               C_BF if (risk or 0) >= 70 else "#f4a582" if (risk or 0) >= 50
               else C_ACCENT)
        ax.scatter([x], [y], s=1400 if (is_target or is_entry) else 1100,
                   c=col, zorder=3, edgecolor="white", linewidth=2,
                   marker="*" if is_target else "o")
        sub = "CROWN JEWEL" if is_target else "ENTRY" if is_entry else f"risk {risk}"
        ax.annotate(f"{z}\n{sub}", (x, y), fontsize=8.5, ha="center", va="center",
                    color="white", fontweight="bold", zorder=4)

    title = (f"Attack path to datacenter — breach cost {path.cost}"
             + (f"; harden '{top_choke}' first" if top_choke else ""))
    ax.set_title(title, fontweight="bold")
    ax.axis("off")
    ax.set_xlim(-0.4, 3.9)
    ax.set_ylim(-0.2, 2.2)
    _save(fig, "attack_path")


def fig_rogue_reader() -> None:
    """Counter-surveillance: rogue readers separate from legit ones in the
    carrier-timing fingerprint space (Specter-inspired)."""
    import random as _r
    from phantomtap.rfsweep import PROFILES, EmitterObservation, classify

    rng = _r.Random(11)
    fig, (axl, axr) = plt.subplots(1, 2, figsize=(11.6, 4.6))

    # Left: sampled emitters in (polling period, jitter) space.
    for p in PROFILES:
        col = C_ML if p.legit else C_BF
        marker = "o" if p.legit else "X"
        xs, ys = [], []
        for _ in range(40):
            noise = 0.10 + p.jitter_ms / 200.0
            xs.append(max(1, p.polling_period_ms * (1 + rng.gauss(0, noise))))
            ys.append(max(0, p.jitter_ms * (1 + rng.gauss(0, 0.25))))
        axl.scatter(xs, ys, s=22, c=col, marker=marker, alpha=0.55,
                    edgecolor="none",
                    label=f"{p.name}{'' if p.legit else '  (ROGUE)'}")
        axl.annotate(p.name, (p.polling_period_ms, p.jitter_ms), fontsize=7.5,
                     ha="center", va="center", fontweight="bold",
                     color="#222",
                     bbox=dict(boxstyle="round,pad=0.15", fc="white", ec=col, alpha=0.9))
    axl.set_xlabel("Carrier polling period (ms)")
    axl.set_ylabel("Timing jitter (ms)")
    axl.set_title("Rogue readers betray themselves by timing jitter",
                  fontweight="bold")
    axl.legend(frameon=False, fontsize=7.2, loc="upper center", ncol=2)

    # Right: a room sweep — emitters by proximity, rogues flagged.
    from phantomtap.rfsweep import synthetic_sweep, sweep as run_sweep
    obs, _ = synthetic_sweep(seed=3)
    res = run_sweep(obs)
    dets = sorted(res.detections, key=lambda d: d.is_rogue)
    y = np.arange(len(dets))
    conf = [d.confidence for d in dets]
    colors = [C_BF if d.is_rogue else C_ML for d in dets]
    axr.barh(y, conf, color=colors)
    labels = [f"{d.location}\n{d.classified_kind} · {d.proximity}" for d in dets]
    axr.set_yticks(y, labels, fontsize=7.5)
    axr.set_xlim(0, 1)
    axr.set_xlabel("Classification confidence")
    axr.set_title(f"Room sweep: {len(res.rogues)} rogue(s) found "
                  f"→ {'DIRTY' if not res.clean else 'CLEAN'}", fontweight="bold")
    for yi, d in zip(y, dets):
        if d.is_rogue:
            axr.annotate("⚠ ROGUE", (d.confidence, yi), xytext=(4, 0),
                         textcoords="offset points", va="center", fontsize=8,
                         color=C_BF, fontweight="bold")
    _save(fig, "rogue_reader")


def main() -> None:
    print("Generating figures ->", FIG)
    fig_attempts_to_characterize()
    fig_inference_vs_n()
    fig_risk_vs_config()
    fig_learning_curve()
    fig_population_estimation()
    fig_guessability()
    fig_purple_team()
    fig_remediation()
    fig_risk_factors()
    fig_fleet()
    fig_attack_path()
    fig_rogue_reader()
    print("done.")


if __name__ == "__main__":
    main()
