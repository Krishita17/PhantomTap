"""Evaluation metrics for every classifier and detector in PhantomTap.

A security tool is only as trustworthy as its measured accuracy. This module
provides a standard, dependency-free metrics core (precision / recall / F1,
ROC-AUC, PR-AUC, Matthews correlation, balanced accuracy, confusion matrices,
Spearman rank correlation) and *evaluators* that run each PhantomTap subsystem
over many seeded trials and report how well it actually performs:

* **format inference** — top-1 accuracy, parity-consistent-set recall, numbering
  accuracy, and a format confusion matrix;
* **rogue-reader detection** — precision/recall/F1 + ROC-AUC/PR-AUC of the
  skimmer flag, plus a per-emitter-type confusion matrix;
* **anomaly monitor** — per-attack-type recall and the clean-stream false-alarm
  rate;
* **Bayesian sizing** — population-count MAPE and the "resistance" recall on
  randomised numbering;
* **risk scoring** — how well the composite separates known-weak from
  known-strong deployments (AUC) and orders them (Spearman rho).

Everything is computed live on synthetic populations with fixed seeds, so the
numbers are reproducible.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Metrics core (pure stdlib)
# ---------------------------------------------------------------------------
def confusion_binary(y_true: Sequence[int], y_pred: Sequence[int]):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    return tp, fp, fn, tn


def precision_recall_f1(y_true, y_pred):
    tp, fp, fn, tn = confusion_binary(y_true, y_pred)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


def accuracy(y_true, y_pred):
    return sum(1 for t, p in zip(y_true, y_pred) if t == p) / max(len(y_true), 1)


def specificity(y_true, y_pred):
    tp, fp, fn, tn = confusion_binary(y_true, y_pred)
    return tn / (tn + fp) if (tn + fp) else 0.0


def balanced_accuracy(y_true, y_pred):
    _, rec, _ = precision_recall_f1(y_true, y_pred)
    return 0.5 * (rec + specificity(y_true, y_pred))


def mcc(y_true, y_pred):
    """Matthews correlation coefficient — robust on imbalanced classes."""
    tp, fp, fn, tn = confusion_binary(y_true, y_pred)
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    if denom == 0:
        return 0.0
    return (tp * tn - fp * fn) / denom


def _ranks(values: Sequence[float]) -> List[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # 1-based average rank
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def roc_auc(y_true: Sequence[int], scores: Sequence[float]) -> float:
    """AUC via the Mann-Whitney U statistic (handles ties)."""
    pos = [s for t, s in zip(y_true, scores) if t]
    neg = [s for t, s in zip(y_true, scores) if not t]
    if not pos or not neg:
        return float("nan")
    ranks = _ranks(list(scores))
    rank_pos = sum(r for r, t in zip(ranks, y_true) if t)
    n_pos, n_neg = len(pos), len(neg)
    u = rank_pos - n_pos * (n_pos + 1) / 2.0
    return u / (n_pos * n_neg)


def roc_curve(y_true, scores) -> List[Tuple[float, float]]:
    pairs = sorted(zip(scores, y_true), key=lambda x: -x[0])
    P = sum(1 for t in y_true if t)
    N = len(y_true) - P
    if P == 0 or N == 0:
        return [(0.0, 0.0), (1.0, 1.0)]
    tp = fp = 0
    pts = [(0.0, 0.0)]
    for _, t in pairs:
        if t:
            tp += 1
        else:
            fp += 1
        pts.append((fp / N, tp / P))
    return pts


def average_precision(y_true, scores) -> float:
    pairs = sorted(zip(scores, y_true), key=lambda x: -x[0])
    P = sum(1 for t in y_true if t)
    if P == 0:
        return float("nan")
    tp = fp = 0
    ap = 0.0
    prev_recall = 0.0
    for _, t in pairs:
        if t:
            tp += 1
        else:
            fp += 1
        recall = tp / P
        precision = tp / (tp + fp)
        ap += precision * (recall - prev_recall)
        prev_recall = recall
    return ap


def spearman(a: Sequence[float], b: Sequence[float]) -> float:
    ra, rb = _ranks(a), _ranks(b)
    n = len(a)
    if n < 2:
        return 0.0
    ma = sum(ra) / n
    mb = sum(rb) / n
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = math.sqrt(sum((x - ma) ** 2 for x in ra))
    vb = math.sqrt(sum((y - mb) ** 2 for y in rb))
    return cov / (va * vb) if va and vb else 0.0


def confusion_matrix(y_true, y_pred, labels: List[str]) -> List[List[int]]:
    idx = {l: i for i, l in enumerate(labels)}
    m = [[0] * len(labels) for _ in labels]
    for t, p in zip(y_true, y_pred):
        if t in idx and p in idx:
            m[idx[t]][idx[p]] += 1
    return m


# ---------------------------------------------------------------------------
# Subsystem evaluators
# ---------------------------------------------------------------------------
@dataclass
class EvalReport:
    sections: Dict[str, dict] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return self.sections


def eval_rogue_reader(trials: int = 120, seed: int = 0) -> dict:
    import random
    from .rfsweep import PROFILES, classify, legit_distance, sample_emitter

    rng = random.Random(seed)
    kinds = [p.kind for p in PROFILES]
    y_true, y_pred, scores = [], [], []
    tk, pk = [], []
    for _ in range(trials):
        for p in PROFILES:
            obs = sample_emitter(p.kind, rng=rng)
            det = classify(obs)
            y_true.append(0 if p.legit else 1)
            y_pred.append(1 if det.is_rogue else 0)
            scores.append(legit_distance(obs))
            tk.append(p.kind)
            pk.append(det.classified_kind)
    prec, rec, f1 = precision_recall_f1(y_true, y_pred)
    cm_labels = kinds + ["unknown"]
    return {
        "n": len(y_true),
        "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
        "accuracy": round(accuracy(y_true, y_pred), 3),
        "balanced_accuracy": round(balanced_accuracy(y_true, y_pred), 3),
        "mcc": round(mcc(y_true, y_pred), 3),
        "roc_auc": round(roc_auc(y_true, scores), 3),
        "pr_auc": round(average_precision(y_true, scores), 3),
        "_curve": {"y_true": y_true, "scores": scores},
        "_confusion": {"labels": cm_labels,
                       "matrix": confusion_matrix(tk, pk, cm_labels)},
    }


def eval_monitor(trials: int = 60, seed: int = 0) -> dict:
    from .monitor import analyze, synthetic_stream
    from .population import NumberingScheme, generate_deployment

    per_type = {}
    total = {}
    for s in range(trials):
        dep = generate_deployment(numbering=NumberingScheme.SEQUENTIAL,
                                  issued=400, seed=s)
        events, injected = synthetic_stream(dep, seed=s)
        kinds = {a.kind for a in analyze(events, dep=dep)}
        for it in injected:
            total[it] = total.get(it, 0) + 1
            if it in kinds:
                per_type[it] = per_type.get(it, 0) + 1
    recall_by_type = {k: round(per_type.get(k, 0) / total[k], 3) for k in total}

    # false-alarm rate on clean streams (no injected attacks)
    fp_streams = 0
    for s in range(trials):
        dep = generate_deployment(numbering=NumberingScheme.RANDOM, issued=400,
                                  seed=1000 + s)
        events, _ = synthetic_stream(dep, seed=1000 + s, inject=False)
        alerts = analyze(events, dep=dep)
        # off-hours on legitimately-random business traffic is expected-benign;
        # count clone/enumeration/rogue as the security-relevant false alarms
        hard = [a for a in alerts if a.kind in
                ("impossible_travel", "enumeration", "rogue_credential")]
        if hard:
            fp_streams += 1
    return {
        "trials": trials,
        "recall_by_attack": recall_by_type,
        "mean_recall": round(sum(recall_by_type.values()) / len(recall_by_type), 3),
        "clean_stream_false_alarm_rate": round(fp_streams / trials, 3),
    }


def eval_inference(trials: int = 200, seed: int = 0) -> dict:
    from .inference import infer_format
    from .population import NumberingScheme, generate_deployment

    fmts = ["H10301-26", "H10306-34", "H10304-37", "H10302-37"]
    schemes = [NumberingScheme.SEQUENTIAL, NumberingScheme.CLUSTERED,
               NumberingScheme.RANDOM]
    top1 = consistent = num_ok = 0
    tf, pf = [], []
    for t in range(trials):
        fmtname = fmts[t % len(fmts)]
        scheme = schemes[t % len(schemes)]
        dep = generate_deployment(fmt_name=fmtname, numbering=scheme,
                                  issued=400, seed=seed + t)
        obs = [c.raw for c in dep.observed_sample(8)]
        hyp = infer_format(obs)
        pred = hyp.fmt.name if hyp.fmt else "none"
        top1 += 1 if pred == fmtname else 0
        consistent += 1 if fmtname in hyp.consistent_formats else 0
        num_ok += 1 if _num_class(hyp.numbering) == _num_class(scheme) else 0
        tf.append(fmtname)
        pf.append(pred)
    return {
        "trials": trials,
        "format_top1_accuracy": round(top1 / trials, 3),
        "format_consistent_recall": round(consistent / trials, 3),
        "numbering_class_accuracy": round(num_ok / trials, 3),
        "_confusion": {"labels": fmts,
                       "matrix": confusion_matrix(tf, pf, fmts)},
    }


def _num_class(scheme) -> str:
    from .population import NumberingScheme
    if scheme in (NumberingScheme.SEQUENTIAL, NumberingScheme.SEQUENTIAL_GAPS):
        return "sequential-like"
    return scheme.value


def eval_bayes(trials: int = 40, seed: int = 0) -> dict:
    from .bayes import estimate_population
    from .population import NumberingScheme, generate_deployment
    from .reader import SimulatedReader

    seq_errs = []
    resist_hits = 0
    for s in range(trials):
        dep = generate_deployment(numbering=NumberingScheme.SEQUENTIAL,
                                  issued=500, seed=seed + s)
        reader = SimulatedReader.from_deployment(dep)
        cn = dep.observed_sample(8)[0].card_number
        est = estimate_population(reader, dep.fmt, dep.facility_code, cn)
        seq_errs.append(abs(est.count_est - len(dep.credentials)) / len(dep.credentials))

        depr = generate_deployment(numbering=NumberingScheme.RANDOM, issued=500,
                                   seed=seed + s)
        rr = SimulatedReader.from_deployment(depr)
        cnr = depr.observed_sample(8)[0].card_number
        er = estimate_population(rr, depr.fmt, depr.facility_code, cnr)
        # "resistance" = randomised numbering should defeat sizing (large error)
        if abs(er.count_est - len(depr.credentials)) / len(depr.credentials) > 0.3:
            resist_hits += 1
    return {
        "trials": trials,
        "sequential_sizing_mape": round(sum(seq_errs) / len(seq_errs), 3),
        "randomized_resistance_recall": round(resist_hits / trials, 3),
    }


def eval_risk_ranking(seed: int = 0) -> dict:
    from .audit import quick_risk_score
    from .population import CardFamily, NumberingScheme, generate_deployment

    weak_kw = dict(fmt_name="H10301-26", numbering=NumberingScheme.SEQUENTIAL,
                   family=CardFamily.UID_ONLY, uses_default_keys=True,
                   default_key_fraction=0.9, key_diversified=False)
    strong_kw = dict(fmt_name="H10304-37", numbering=NumberingScheme.RANDOM,
                     family=CardFamily.MIFARE_CLASSIC, uses_default_keys=False,
                     default_key_fraction=0.0, key_diversified=True)
    labels, scores = [], []
    for s in range(20):
        labels.append(1)  # weak == positive
        scores.append(quick_risk_score(generate_deployment(issued=300, seed=s, **weak_kw)))
        labels.append(0)
        scores.append(quick_risk_score(generate_deployment(issued=300, seed=s, **strong_kw)))
    return {
        "auc_weak_vs_strong": round(roc_auc(labels, scores), 3),
        "spearman_rho": round(spearman(labels, scores), 3),
        "n": len(labels),
    }


def evaluate_all(seed: int = 0) -> EvalReport:
    rep = EvalReport()
    rep.sections["format_inference"] = eval_inference(seed=seed)
    rep.sections["rogue_reader_detection"] = eval_rogue_reader(seed=seed)
    rep.sections["anomaly_monitor"] = eval_monitor(seed=seed)
    rep.sections["bayesian_sizing"] = eval_bayes(seed=seed)
    rep.sections["risk_ranking"] = eval_risk_ranking(seed=seed)
    return rep


def render_markdown(rep: EvalReport) -> str:
    s = rep.sections
    L: List[str] = ["# PhantomTap Evaluation Metrics", "",
                    "All metrics computed live on seeded synthetic populations.",
                    ""]

    r = s["rogue_reader_detection"]
    L += ["## Rogue-reader / skimmer detection", "",
          "| Metric | Value |", "|--------|------:|",
          f"| Precision | {r['precision']} |",
          f"| Recall | {r['recall']} |",
          f"| F1 | {r['f1']} |",
          f"| Balanced accuracy | {r['balanced_accuracy']} |",
          f"| MCC | {r['mcc']} |",
          f"| ROC-AUC | {r['roc_auc']} |",
          f"| PR-AUC | {r['pr_auc']} |", ""]

    m = s["anomaly_monitor"]
    L += ["## Anomaly monitor (blue-team)", "",
          f"Mean per-attack recall **{m['mean_recall']}**; clean-stream false-alarm "
          f"rate **{m['clean_stream_false_alarm_rate']}**.", "",
          "| Attack type | Recall |", "|-------------|-------:|"]
    for k, v in m["recall_by_attack"].items():
        L.append(f"| {k} | {v} |")
    L.append("")

    i = s["format_inference"]
    L += ["## Format inference", "",
          f"Top-1 accuracy **{i['format_top1_accuracy']}**, parity-consistent-set "
          f"recall **{i['format_consistent_recall']}**, numbering-class accuracy "
          f"**{i['numbering_class_accuracy']}**.", ""]

    b = s["bayesian_sizing"]
    L += ["## Bayesian population sizing", "",
          f"Sequential-numbering sizing MAPE **{b['sequential_sizing_mape']}**; "
          f"randomized-numbering resistance recall "
          f"**{b['randomized_resistance_recall']}** (correctly defeated).", ""]

    k = s["risk_ranking"]
    L += ["## Risk-score validity", "",
          f"The composite separates known-weak from known-strong deployments with "
          f"**AUC {k['auc_weak_vs_strong']}** (Spearman rho "
          f"{k['spearman_rho']}).", "",
          "---", "*Generated by `phantomtap.evaluation`.*"]
    return "\n".join(L)
