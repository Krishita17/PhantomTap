"""Tests for the evaluation-metrics core and subsystem evaluators."""

import math

from phantomtap.evaluation import (
    average_precision,
    balanced_accuracy,
    confusion_matrix,
    eval_rogue_reader,
    evaluate_all,
    mcc,
    precision_recall_f1,
    roc_auc,
    spearman,
)


def test_precision_recall_f1_on_known_case():
    #        pred: 1 1 0 0 1
    y_true = [1, 0, 0, 1, 1]
    y_pred = [1, 1, 0, 0, 1]
    prec, rec, f1 = precision_recall_f1(y_true, y_pred)
    # tp=2 fp=1 fn=1 -> P=2/3, R=2/3, F1=2/3
    assert abs(prec - 2 / 3) < 1e-9
    assert abs(rec - 2 / 3) < 1e-9
    assert abs(f1 - 2 / 3) < 1e-9


def test_roc_auc_perfect_and_chance():
    # perfectly separable -> AUC 1.0
    yt = [0, 0, 1, 1]
    sc = [0.1, 0.2, 0.8, 0.9]
    assert roc_auc(yt, sc) == 1.0
    # inverted -> AUC 0.0
    assert roc_auc(yt, [0.9, 0.8, 0.2, 0.1]) == 0.0
    # tie in the middle -> 0.5
    assert abs(roc_auc([0, 1], [0.5, 0.5]) - 0.5) < 1e-9


def test_average_precision_perfect():
    yt = [0, 0, 1, 1]
    sc = [0.1, 0.2, 0.8, 0.9]
    assert abs(average_precision(yt, sc) - 1.0) < 1e-9


def test_mcc_perfect():
    assert abs(mcc([1, 0, 1, 0], [1, 0, 1, 0]) - 1.0) < 1e-9


def test_spearman_monotonic():
    assert abs(spearman([1, 2, 3, 4], [10, 20, 30, 40]) - 1.0) < 1e-9
    assert abs(spearman([1, 2, 3, 4], [40, 30, 20, 10]) + 1.0) < 1e-9


def test_confusion_matrix_counts():
    m = confusion_matrix(["a", "a", "b"], ["a", "b", "b"], ["a", "b"])
    assert m == [[1, 1], [0, 1]]


def test_rogue_reader_detection_is_strong():
    r = eval_rogue_reader(trials=40, seed=1)
    assert r["f1"] > 0.9
    assert r["roc_auc"] > 0.9


def test_evaluate_all_sections_present():
    rep = evaluate_all(seed=0)
    for key in ("format_inference", "rogue_reader_detection", "anomaly_monitor",
                "bayesian_sizing", "risk_ranking"):
        assert key in rep.sections
    # monitor should catch every injected attack type and stay quiet on clean traffic
    mon = rep.sections["anomaly_monitor"]
    assert mon["mean_recall"] == 1.0
    assert mon["clean_stream_false_alarm_rate"] < 0.1
