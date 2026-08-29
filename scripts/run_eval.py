"""Run the full evaluation suite -> docs/evaluation.{md,json}.

Reports precision/recall/F1, ROC-AUC/PR-AUC, MCC, confusion matrices and
ranking quality for every PhantomTap classifier and detector.

Run::

    python -m scripts.run_eval
"""

from __future__ import annotations

import json
from pathlib import Path

from phantomtap.evaluation import evaluate_all, render_markdown

OUT = Path(__file__).resolve().parents[1] / "docs"


def _strip(section: dict) -> dict:
    """Drop bulky ROC arrays; keep confusion matrices under a clean key."""
    out = {}
    for k, v in section.items():
        if k == "_curve":
            continue
        if k == "_confusion":
            out["confusion"] = v
        else:
            out[k] = v
    return out


def main() -> None:
    rep = evaluate_all(seed=0)
    md = render_markdown(rep)
    (OUT / "evaluation.md").write_text(md)
    summary = {name: _strip(sec) for name, sec in rep.sections.items()}
    (OUT / "evaluation.json").write_text(json.dumps(summary, indent=2))
    print(md)
    print(f"\nwrote {OUT/'evaluation.md'} and .json")


if __name__ == "__main__":
    main()
