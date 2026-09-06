"""Unified assessment: run the whole pipeline into one professional report.

Every other module answers one question. Real assessors want the *whole* picture
in a single deliverable. :func:`full_assessment` runs inference-driven audit,
efficiency characterization, information-theoretic leakage, the prioritized
remediation roadmap, and the organizational-timeline leak, then renders them as a
self-contained, styled **HTML report** (no external assets, no JavaScript) or as
Markdown — the artifact a physical-security engagement actually hands over.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import List, Optional

from .audit import AuditResult, audit_deployment
from .entropy import Guessability, assess_guessability
from .population import Deployment, NumberingScheme
from .remediation import Fix, prioritized_plan
from .timeline import LeakResult, date_leakage, synthesize_org

_BAND_COLOR = {
    "CRITICAL": "#b2182b", "HIGH": "#e08214", "MEDIUM": "#d6a800",
    "LOW": "#1b7837", "MINIMAL": "#2166ac",
}
_SEV_COLOR = {
    "critical": "#b2182b", "high": "#e08214", "medium": "#d6a800",
    "low": "#1b7837", "info": "#888",
}


@dataclass
class Assessment:
    dep: Deployment
    result: AuditResult
    guess: Guessability
    plan: List[Fix]
    leak: LeakResult

    def as_dict(self) -> dict:
        return {
            "deployment": self.dep.name,
            "risk_score": self.result.risk_score,
            "risk_band": self.result.risk_band,
            "findings": [f.as_dict() for f in self.result.findings],
            "metrics": self.result.metrics,
            "guessability": self.guess.as_dict(),
            "remediation": [f.as_dict() for f in self.plan],
            "timeline_leak": self.leak.as_dict(),
        }


def full_assessment(dep: Deployment, n_observations: int = 8) -> Assessment:
    result = audit_deployment(dep, n_observations=n_observations)
    guess = assess_guessability(dep)
    plan = prioritized_plan(dep)
    org = synthesize_org(n=len(dep.credentials), seed=dep.seed,
                         randomized=dep.numbering == NumberingScheme.RANDOM)
    leak = date_leakage(org, n_known=2)
    return Assessment(dep, result, guess, plan, leak)


# ---------------------------------------------------------------------------
# HTML rendering (self-contained, inline CSS, no JS)
# ---------------------------------------------------------------------------
def _e(s) -> str:
    return html.escape(str(s))


def render_html(a: Assessment) -> str:
    r = a.result
    band_color = _BAND_COLOR.get(r.risk_band, "#333")
    dep = a.dep.summary()
    m = r.metrics
    pct = max(2, min(100, r.risk_score))

    rows = "".join(
        f'<tr><td><span class="dot" style="background:{_SEV_COLOR.get(f.severity,"#888")}"></span>'
        f'{_e(f.severity.upper())}</td><td><code>{_e(f.factor)}</code></td>'
        f'<td><b>{_e(f.title)}</b><br><span class="muted">{_e(f.detail)}</span>'
        f'<br><span class="fix">Fix: {_e(f.remediation)}</span></td></tr>'
        for f in r.findings)

    plan_rows = "".join(
        f'<tr><td>{i}</td><td>{_e(f.action)}</td><td>{f.new_risk}</td>'
        f'<td class="drop">&minus;{f.delta}</td></tr>'
        for i, f in enumerate(a.plan, 1))
    final_risk = a.plan[-1].new_risk if a.plan else r.risk_score

    leak_html = ""
    if not a.leak.randomized:
        leak_html = (
            f'<p>Because badges are issued in hire order, <b>two known badge '
            f'dates</b> date every other badge to <b>&plusmn;{a.leak.mae_days:.0f} '
            f'days</b> (fit R&sup2; {a.leak.r2:.2f}) &mdash; leaking headcount, '
            f'tenure and hiring spikes. Randomise numbering to close this.</p>')
    else:
        leak_html = ('<p>Randomised numbering breaks the card&rarr;date '
                     'correlation &mdash; no organizational timeline leaks. '
                     '<b>Good.</b></p>')

    bf = m.get("bruteforce_queries")
    ml = m.get("ml_queries")
    eff = (f"~{bf / max(ml, 1):,.0f}&times; fewer reader interactions than brute "
           f"force" if bf and ml else "n/a")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhantomTap Assessment — {_e(a.dep.name)}</title>
<style>
:root{{color-scheme:light}}
body{{font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
 color:#1a1a1a;background:#f6f7f9;margin:0;padding:0}}
.wrap{{max-width:860px;margin:0 auto;padding:32px 22px 60px}}
h1{{font-size:26px;margin:0 0 4px}} h2{{font-size:18px;margin:34px 0 10px;
 border-bottom:2px solid #e6e8eb;padding-bottom:6px}}
.sub{{color:#666;margin:0 0 18px}}
.gauge{{background:#e6e8eb;border-radius:10px;height:26px;overflow:hidden;margin:6px 0}}
.gauge > span{{display:block;height:100%;width:{pct}%;background:{band_color}}}
.score{{font-size:40px;font-weight:800;color:{band_color}}}
.band{{display:inline-block;padding:3px 12px;border-radius:20px;color:#fff;
 background:{band_color};font-weight:700;font-size:13px;letter-spacing:.5px}}
table{{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;
 overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06);margin:8px 0}}
th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #eef0f2;vertical-align:top}}
th{{background:#fafbfc;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:#555}}
.muted{{color:#666;font-size:13px}} .fix{{color:#1b7837;font-size:13px}}
.dot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}}
.drop{{color:#1b7837;font-weight:700}}
code{{background:#eef0f2;padding:1px 5px;border-radius:4px;font-size:13px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0}}
.card{{flex:1;min-width:150px;background:#fff;border-radius:8px;padding:12px 14px;
 box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.card b{{font-size:22px;display:block}} .card span{{color:#666;font-size:12px}}
.note{{background:#fff7e6;border:1px solid #ffe0a3;border-radius:8px;padding:12px 14px;
 font-size:13px;color:#7a5b00;margin-top:30px}}
footer{{color:#888;font-size:12px;margin-top:24px}}
</style></head><body><div class="wrap">
<h1>PhantomTap Access-Control Assessment</h1>
<p class="sub">Deployment <code>{_e(a.dep.name)}</code> &middot; {_e(dep['format'])}
 &middot; facility {_e(dep['facility_code'])} &middot; {_e(dep['numbering'])}
 &middot; {_e(dep['issued'])} credentials</p>

<div class="score">{r.risk_score}<span style="font-size:20px;color:#999">/100</span>
 &nbsp;<span class="band">{_e(r.risk_band)}</span></div>
<div class="gauge"><span></span></div>

<div class="cards">
 <div class="card"><b>{a.guess.informed_guess_bits:.1f}</b>
   <span>bits of guessing (structure-aware)</span></div>
 <div class="card"><b>{a.guess.leaked_bits:.1f}</b><span>bits leaked to structure</span></div>
 <div class="card"><b>{eff.split('&')[0].strip()}&times;</b>
   <span>fewer queries than brute force</span></div>
 <div class="card"><b>&minus;{r.risk_score - final_risk}</b>
   <span>risk removable via roadmap</span></div>
</div>

<h2>Findings ({len(r.findings)})</h2>
<table><tr><th>Severity</th><th>Factor</th><th>Finding &amp; remediation</th></tr>
{rows}</table>

<h2>Efficiency evidence</h2>
<p>Guided characterization mapped 90% of the population in
 <b>{_e(f"{ml:,}" if ml else "n/a")}</b> reader queries vs
 <b>{_e(f"{bf:,}" if bf else "n/a")}</b> for brute force ({eff}).</p>

<h2>Information-theoretic leakage</h2>
<p>A blind adversary faces ~{a.guess.naive_guess_bits:.1f} bits to forge a
 credential; a structure-aware one faces only ~{a.guess.informed_guess_bits:.1f}
 &mdash; the deployment <b>leaks ~{a.guess.leaked_bits:.1f} bits</b>.</p>

<h2>Organizational-timeline exposure</h2>
{leak_html}

<h2>Prioritized remediation roadmap</h2>
<table><tr><th>#</th><th>Fix</th><th>Risk after</th><th>&Delta;</th></tr>
{plan_rows}</table>
<p>Applying the full roadmap projects a residual risk of <b>{final_risk}/100</b>.</p>

<div class="note"><b>Authorized, defensive use only.</b> This assessment was
 produced against a synthetic or author-owned system. Testing any system you do
 not own requires prior written authorization.</div>
<footer>Generated by PhantomTap &middot; ML-guided RFID/NFC access-control auditing.</footer>
</div></body></html>"""
