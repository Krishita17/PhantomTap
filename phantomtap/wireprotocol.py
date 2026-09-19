"""Reader-to-controller wire-protocol posture (the layer behind the reader).

Every other module reasons about the *credential*. But the link between the
reader and the door controller is its own attack surface -- and often the
weakest. The legacy **Wiegand** interface sends the credential over two data
wires (D0/D1) in the clear, with no encryption, no authentication, and no line
supervision. A real, off-the-shelf implant (**ESPKey**, and similar) splices
onto those wires behind a reader, logs every badge presented, and **replays**
any of them on demand -- defeating even a perfect smart credential, because the
attack is downstream of the card.

The documented fix is **OSDP Secure Channel** (SIA Open Supervised Device
Protocol, standardised as IEC 60839-11-5): an AES-128 encrypted, mutually
authenticated, continuously *supervised* RS-485 link, so a wiretap sees
ciphertext and a cut line raises an alarm.

This module scores that link. It is deliberately standalone -- the wire posture
is a property of the *installation*, not the credential -- so it composes with a
credential audit without changing it.

References (public): SIA OSDP / IEC 60839-11-5; the ESPKey Wiegand wiretap
research (Bishop Fox / Lares) motivating the migration off Wiegand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class WireProtocol:
    name: str
    label: str
    encrypted: bool
    authenticated: bool
    supervised: bool         # line monitoring: a cut/splice is detectable
    replay_resistant: bool
    description: str = ""


PROTOCOLS: Dict[str, WireProtocol] = {
    "wiegand": WireProtocol(
        "wiegand", "Wiegand (D0/D1)", encrypted=False, authenticated=False,
        supervised=False, replay_resistant=False,
        description="Legacy 2-wire cleartext link. No encryption, no auth, no "
        "supervision — an ESPKey-style implant on the wires logs and replays "
        "every credential."),
    "rs485_clear": WireProtocol(
        "rs485_clear", "RS-485 (cleartext)", encrypted=False, authenticated=False,
        supervised=True, replay_resistant=False,
        description="Polled RS-485 bus (a cut line is noticed) but the payload is "
        "still cleartext and replayable."),
    "osdp_v1": WireProtocol(
        "osdp_v1", "OSDP v1 (unencrypted)", encrypted=False, authenticated=False,
        supervised=True, replay_resistant=False,
        description="OSDP framing with supervision, but Secure Channel not "
        "enabled — traffic is readable and replayable on the bus."),
    "osdp_sc": WireProtocol(
        "osdp_sc", "OSDP Secure Channel", encrypted=True, authenticated=True,
        supervised=True, replay_resistant=True,
        description="AES-128 encrypted, mutually authenticated, supervised "
        "RS-485. A wiretap sees ciphertext; a cut line alarms. The target state."),
}

# Weight of each missing property toward link risk (sum = 100).
_WEIGHTS = {"encrypted": 35, "authenticated": 25, "replay_resistant": 25,
            "supervised": 15}


@dataclass
class LinkFinding:
    severity: str
    title: str
    detail: str
    remediation: str

    def as_dict(self) -> dict:
        return {"severity": self.severity, "title": self.title,
                "detail": self.detail, "remediation": self.remediation}


@dataclass
class LinkAssessment:
    protocol: str
    label: str
    link_risk: int
    band: str
    findings: List[LinkFinding] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"protocol": self.protocol, "label": self.label,
                "link_risk": self.link_risk, "band": self.band,
                "findings": [f.as_dict() for f in self.findings]}


def _band(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "MINIMAL"


def assess_link(protocol_name: str) -> LinkAssessment:
    if protocol_name not in PROTOCOLS:
        raise KeyError(f"unknown protocol {protocol_name!r}; "
                       f"known: {sorted(PROTOCOLS)}")
    p = PROTOCOLS[protocol_name]
    risk = 0
    findings: List[LinkFinding] = []

    if not p.encrypted:
        risk += _WEIGHTS["encrypted"]
        findings.append(LinkFinding(
            "critical", "Link traffic is unencrypted",
            "Credential data crosses the reader-to-controller link in the clear; "
            "a wiretap (e.g. an ESPKey implant on Wiegand D0/D1) captures every "
            "badge presented.",
            "Enable OSDP Secure Channel (AES-128) end-to-end."))
    if not p.authenticated:
        risk += _WEIGHTS["authenticated"]
        findings.append(LinkFinding(
            "high", "Reader/controller are not mutually authenticated",
            "The controller cannot verify the reader (or an implant impersonating "
            "one), so injected frames are trusted.",
            "Use OSDP Secure Channel mutual authentication with per-device keys."))
    if not p.replay_resistant:
        risk += _WEIGHTS["replay_resistant"]
        findings.append(LinkFinding(
            "critical", "Captured credentials can be replayed",
            "With no rolling/session cryptography, a recorded badge frame opens "
            "the door when replayed — defeating even a strong smart credential.",
            "Secure Channel session keys make each transaction non-replayable."))
    if not p.supervised:
        risk += _WEIGHTS["supervised"]
        findings.append(LinkFinding(
            "medium", "Link is not supervised",
            "Cutting or splicing the wires raises no alarm, so a tap can be "
            "installed undetected.",
            "Move to a polled, supervised bus (OSDP/RS-485) with tamper alerts."))

    if not findings:
        findings.append(LinkFinding(
            "info", "Link posture is strong",
            "Encrypted, authenticated, supervised and replay-resistant — the "
            "reader-to-controller link is not the weak point.", "Maintain keys "
            "and firmware; verify Secure Channel is actually enforced, not just "
            "available."))

    risk = min(100, risk)
    return LinkAssessment(p.name, p.label, risk, _band(risk), findings)


def compare_protocols() -> List[LinkAssessment]:
    order = ["wiegand", "rs485_clear", "osdp_v1", "osdp_sc"]
    return [assess_link(n) for n in order]


def render_markdown(protocol_name: str) -> str:
    a = assess_link(protocol_name)
    p = PROTOCOLS[protocol_name]
    L = ["# PhantomTap Wire-Protocol (Reader→Controller) Assessment", "",
         f"**Link:** {a.label} · **Link risk:** **{a.link_risk}/100** → "
         f"**{a.band}**  ", "", f"> {p.description}", "", "## Findings", ""]
    for f in a.findings:
        L.append(f"- **[{f.severity.upper()}] {f.title}** — {f.detail}  "
                 f"*Fix: {f.remediation}*")
    L += ["", "## Protocol comparison", "",
          "| Protocol | Encrypted | Auth | Supervised | Replay-resistant | Risk |",
          "|----------|:---------:|:----:|:----------:|:----------------:|-----:|"]
    for c in compare_protocols():
        pr = PROTOCOLS[c.protocol]
        y = lambda b: "✓" if b else "—"
        L.append(f"| {c.label} | {y(pr.encrypted)} | {y(pr.authenticated)} | "
                 f"{y(pr.supervised)} | {y(pr.replay_resistant)} | {c.link_risk} |")
    L += ["", "**Bottom line:** migrating Wiegand → OSDP Secure Channel is the "
          "single highest-leverage fix for the wire layer, and it protects even "
          "deployments whose *credentials* are already strong."]
    return "\n".join(L)
