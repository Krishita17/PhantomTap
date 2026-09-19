# Reader-to-controller wire protocols (public reference)

PhantomTap audits the credential *and* the link that carries it from the reader
to the door controller. That link is a distinct, often-overlooked attack
surface. This file grounds the `phantomtap.wireprotocol` scoring in public
standards and documented real-world attacks. No proprietary data is included.

## The protocols

| Protocol | Encrypted | Authenticated | Supervised | Replay-resistant | Notes |
|----------|:---------:|:-------------:|:----------:|:----------------:|-------|
| **Wiegand (D0/D1)** | ✗ | ✗ | ✗ | ✗ | Legacy 2-wire cleartext. The dominant installed base. |
| **RS-485 (cleartext)** | ✗ | ✗ | ✓ | ✗ | Bus is polled (cut detectable), payload still cleartext. |
| **OSDP v1 (unencrypted)** | ✗ | ✗ | ✓ | ✗ | OSDP framing without Secure Channel enabled. |
| **OSDP Secure Channel** | ✓ | ✓ | ✓ | ✓ | AES-128, mutual auth, supervised. The target state. |

## Why Wiegand is the weak point

The Wiegand interface transmits the raw credential over two data lines (D0/D1)
in the clear, with no encryption, no reader/controller authentication, and no
line supervision. This means an attacker with brief physical access to the
reader wiring can install an inline implant that **logs every badge presented
and replays any of them on demand** — defeating even a cryptographically strong
smart card, because the attack happens *downstream* of the credential.

This is not theoretical: the open-source **ESPKey** implant (and similar
devices) does exactly this against Wiegand readers.

## The documented fix

**OSDP Secure Channel** — the SIA Open Supervised Device Protocol, standardised
as **IEC 60839-11-5** — replaces the cleartext link with an AES-128 encrypted,
mutually authenticated, continuously supervised RS-485 channel. A wiretap sees
ciphertext; a cut or spliced line raises an alarm; session cryptography makes
each transaction non-replayable.

## Sources (public references)

- SIA, *OSDP (Open Supervised Device Protocol)* and OSDP Secure Channel;
  standardised as IEC 60839-11-5.
  <https://www.securityindustry.org/industry-standards/open-supervised-device-protocol/>
- ESPKey Wiegand wiretap/replay implant (open hardware), and the associated
  physical-access-control research (Bishop Fox / Lares) motivating migration off
  Wiegand.
- Wiegand interface overview (unauthenticated, cleartext D0/D1 signalling).
  <https://en.wikipedia.org/wiki/Wiegand_interface>

> Included solely so PhantomTap can *recommend* hardening the link (migrate
> Wiegand → OSDP Secure Channel). No attack tooling ships in this repository.
