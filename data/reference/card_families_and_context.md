# Card families & real-world security context (public references)

PhantomTap's risk model is grounded in the documented, public security history
of the credential technologies it audits. This file collects the card-family
taxonomy and the primary literature behind each weakness the tool scores. None of
it is site-specific.

## Card-family taxonomy

| Family | Band | Structure | Authentication | Clonability | PhantomTap class |
|--------|------|-----------|----------------|-------------|------------------|
| **EM4100 / EM4102** | 125 kHz LF | 40-bit: 8-bit customer/version + 32-bit ID, Manchester + row/col parity | **None** (read-only ID) | Trivial — copy to a blank in seconds | `UID_ONLY` |
| **HID Prox (H10301, etc.)** | 125 kHz LF | Wiegand frame over the air | **None** (static, replayable) | Trivial — read + replay | `UID_ONLY` / Wiegand format |
| **MIFARE Classic 1K/4K** | 13.56 MHz HF | 16/40 sectors, per-sector A/B keys, Crypto-1 cipher | Symmetric (Crypto-1, **broken**) | Feasible — weak/default keys or Crypto-1 attacks | `MIFARE_CLASSIC` |
| **MIFARE DESFire EV2/EV3** | 13.56 MHz HF | AES/3DES application keys, mutual auth | Strong (AES) | Impractical when configured correctly | (hardened target) |

The EM4100 and HID Prox families carry **no secret at all** — access is granted
on a static identifier that any reader can capture and any writable tag can
replay. That is why PhantomTap scores UID-only credentials as CRITICAL for
clonability regardless of numbering.

## Why the weaknesses are real (primary sources)

- **Crypto-1 is broken.** Nohl, Evans, Starbug & Plötz, *Reverse-Engineering a
  Cryptographic RFID Tag*, USENIX Security 2008 — recovered the MIFARE Classic
  cipher from silicon.
- **MIFARE Classic is fully defeated.** Garcia et al., *Dismantling MIFARE
  Classic*, ESORICS 2008; and Garcia, van Rossum, Verdult & Schreur,
  *Wirelessly Pickpocketing a MIFARE Classic Card*, IEEE S&P 2009 — practical
  key recovery, including card-only attacks.
- **Default keys are pervasive.** The community MIFARE key dictionaries shipped
  with Proxmark3, libnfc (`mfoc`/`mfcuk`), and Flipper Zero exist precisely
  because so many deployments never rotate factory keys. See
  [`default_keys.md`](default_keys.md).
- **Wiegand itself is unauthenticated.** The reader-to-controller Wiegand
  interface transmits the credential in the clear with no cryptographic
  protection; static formats are inherently replayable. See
  [`wiegand_formats.md`](wiegand_formats.md).

## The documented remediation direction

- **OSDP (Open Supervised Device Protocol)** — SIA's Secure Channel replacement
  for Wiegand, standardized as IEC 60839-11-5, adds encryption and supervision
  on the reader-to-controller link.
- **AES-authenticated credentials** (DESFire EV2/EV3, HID Seos, iCLASS SE)
  replace static identifiers and broken Crypto-1 with mutual authentication.
- **Diversified keys** (unique per-card key derived from a master + UID) contain
  the blast radius of any single recovered card.

These are exactly the fixes PhantomTap's remediation planner
(`phantomtap.remediation`) proposes, ranked by projected risk reduction.

> All references above are public, peer-reviewed or standards-body material,
> included to justify the tool's scoring — not to enable any attack.
