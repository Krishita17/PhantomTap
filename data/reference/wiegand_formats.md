# Wiegand credential-format reference (public specifications)

This is a compact, public-knowledge reference for the Wiegand formats PhantomTap
models. These layouts are widely documented in access-control literature and
vendor integration guides; none of the information below is proprietary or
site-specific. It grounds the format-inference parser and the risk taxonomy.

## Frame model

Every format is a fixed-width bit frame. **Bit positions and parity ranges below
follow the Proxmark3 reference implementation** (`client/src/wiegand_formats.c`,
RfidResearchGroup/proxmark3), so PhantomTap's encoder is *bit-compatible* with
what a Proxmark3 or Flipper Zero emits for these formats. Frame bits are numbered
MSB-first (bit 0 is the first bit on the wire).

Exact layouts (offset:width, and parity ranges):

| Format | Layout (MSB-first) |
|--------|--------------------|
| H10301-26 | `card@1:16; facility@17:8` · P0=odd[1..13), P25=even[13..25) |
| H10306-34 | `facility@1:16; card@17:16` · P0=even[1..17), P33=odd[17..33) |
| N10002-34 | identical to H10306-34 (structural alias) |
| H10304-37 | `facility@1:16; card@17:19` · P0=even[1..19), P36=odd[18..36) |
| H10302-37 | `card@1:35` (no facility) · P0=even[1..19), P36=odd[19..36) |

Parity lets a reader reject bit-errors and lets an auditor tell one format from
another — as long as the high-order bits are actually exercised (see the
width-ambiguity note). Note H10306-34 and N10002-34 are *structurally identical*,
so a 34-bit read is legitimately consistent with both.

## Format taxonomy

| Format | Total bits | Facility bits | Card bits | Facility range | Card range | Known weaknesses |
|--------|-----------:|--------------:|----------:|---------------:|-----------:|------------------|
| **H10301-26** | 26 | 8  | 16 | 0–255      | 0–65,535   | Tiny facility space; facility-code collisions and guessing are trivial. Ubiquitous legacy format. |
| **H10306-34** | 34 | 16 | 16 | 0–65,535   | 0–65,535   | 16-bit facility + 16-bit card. Structural alias of N10002-34. |
| **N10002-34** | 34 | 16 | 16 | 0–65,535   | 0–65,535   | Wider facility code, but 16-bit card space keeps per-facility populations small and enumerable. |
| **H10304-37** | 37 | 16 | 19 | 0–65,535   | 0–524,287  | Larger card space resists pure enumeration, but sequential numbering remains fully predictable. |
| **H10302-37** | 37 | 0  | 35 | — (none)   | 0–34,359,738,367 | **No facility code** — a single 35-bit card number. With no facility field to divide the space by, such formats are markedly *more* enumerable; the auditor's facility-locking advantage disappears, leaving only numbering structure to exploit. |

All five formats above are **Proxmark3-compatible** (bit-exact field + parity
layout).

### Documented but not yet bit-exact

The **HID Corporate 1000** family carries a 3-bit *interleaved* parity scheme
(35-bit: 12-bit company + 20-bit card; 48-bit: 22-bit company + ~23-bit card)
whose exact masks are more intricate than the ranges above. PhantomTap documents
these in the taxonomy; wiring their exact Proxmark parity into the registry is
tracked for Tier-2 hardware validation.

The **EM4100** 125 kHz prox credential (8-bit customer/version + 32-bit unique
ID, with a Manchester row/column parity matrix rather than a Wiegand frame) is
the most common real low-frequency prox. PhantomTap treats it as a **UID-only,
authentication-free** family (trivially clonable) — see the card-family taxonomy
in the README.

## Width-ambiguity note

When a wider format carries small values (e.g. a 37-bit credential whose card
number fits in 16 bits), its unused high-order bits are zero and its parity is
*indistinguishable* from a narrower format's. PhantomTap therefore reports the
**narrowest parity-consistent format** and explicitly lists the wider formats it
is also consistent with. Exact width is only recoverable once the high-order
bits are used.

## Sources (public references)

- **Proxmark3 `client/src/wiegand_formats.c`** (RfidResearchGroup/proxmark3) —
  the authoritative open Pack/Unpack definitions this registry's field offsets
  and parity ranges are aligned to.
  <https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/wiegand_formats.c>
- HID Global, *Understanding Card Data Formats* (white paper), HID Corporation.
  <https://www.idesco.com/files/articles/HID%20-%20Understanding%20card%20formats.pdf>
- Security ID Systems, *The Complete Wiegand Format Guide* — H10301, H10302,
  H10304 and Corporate 1000 field layouts.
  <https://securityidsystems.com/guides/wiegand-format-guide/>
- Authoriz-ID, *Navigating the World of HID 37-bit Card Formats — H10304 and
  H10302* (16-bit FC + 19-bit card vs. facility-less 35-bit card).
  <https://authoriz-id.com/blogs/news/navigating-the-world-of-hid-37-bit-card-formats-h10304-and-h10302>
- Kisi, *How to Calculate Facility Code Using Card Bit Calculators* (26-bit
  parity and field boundaries). <https://www.getkisi.com/blog/how-to-calculate-facility-code-using-card-bit-calculators>

Field widths and ranges in the table above are drawn from these public
specifications. The single leading/trailing bracket-parity model reproduces the
documented H10301 scheme and is applied as a standard approximation to the wider
formats; exact HID parity maps are validated against hardware in Tier-2.
