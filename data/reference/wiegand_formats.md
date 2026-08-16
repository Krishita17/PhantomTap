# Wiegand credential-format reference (public specifications)

This is a compact, public-knowledge reference for the Wiegand formats PhantomTap
models. These layouts are widely documented in access-control literature and
vendor integration guides; none of the information below is proprietary or
site-specific. It grounds the format-inference parser and the risk taxonomy.

## Frame model

Every format here is a fixed-width bit frame of the classic HID shape:

```
[ leading parity ][ facility code | card number ][ trailing parity ]
```

* **Leading parity** is *even* over the high half of the data payload.
* **Trailing parity** is *odd* over the low half of the data payload.

Parity lets a reader reject bit-errors and lets an auditor tell one format from
another — as long as the high-order bits are actually exercised (see the
width-ambiguity note).

## Format taxonomy

| Format | Total bits | Facility bits | Card bits | Facility range | Card range | Known weaknesses |
|--------|-----------:|--------------:|----------:|---------------:|-----------:|------------------|
| **H10301-26** | 26 | 8  | 16 | 0–255      | 0–65,535   | Tiny facility space; facility-code collisions and guessing are trivial. Ubiquitous legacy format. |
| **N10002-34** | 34 | 16 | 16 | 0–65,535   | 0–65,535   | Wider facility code, but 16-bit card space keeps per-facility populations small and enumerable. |
| **H10304-37** | 37 | 16 | 19 | 0–65,535   | 0–524,287  | Larger card space resists pure enumeration, but sequential numbering remains fully predictable. |

## Width-ambiguity note

When a wider format carries small values (e.g. a 37-bit credential whose card
number fits in 16 bits), its unused high-order bits are zero and its parity is
*indistinguishable* from a narrower format's. PhantomTap therefore reports the
**narrowest parity-consistent format** and explicitly lists the wider formats it
is also consistent with. Exact width is only recoverable once the high-order
bits are used.

## Sources to cite in a writeup

- HID Global Wiegand format documentation and integration guides (H10301,
  H10304, corporate 1000 families).
- Public access-control security surveys covering Wiegand weaknesses and
  facility-code enumeration.
- The Wiegand interface protocol description (26-bit / 34-bit / 37-bit layouts).

> Replace the bullet list above with fully-qualified citations (title, author,
> year, URL, license) before submission.
