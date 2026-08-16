# Default-key reference (public MIFARE Classic keys)

PhantomTap detects deployments still running on **factory / transport default
keys** — a serious, common finding. The keys below are the well-known, widely
published defaults that appear throughout the RFID-security literature and in
open tooling (libnfc `mfoc`/`mfcuk` dictionaries, the Proxmark3 default
dictionary, and the Flipper Zero `mf_classic_dict.nfc`). They are included so
the auditor can *recognise* them, not to attack anything.

**No site-specific or non-public key material is stored in this repository.**

| Key (hex) | Notes |
|-----------|-------|
| `FFFFFFFFFFFF` | Blank / factory transport key |
| `A0A1A2A3A4A5` | MIFARE Application Directory (MAD) default |
| `D3F7D3F7D3F7` | NDEF / NFC Forum default |
| `000000000000` | All-zero |
| `B0B1B2B3B4B5` | Common transport key |
| `AABBCCDDEEFF` | Common demo/test key |
| `4D3A99C351DD`, `1A982C7E459A`, `714C5C886E97`, `587EE5F9350F`, `A0478CC39091`, `533CB6C723F6`, `8FD0A4F256E9` | Documented sector defaults seen in public key dictionaries |

The authoritative in-code list lives in [`phantomtap/keys.py`](../../phantomtap/keys.py).

## Why this is a finding, not an exploit

MIFARE Classic's Crypto-1 cipher is itself academically broken, so a sector left
on a default key offers no protection at all. Reporting "N of 16 sectors still
use factory keys" tells a building owner exactly what to fix. The remediation is
always the same: rotate off default keys, diversify keys per card, and migrate
off Crypto-1 to AES-authenticated credentials.

## Sources to cite in a writeup

- libnfc `mfoc` / `mfcuk` default key dictionaries.
- Proxmark3 `mfc_default_keys` dictionary.
- Flipper Zero `mf_classic_dict.nfc`.
- MIFARE Classic / Crypto-1 cryptanalysis literature (Nohl et al.; Garcia et al.).

> Replace with fully-qualified citations and license notes before submission.
