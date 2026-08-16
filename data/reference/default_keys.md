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

The authoritative in-code list lives in [`phantomtap/keys.py`](../../phantomtap/keys.py),
and a committed 41-key slice of the real public dictionary (with provenance
header) is at [`mifare_default_keys.dic`](mifare_default_keys.dic) —
`phantomtap.keys.load_full_dictionary()` reads it at runtime.

## Why this is a finding, not an exploit

MIFARE Classic's Crypto-1 cipher is itself academically broken, so a sector left
on a default key offers no protection at all. Reporting "N of 16 sectors still
use factory keys" tells a building owner exactly what to fix. The remediation is
always the same: rotate off default keys, diversify keys per card, and migrate
off Crypto-1 to AES-authenticated credentials.

## Sources (public references)

- RfidResearchGroup/proxmark3 — `client/dictionaries/mfc_default_keys.dic`
  (the canonical community dictionary; our committed slice is its head).
  <https://github.com/RfidResearchGroup/proxmark3/blob/master/client/dictionaries/mfc_default_keys.dic>
- iceman `default_keys.dic` (mirror used to extract the committed slice).
  <https://raw.githubusercontent.com/zhovner/proxmark3-1/master/client/default_keys.dic>
- Flipper Zero `mf_classic_dict.nfc` (ships the same community key set).
- libnfc `mfoc` / `mfcuk` default-key dictionaries.
- MIFARE Classic / Crypto-1 cryptanalysis: Nohl, Evans, Starbug & Plötz,
  *Reverse-Engineering a Cryptographic RFID Tag* (USENIX Security 2008);
  Garcia et al., *Dismantling MIFARE Classic* (ESORICS 2008).

These are published, factual key lists included solely so PhantomTap can
*detect* deployments still running on them. No site-specific or non-public key
material is stored in this repository.
