"""Publicly documented default keys for common card families.

These MIFARE Classic keys are the *well-known, widely published* factory /
transport / application defaults that appear throughout the RFID-security
literature and in open tooling. The list below is the leading slice of the
canonical community dictionary shipped with the Proxmark3 (iceman fork) and
mirrored across libnfc (`mfoc`/`mfcuk`) and the Flipper Zero
`mf_classic_dict.nfc`.

Provenance (real, public sources):
  * RfidResearchGroup/proxmark3 — client/dictionaries/mfc_default_keys.dic
    https://github.com/RfidResearchGroup/proxmark3/blob/master/client/dictionaries/mfc_default_keys.dic
  * iceman default_keys.dic (mirror):
    https://raw.githubusercontent.com/zhovner/proxmark3-1/master/client/default_keys.dic
  * The full local copy lives in data/reference/mifare_default_keys.dic.

They are included so the auditor can *detect* that a deployment is still running
on publicly-known keys -- a serious finding -- not to attack anything. No
site-specific or non-public key material lives in this repository.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

# The leading, most-common entries of the canonical public dictionary
# (deduplicated, upper-cased). This mirrors the head of the Proxmark3/iceman
# `default_keys.dic` file bundled in data/reference/.
DEFAULT_KEYS: List[str] = [
    "FFFFFFFFFFFF",  # factory / transport blank key
    "000000000000",  # all-zero blank
    "A0A1A2A3A4A5",  # MIFARE Application Directory (MAD) key A / NFC Forum
    "B0B1B2B3B4B5",  # common transport key
    "C0C1C2C3C4C5",
    "D0D1D2D3D4D5",
    "AABBCCDDEEFF",  # common demo/test key
    "4D3A99C351DD",
    "1A982C7E459A",
    "D3F7D3F7D3F7",  # NDEF / NFC Forum default
    "5A1B85FCE20A",
    "714C5C886E97",
    "587EE5F9350F",
    "A0478CC39091",
    "533CB6C723F6",
    "8FD0A4F256E9",
    "000000000001",
    "000000000002",
    "00000000000A",
    "00000000000B",
    "00000FFE2488",
    "010203040506",
    "0123456789AB",
    "0297927C0F77",
    "100000000000",
    "111111111111",
    "123456789ABC",
    "12F2EE3478C1",
    "14D446E33363",
    "1999A3554A55",
    "222222222222",
    "26940B21FF5D",
    "27DD91F1FCF1",
    "2BA9621E0A36",
    "333333333333",
    "33F974B42769",
    "34D1DF9934C5",
    "434F4D4D4F41",
    "434F4D4D4F42",
    "A5A4A3A2A1A0",  # MAD key A, reversed
    "89ECA97F8C2A",  # MAD key B
]

DEFAULT_KEY_SET = set(k.upper() for k in DEFAULT_KEYS)

_DIC_PATH = Path(__file__).resolve().parent.parent / "data" / "reference" / \
    "mifare_default_keys.dic"


def load_full_dictionary() -> List[str]:
    """Load the full committed public dictionary (data/reference), if present.

    Falls back to the built-in :data:`DEFAULT_KEYS` when the file is missing.
    Lines starting with ``#`` are treated as comments.
    """
    if not _DIC_PATH.exists():
        return list(DEFAULT_KEYS)
    keys: List[str] = []
    for line in _DIC_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) == 12 and all(c in "0123456789abcdefABCDEF" for c in line):
            keys.append(line.upper())
    return keys or list(DEFAULT_KEYS)


def is_default_key(key_hex: str) -> bool:
    return key_hex.upper() in DEFAULT_KEY_SET
