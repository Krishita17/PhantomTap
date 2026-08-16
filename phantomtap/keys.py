"""Publicly documented default keys for common card families.

These MIFARE Classic keys are the *well-known, widely published* factory /
transport defaults that appear throughout the RFID-security literature and in
open tools (e.g. libnfc's ``mfoc``/``mfcuk`` key dictionaries, the Proxmark3
default dictionary, and the Flipper Zero ``mf_classic_dict.nfc``).  They are
included here purely so the auditor can *detect* that a deployment is still
running on factory keys -- a serious finding -- not to attack anything.

No site-specific or non-public key material lives in this repository.
"""

from __future__ import annotations

from typing import List

# The canonical short-list of MIFARE Classic default keys (hex, 6 bytes / 48b).
DEFAULT_KEYS: List[str] = [
    "FFFFFFFFFFFF",  # blank / factory transport key
    "A0A1A2A3A4A5",  # MAD (MIFARE Application Directory) default
    "D3F7D3F7D3F7",  # NDEF / NFC Forum default
    "000000000000",  # all-zero
    "B0B1B2B3B4B5",
    "4D3A99C351DD",
    "1A982C7E459A",
    "AABBCCDDEEFF",
    "714C5C886E97",
    "587EE5F9350F",
    "A0478CC39091",
    "533CB6C723F6",
    "8FD0A4F256E9",
]

DEFAULT_KEY_SET = set(k.upper() for k in DEFAULT_KEYS)


def is_default_key(key_hex: str) -> bool:
    return key_hex.upper() in DEFAULT_KEY_SET
