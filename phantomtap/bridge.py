"""Tier-2 hardware bridge: driving a real Flipper Zero as the RF front-end.

The Flipper Zero exposes a scriptable CLI over its USB serial port.  This
module wraps that CLI so the *same* pipeline that runs against the simulated
reader can run against genuine RF reads of the auditor's **own** cards and
readers.

Design notes
------------
* ``pyserial`` is an *optional* dependency.  Import is deferred so the whole
  Tier-1 software pipeline works with zero hardware and zero extra packages.
* :class:`MockFlipperBridge` mirrors the real interface for tests and demos.
* This module never ships facility-specific keys or a "clone a stranger's
  badge" routine.  It reads UIDs/blocks and emulates credentials you are
  authorised to test, exactly as the manual Flipper UI already does -- just
  scripted.

Responsible use: only connect this to readers and cards you own or are
explicitly contracted to assess.  See ``docs/threat_model.md``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional, Protocol


@dataclass
class CardRead:
    """A single card read returned by the Flipper."""

    uid: str                    # hex UID, e.g. "04A1B2C3"
    raw: Optional[int] = None   # decoded Wiegand frame value, if available
    card_type: str = "unknown"  # e.g. "EM4100", "MIFARE Classic 1K"
    blocks: Optional[list] = None


class FlipperInterface(Protocol):
    def read_card(self, timeout: float = 5.0) -> Optional[CardRead]: ...
    def emulate(self, raw: int, seconds: float = 3.0) -> None: ...
    def close(self) -> None: ...


class FlipperBridge:
    """Real serial bridge to a Flipper Zero CLI.

    Usage::

        with FlipperBridge("/dev/tty.usbmodemflip_XXXX") as flip:
            read = flip.read_card()
    """

    def __init__(self, port: str, baud: int = 115200, timeout: float = 2.0):
        try:
            import serial  # noqa: F401  (optional dependency: pyserial)
        except ImportError as exc:  # pragma: no cover - hardware path
            raise ImportError(
                "FlipperBridge needs pyserial. Install the hardware extra:\n"
                "    pip install 'phantomtap[hardware]'\n"
                "Tier-1 (simulation) needs none of this."
            ) from exc
        import serial

        self.port = port
        self._ser = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.2)
        self._drain()

    # -- low-level CLI plumbing -----------------------------------------
    def _drain(self) -> None:
        try:
            self._ser.reset_input_buffer()
        except Exception:  # pragma: no cover
            pass

    def _cmd(self, line: str, settle: float = 0.3) -> str:
        self._ser.write((line + "\r\n").encode())
        time.sleep(settle)
        out = self._ser.read_all() or b""
        return out.decode(errors="replace")

    # -- high-level operations ------------------------------------------
    def read_card(self, timeout: float = 5.0) -> Optional[CardRead]:  # pragma: no cover
        """Trigger an RFID/NFC read and parse the CLI response.

        The exact parsing depends on Flipper firmware version; this is the
        integration seam validated on the author's own hardware in Tier 2.
        """
        resp = self._cmd("rfid read", settle=timeout)
        return _parse_read(resp)

    def emulate(self, raw: int, seconds: float = 3.0) -> None:  # pragma: no cover
        self._cmd(f"rfid emulate {raw:X}", settle=seconds)

    def close(self) -> None:
        try:
            self._ser.close()
        except Exception:  # pragma: no cover
            pass

    def __enter__(self) -> "FlipperBridge":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class MockFlipperBridge:
    """Hardware-free stand-in used by tests, demos, and CI.

    Replays a scripted list of :class:`CardRead` objects, so the Tier-2 code
    path can be exercised without a physical Flipper attached.
    """

    def __init__(self, scripted_reads: List[CardRead]):
        self._reads = list(scripted_reads)
        self._i = 0
        self.emulated: List[int] = []

    def read_card(self, timeout: float = 5.0) -> Optional[CardRead]:
        if self._i >= len(self._reads):
            return None
        r = self._reads[self._i]
        self._i += 1
        return r

    def emulate(self, raw: int, seconds: float = 3.0) -> None:
        self.emulated.append(raw)

    def close(self) -> None:
        pass

    def __enter__(self) -> "MockFlipperBridge":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _parse_read(resp: str) -> Optional[CardRead]:  # pragma: no cover - firmware-specific
    """Best-effort parse of a Flipper ``rfid read`` response.

    Kept intentionally small; the real parser is firmware-version specific and
    validated against the author's own device during Tier-2 integration.
    """
    uid = None
    card_type = "unknown"
    for line in resp.splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith("uid") and ":" in line:
            uid = line.split(":", 1)[1].strip().replace(" ", "")
        elif any(t in line for t in ("EM4100", "HIDProx", "MIFARE", "Indala")):
            card_type = line
    if uid is None:
        return None
    return CardRead(uid=uid, card_type=card_type)
