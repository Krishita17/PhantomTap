"""A simulated access-control reader.

The reader holds the set of valid issued credentials and answers a single
question: *does this credential open the door?*  Every query is counted, which
is what lets us measure "attempts-to-characterize" -- the core efficiency
metric that separates ML-guided search from blind brute force.

This is the safe stand-in for a real reader.  The real hardware path
(:mod:`phantomtap.bridge`) exposes the same ``query`` interface so the rest of
the pipeline is identical whether it is driving a simulation or a Flipper Zero
against the auditor's own reader.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Set

from .population import Deployment


@dataclass
class SimulatedReader:
    """Accept/reject oracle over a deployment's issued credentials."""

    valid: Set[int]
    queries: int = 0
    accepts: int = 0

    @classmethod
    def from_deployment(cls, dep: Deployment) -> "SimulatedReader":
        return cls(valid=set(dep.valid_raws))

    def query(self, raw: int) -> bool:
        """Present one credential; returns True if the reader would unlock."""
        self.queries += 1
        ok = raw in self.valid
        if ok:
            self.accepts += 1
        return ok

    def reset_counters(self) -> None:
        self.queries = 0
        self.accepts = 0

    @property
    def total_issued(self) -> int:
        return len(self.valid)


class ReaderProtocol:
    """Structural interface shared by simulated and hardware readers."""

    def query(self, raw: int) -> bool:  # pragma: no cover - interface
        raise NotImplementedError
