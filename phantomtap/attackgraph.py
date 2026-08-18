"""Physical attack-path analysis: the path of least resistance to the crown jewels.

Per-door audits tell you how weak each reader is. But an intruder doesn't attack
a door in isolation -- they chain the *weakest sequence* of doors from the street
to a high-value asset (a datacenter, a records room). PhantomTap models the
estate as a graph:

* **zones** are nodes (outside, lobby, wings, datacenter),
* **doors** are edges, each guarded by a reader whose *breach cost* is derived
  from that reader's audit risk (a weak, high-risk door is cheap to defeat).

The auditor then answers two questions no per-door score can:

1. **Reachability** -- what is the *cheapest* path from ``outside`` to the crown
   jewels, and which doors lie on it? (Dijkstra over breach costs.)
2. **Chokepoints** -- hardening *which single door* raises that cheapest-path
   cost the most? That is where the defensive dollar buys the most protection,
   and it is frequently **not** the estate's weakest door.

This is classic attack-graph / kill-chain reasoning, brought to physical access
control and driven by real audit scores.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


def _breach_cost(risk_score: int) -> int:
    """A weak (high-risk) door is cheap to defeat. Cost in [1, 100]."""
    return max(1, 100 - int(risk_score))


@dataclass
class Door:
    name: str
    frm: str
    to: str
    risk_score: int          # audit composite risk of the reader on this door
    bidirectional: bool = True

    @property
    def breach_cost(self) -> int:
        return _breach_cost(self.risk_score)


@dataclass
class AccessGraph:
    doors: List[Door]
    positions: Dict[str, Tuple[float, float]] = field(default_factory=dict)

    @property
    def zones(self) -> List[str]:
        z = set()
        for d in self.doors:
            z.add(d.frm)
            z.add(d.to)
        return sorted(z)

    def _adj(self, hardened: Optional[Dict[str, int]] = None):
        """Adjacency list; ``hardened`` overrides a door's risk score."""
        hardened = hardened or {}
        adj: Dict[str, List[Tuple[str, int, str]]] = {z: [] for z in self.zones}
        for d in self.doors:
            risk = hardened.get(d.name, d.risk_score)
            cost = _breach_cost(risk)
            adj[d.frm].append((d.to, cost, d.name))
            if d.bidirectional:
                adj[d.to].append((d.frm, cost, d.name))
        return adj

    def cheapest_path(self, start: str, target: str,
                      hardened: Optional[Dict[str, int]] = None) -> "AttackPath":
        """Minimum total breach cost from ``start`` to ``target`` (Dijkstra)."""
        zones = self.zones
        if start not in zones or target not in zones:
            return AttackPath(start, target, [], [], None)
        adj = self._adj(hardened)
        dist = {z: float("inf") for z in zones}
        prev: Dict[str, Tuple[str, str]] = {}
        dist[start] = 0
        pq: List[Tuple[int, str]] = [(0, start)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist[u]:
                continue
            if u == target:
                break
            for v, w, dname in adj[u]:
                nd = d + w
                if nd < dist[v]:
                    dist[v] = nd
                    prev[v] = (u, dname)
                    heapq.heappush(pq, (nd, v))
        if dist[target] == float("inf"):
            return AttackPath(start, target, [], [], None)
        # reconstruct
        zones_path: List[str] = [target]
        doors_path: List[str] = []
        cur = target
        while cur != start:
            u, dname = prev[cur]
            doors_path.append(dname)
            zones_path.append(u)
            cur = u
        zones_path.reverse()
        doors_path.reverse()
        return AttackPath(start, target, zones_path, doors_path, int(dist[target]))

    def harden_priorities(self, start: str, target: str,
                          hardened_risk: int = 15) -> List["Chokepoint"]:
        """Rank doors by how much hardening each raises the cheapest-path cost.

        For every door we recompute the min-cost path assuming that one door is
        brought up to ``hardened_risk`` (i.e. made strong). The increase in the
        attacker's cheapest path is that door's defensive value.
        """
        base = self.cheapest_path(start, target)
        out: List[Chokepoint] = []
        for d in self.doors:
            if d.risk_score <= hardened_risk:
                continue  # already strong
            new = self.cheapest_path(start, target, hardened={d.name: hardened_risk})
            base_cost = base.cost or 0
            new_cost = new.cost or base_cost
            out.append(Chokepoint(d.name, d.risk_score, new_cost - base_cost,
                                  d.name in (base.doors or [])))
        out.sort(key=lambda c: (c.cost_increase, c.on_cheapest_path), reverse=True)
        return out


@dataclass
class AttackPath:
    start: str
    target: str
    zones: List[str]
    doors: List[str]
    cost: Optional[int]

    @property
    def reachable(self) -> bool:
        return self.cost is not None

    def as_dict(self) -> dict:
        return {"start": self.start, "target": self.target, "zones": self.zones,
                "doors": self.doors, "cost": self.cost, "reachable": self.reachable}


@dataclass
class Chokepoint:
    door: str
    risk_score: int
    cost_increase: int       # how much hardening this door raises the min path
    on_cheapest_path: bool

    def as_dict(self) -> dict:
        return {"door": self.door, "risk_score": self.risk_score,
                "cost_increase": self.cost_increase,
                "on_cheapest_path": self.on_cheapest_path}


def render_markdown(graph: AccessGraph, start: str, target: str) -> str:
    path = graph.cheapest_path(start, target)
    chokes = graph.harden_priorities(start, target)
    lines: List[str] = []
    lines.append(f"# PhantomTap Attack-Path Analysis")
    lines.append("")
    if not path.reachable:
        lines.append(f"`{target}` is **not reachable** from `{start}` — good.")
        return "\n".join(lines)
    lines.append(f"**Crown jewel:** `{target}` · **Entry:** `{start}`  ")
    lines.append(f"**Path of least resistance (breach cost {path.cost}):** "
                 + " → ".join(f"`{z}`" for z in path.zones))
    lines.append(f"**Doors on that path:** "
                 + ", ".join(f"`{d}`" for d in path.doors))
    lines.append("")
    lines.append("## Harden-first chokepoints")
    lines.append("")
    lines.append("Hardening *one* door raises the intruder's cheapest path by:")
    lines.append("")
    lines.append("| Door | Door risk | +Path cost if hardened | On current path |")
    lines.append("|------|----------:|-----------------------:|:---------------:|")
    for c in chokes[:6]:
        lines.append(f"| `{c.door}` | {c.risk_score} | +{c.cost_increase} | "
                     f"{'✓' if c.on_cheapest_path else '—'} |")
    lines.append("")
    if chokes and chokes[0].cost_increase > 0:
        lines.append(f"**Harden `{chokes[0].door}` first** — it buys the biggest "
                     f"increase (+{chokes[0].cost_increase}) in the cost of "
                     f"reaching `{target}`, which is often *not* the estate's "
                     f"weakest door in isolation.")
    return "\n".join(lines)


def build_campus_graph(risk_by_building: Dict[str, int]) -> AccessGraph:
    """A small realistic campus topology, doors weighted by building audit risk.

    ``risk_by_building`` maps a zone name to its reader's audit risk score.
    """
    r = risk_by_building
    doors = [
        Door("front-door", "outside", "lobby", r.get("lobby", 70)),
        Door("garage-gate", "outside", "garage", r.get("garage", 60)),
        Door("lobby-east", "lobby", "east-wing", r.get("east-wing", 55)),
        Door("lobby-west", "lobby", "west-wing", r.get("west-wing", 55)),
        Door("garage-west", "garage", "west-wing", r.get("west-wing", 55)),
        Door("east-core", "east-wing", "datacenter", r.get("datacenter", 25)),
        Door("west-core", "west-wing", "datacenter", r.get("datacenter", 25)),
    ]
    positions = {
        "outside": (0.0, 1.0), "lobby": (1.0, 1.6), "garage": (1.0, 0.2),
        "east-wing": (2.2, 1.8), "west-wing": (2.2, 0.6),
        "datacenter": (3.4, 1.2),
    }
    return AccessGraph(doors, positions)
