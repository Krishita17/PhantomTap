"""Tests for physical attack-path analysis."""

from phantomtap.attackgraph import Door, AccessGraph, build_campus_graph


def _graph():
    # datacenter reader strong (low risk); lobby prox weak (high risk)
    return build_campus_graph({
        "lobby": 75, "garage": 60, "east-wing": 56,
        "west-wing": 62, "datacenter": 22,
    })


def test_cheapest_path_reaches_target():
    g = _graph()
    p = g.cheapest_path("outside", "datacenter")
    assert p.reachable
    assert p.zones[0] == "outside" and p.zones[-1] == "datacenter"
    assert p.cost > 0


def test_weakest_route_is_chosen():
    # A path through a very weak door must cost less than an all-strong route.
    weak = AccessGraph([
        Door("d1", "outside", "hall", risk_score=90),   # very weak
        Door("d2", "hall", "vault", risk_score=90),
        Door("d3", "outside", "vault", risk_score=10),   # single strong door
    ])
    via_hall = weak.cheapest_path("outside", "vault")
    assert via_hall.cost == (100 - 90) + (100 - 90)      # 20, cheaper than 90
    assert "hall" in via_hall.zones


def test_harden_priorities_flags_a_useful_chokepoint():
    g = _graph()
    chokes = g.harden_priorities("outside", "datacenter")
    assert chokes
    # the best chokepoint must actually increase the attacker's path cost
    assert chokes[0].cost_increase > 0
    # and it should lie on the current cheapest path
    assert chokes[0].on_cheapest_path


def test_unreachable_target():
    g = AccessGraph([Door("d", "outside", "lobby", 50)])
    p = g.cheapest_path("outside", "datacenter")
    assert not p.reachable and p.cost is None
