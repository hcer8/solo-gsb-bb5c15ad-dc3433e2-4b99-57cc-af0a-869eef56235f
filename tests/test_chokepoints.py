"""End-to-end tests for POST /audit/dependency-chokepoints."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _chokepoints(**payload):
    response = client.post("/audit/dependency-chokepoints", json=payload)
    return response.status_code, response.json()


def _edge(source, source_version, target, target_version):
    return {
        "source": source,
        "source_version": source_version,
        "target": target,
        "target_version": target_version,
    }


DIAMOND_RESOLVED = {"app": "1.0", "left": "1.0", "right": "1.0", "shared": "1.5"}
DIAMOND_GRAPH = [
    _edge("<root>", "", "app", "1.0"),
    _edge("app", "1.0", "left", "1.0"),
    _edge("app", "1.0", "right", "1.0"),
    _edge("left", "1.0", "shared", "1.5"),
    _edge("right", "1.0", "shared", "1.5"),
]


def _by_package(body):
    return {entry["package"]: entry for entry in body["chokepoints"]}


# ---------------------------------------------------------------------------
# Core dominator semantics
# ---------------------------------------------------------------------------


def test_diamond_has_single_chokepoint():
    status, body = _chokepoints(
        resolved=DIAMOND_RESOLVED, dependency_graph=DIAMOND_GRAPH
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["summary"] == {
        "packages": 4,
        "reachable": 4,
        "unreachable": 0,
        "chokepoints": 1,
    }
    # The diamond re-converges at shared, so left/right can be bypassed and
    # the only unavoidable dependency of everything below app is app itself.
    (entry,) = body["chokepoints"]
    assert entry["package"] == "app"
    assert entry["version"] == "1.0"
    assert entry["dominated"] == ["left", "right", "shared"]
    assert entry["dominated_count"] == 3
    assert body["unreachable"] == []


def test_chain_domination_is_transitive():
    resolved = {"a": "1.0", "b": "2.0", "c": "3.0"}
    graph = [
        _edge("<root>", "", "a", "1.0"),
        _edge("a", "1.0", "b", "2.0"),
        _edge("b", "2.0", "c", "3.0"),
    ]
    status, body = _chokepoints(resolved=resolved, dependency_graph=graph)
    assert status == 200
    entries = _by_package(body)
    assert entries["a"]["dominated"] == ["b", "c"]
    assert entries["a"]["dominated_count"] == 2
    assert entries["b"]["dominated"] == ["c"]
    assert entries["b"]["version"] == "2.0"
    assert "c" not in entries
    # Chokepoints are sorted by package name.
    assert [e["package"] for e in body["chokepoints"]] == ["a", "b"]


def test_cycle_entry_dominates_cycle_members():
    resolved = {"a": "1.0", "b": "1.0", "c": "1.0"}
    graph = [
        _edge("<root>", "", "c", "1.0"),
        _edge("c", "1.0", "a", "1.0"),
        _edge("a", "1.0", "b", "1.0"),
        _edge("b", "1.0", "a", "1.0"),  # cycle a <-> b
    ]
    status, body = _chokepoints(resolved=resolved, dependency_graph=graph)
    assert status == 200
    entries = _by_package(body)
    # c is the only way into the cycle: it dominates both members.
    assert entries["c"]["dominated"] == ["a", "b"]
    # Every path to b passes a, but a and b do not dominate each other.
    assert entries["a"]["dominated"] == ["b"]
    assert "b" not in entries


def test_self_loop_does_not_create_chokepoint():
    resolved = {"a": "1.0", "b": "1.0"}
    graph = [
        _edge("<root>", "", "b", "1.0"),
        _edge("b", "1.0", "a", "1.0"),
        _edge("a", "1.0", "a", "1.0"),  # self loop
    ]
    status, body = _chokepoints(resolved=resolved, dependency_graph=graph)
    assert status == 200
    entries = _by_package(body)
    assert entries["b"]["dominated"] == ["a"]
    assert "a" not in entries


def test_direct_root_dependencies_have_no_chokepoint():
    resolved = {"a": "1.0", "b": "1.0"}
    graph = [
        _edge("<root>", "", "a", "1.0"),
        _edge("<root>", "", "b", "1.0"),
    ]
    status, body = _chokepoints(resolved=resolved, dependency_graph=graph)
    assert status == 200
    assert body["chokepoints"] == []
    assert body["summary"] == {
        "packages": 2,
        "reachable": 2,
        "unreachable": 0,
        "chokepoints": 0,
    }


def test_multiple_entry_edges_narrow_dominators():
    # shared is reachable both via app and directly from <root>, so app does
    # not dominate it.
    resolved = {"app": "1.0", "shared": "1.5"}
    graph = [
        _edge("<root>", "", "app", "1.0"),
        _edge("<root>", "", "shared", "1.5"),
        _edge("app", "1.0", "shared", "1.5"),
    ]
    status, body = _chokepoints(resolved=resolved, dependency_graph=graph)
    assert status == 200
    assert body["chokepoints"] == []


# ---------------------------------------------------------------------------
# Unreachable packages
# ---------------------------------------------------------------------------


def test_unreachable_packages_are_listed_separately():
    resolved = {"app": "1.0", "ghost": "2.0", "lib": "1.0"}
    graph = [
        _edge("<root>", "", "app", "1.0"),
        # lib's only predecessor is itself unreachable.
        _edge("ghost", "2.0", "lib", "1.0"),
    ]
    status, body = _chokepoints(resolved=resolved, dependency_graph=graph)
    assert status == 200
    assert body["unreachable"] == ["ghost", "lib"]
    assert body["summary"] == {
        "packages": 3,
        "reachable": 1,
        "unreachable": 2,
        "chokepoints": 0,
    }
    # Unreachable packages never appear as chokepoints or dominated entries.
    assert body["chokepoints"] == []


def test_no_root_edges_makes_everything_unreachable():
    resolved = {"a": "1.0", "b": "1.0"}
    graph = [_edge("a", "1.0", "b", "1.0")]
    status, body = _chokepoints(resolved=resolved, dependency_graph=graph)
    assert status == 200
    assert body["unreachable"] == ["a", "b"]
    assert body["chokepoints"] == []


def test_empty_resolution():
    status, body = _chokepoints(resolved={}, dependency_graph=[])
    assert status == 200
    assert body == {
        "status": "ok",
        "summary": {"packages": 0, "reachable": 0, "unreachable": 0, "chokepoints": 0},
        "chokepoints": [],
        "unreachable": [],
    }


# ---------------------------------------------------------------------------
# Roundtrip, normalization, determinism
# ---------------------------------------------------------------------------


def test_roundtrip_from_resolve_response():
    resolve_body = client.post(
        "/resolve",
        json={
            "packages": {
                "app": {"1.0": {"dependencies": {"web": ">=2.0", "db": ""}}},
                "web": {
                    "2.0": {"dependencies": {"common": "<2.0"}},
                    "3.0": {"dependencies": {"common": ">=2.0"}},
                },
                "db": {"1.0": {"dependencies": {"common": "==1.5"}}},
                "common": {"1.5": {}, "2.0": {}},
            },
            "root": {"app": ""},
        },
    ).json()
    assert resolve_body["status"] == "ok"

    status, body = _chokepoints(
        resolved=resolve_body["resolved"],
        dependency_graph=resolve_body["dependency_graph"],
    )
    assert status == 200
    # common is reachable via db and via web, so only app is a chokepoint.
    (entry,) = body["chokepoints"]
    assert entry["package"] == "app"
    assert entry["version"] == "1.0"
    assert entry["dominated"] == ["common", "db", "web"]
    assert entry["dominated_count"] == 3
    assert body["unreachable"] == []


def test_package_names_are_canonicalized():
    status, body = _chokepoints(
        resolved={"App": "1.0", "Left_Pkg": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "App", "1.0"),
            _edge("App", "1.0", "Left_Pkg", "1.0"),
        ],
    )
    assert status == 200
    (entry,) = body["chokepoints"]
    assert entry["package"] == "app"
    assert entry["dominated"] == ["left-pkg"]


def test_deterministic_results_regardless_of_edge_order():
    payload = {"resolved": DIAMOND_RESOLVED, "dependency_graph": DIAMOND_GRAPH}
    first = client.post("/audit/dependency-chokepoints", json=payload).json()
    # Edge input permutation must not change the audit.
    shuffled = dict(payload, dependency_graph=list(reversed(DIAMOND_GRAPH)))
    second = client.post("/audit/dependency-chokepoints", json=shuffled).json()
    assert second == first
    results = [
        client.post("/audit/dependency-chokepoints", json=payload).json()
        for _ in range(5)
    ]
    assert all(r == first for r in results)


# ---------------------------------------------------------------------------
# 400s / 422s (audit conventions reused)
# ---------------------------------------------------------------------------


def test_invalid_resolved_version_returns_400():
    status, body = _chokepoints(
        resolved={"x": "not-a-version"}, dependency_graph=[]
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "PEP 440" in body["error"]["message"]


def test_dangling_target_returns_400():
    status, body = _chokepoints(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "ghost", "1.0")],
    )
    assert status == 400
    assert "dangling" in body["error"]["message"]


def test_dangling_source_returns_400():
    status, body = _chokepoints(
        resolved={"app": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("ghost", "1.0", "app", "1.0"),
        ],
    )
    assert status == 400
    assert "dangling" in body["error"]["message"]


def test_edge_target_version_inconsistent_with_resolved_returns_400():
    status, body = _chokepoints(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "app", "2.0")],
    )
    assert status == 400
    assert "inconsistent" in body["error"]["message"]


def test_edge_source_version_inconsistent_with_resolved_returns_400():
    status, body = _chokepoints(
        resolved={"app": "1.0", "lib": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("app", "9.9", "lib", "1.0"),
        ],
    )
    assert status == 400
    assert "inconsistent" in body["error"]["message"]


def test_root_edge_with_source_version_returns_400():
    status, body = _chokepoints(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "1.0", "app", "1.0")],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_extra_fields_rejected():
    response = client.post(
        "/audit/dependency-chokepoints",
        json={"resolved": {}, "dependency_graph": [], "nope": 1},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Differential testing against an independent brute-force oracle
# ---------------------------------------------------------------------------


def _oracle(names, edges):
    """Reference dominators via node deletion.

    ``c`` dominates ``p`` iff removing ``c`` from the graph makes ``p``
    unreachable from ``<root>`` — the definitional check, computed with an
    independent plain-BFS implementation.
    """
    adj = {"<root>": set()}
    for name in names:
        adj.setdefault(name, set())
    for s, t in edges:
        adj[s].add(t)

    def reachable(banned=None):
        seen = set()
        stack = ["<root>"]
        while stack:
            node = stack.pop()
            if node in seen or node == banned:
                continue
            seen.add(node)
            stack.extend(adj.get(node, ()))
        return seen

    full = reachable()
    dominated = {}
    for c in sorted(full - {"<root>"}):
        without = reachable(c)
        dominated[c] = sorted(
            p for p in full - {"<root>", c} if p not in without
        )
    return full, dominated


def test_random_graphs_match_oracle():
    import random

    rng = random.Random(20260918)
    for trial in range(500):
        count = rng.randint(1, 7)
        names = [f"p{i}" for i in range(count)]
        edges = set()
        for s in names:
            for t in names:
                if rng.random() < 0.28:
                    edges.add((s, t))
        # names[0] is always a root dependency; extra root edges and missing
        # ones vary which packages are reachable at all.
        root_edges = {("<root>", names[0])}
        for n in names:
            if rng.random() < 0.3:
                root_edges.add(("<root>", n))
        all_edges = sorted(root_edges) + sorted(edges)

        resolved = {name: "1.0" for name in names}
        graph = [
            _edge(
                s if s != "<root>" else "<root>",
                "" if s == "<root>" else "1.0",
                t,
                "1.0",
            )
            for s, t in all_edges
        ]

        full, dominated = _oracle(names, all_edges)

        status, body = _chokepoints(resolved=resolved, dependency_graph=graph)
        assert status == 200, trial

        expected_unreachable = sorted(set(names) - (full - {"<root>"}))
        assert body["unreachable"] == expected_unreachable, trial

        expected_chokepoints = {c: ps for c, ps in dominated.items() if ps}
        got = {e["package"]: e["dominated"] for e in body["chokepoints"]}
        assert got == expected_chokepoints, trial

        # Shape invariants: sorted output, consistent counts and summary.
        assert [e["package"] for e in body["chokepoints"]] == sorted(got)
        for entry in body["chokepoints"]:
            assert entry["dominated"] == sorted(entry["dominated"])
            assert entry["dominated_count"] == len(entry["dominated"])
            assert entry["version"] == "1.0"
        assert body["summary"] == {
            "packages": count,
            "reachable": len(full) - 1,
            "unreachable": len(expected_unreachable),
            "chokepoints": len(expected_chokepoints),
        }
