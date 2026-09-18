"""Dependency chokepoint (dominator) audit over a resolved dependency graph.

Consumes the ``resolved`` mapping and ``dependency_graph`` edges emitted by a
successful ``/resolve`` call and performs a dominator analysis with ``<root>``
as the single entry: a package ``c`` *dominates* a reachable package ``p``
when every path from ``<root>`` to ``p`` passes through ``c`` — ``p`` cannot
be reached, even via cycles or diamond re-convergence, without ``c``.  Such a
``c`` is an unavoidable dependency (a chokepoint) of ``p``.

For every chokepoint the response aggregates the downstream packages it
exclusively controls (its *dominated* set) together with the count — exactly
the blast radius of removing or compromising that one package.  Packages
present in ``resolved`` but unreachable from ``<root>`` take no part in the
analysis and are listed separately as ``unreachable``.

Pipeline
--------
1. Validation reuses the audit pipeline verbatim: ``resolved`` versions are
   PEP 440-checked and every graph endpoint must be ``<root>`` or a package
   present in ``resolved`` with a matching version (no dangling edges).
2. Dominator sets are computed with the standard iterative dataflow
   (``dom(<root>) = {<root>}``, ``dom(n) = {n} ∪ ⋂ dom(predecessors(n))``)
   over the reachable subgraph.  The meet operator is set intersection, so
   cycles and diamonds need no special handling and the fixpoint is unique:
   identical input always yields identical output, regardless of edge order.
3. The per-package dominator sets are inverted into the per-chokepoint
   aggregation.  ``<root>`` itself and self-domination are excluded, since
   neither names a dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .audit import parse_graph, parse_resolved
from .resolver import ROOT


# ---------------------------------------------------------------------------
# Edge normalization (same convention as the rebuild planner)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _GraphEdge:
    source: str
    source_version: str
    target: str
    target_version: str


def _edge_view(raw: Any):
    """Accept pydantic edge models (API path) or plain dicts (direct calls)."""
    if isinstance(raw, dict):
        return _GraphEdge(
            source=raw["source"],
            source_version=raw["source_version"],
            target=raw["target"],
            target_version=raw["target_version"],
        )
    return raw


# ---------------------------------------------------------------------------
# Dominator analysis
# ---------------------------------------------------------------------------


def _reachable_nodes(adjacency: dict[str, list[str]]) -> set[str]:
    """Every node reachable from ``<root>`` (``<root>`` itself included)."""
    seen = {ROOT}
    stack = [ROOT]
    while stack:
        node = stack.pop()
        for nxt in adjacency.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _dominator_sets(
    adjacency: dict[str, list[str]], nodes: set[str]
) -> dict[str, set[str]]:
    """Dominator set of every reachable node, with ``<root>`` as the entry.

    Standard iterative dataflow: ``dom(<root>) = {<root>}`` and
    ``dom(n) = {n} ∪ (⋂ dom(p) for p in predecessors(n))``.  Intersection is
    the meet operator, so the equations have a unique fixpoint that the
    iteration reaches regardless of evaluation order; iterating in sorted
    order merely keeps intermediate states deterministic as well.
    """
    predecessors: dict[str, list[str]] = {node: [] for node in nodes}
    for source in nodes:
        for target in adjacency.get(source, ()):
            if target in predecessors:
                predecessors[target].append(source)

    dom = {node: set(nodes) for node in nodes}
    dom[ROOT] = {ROOT}
    changed = True
    while changed:
        changed = False
        for node in sorted(nodes):
            if node == ROOT:
                continue
            preds = predecessors[node]
            # A reachable non-root node always has >=1 reachable predecessor.
            assert preds, f"reachable node {node!r} has no predecessor"
            new = {node} | set.intersection(*(dom[p] for p in preds))
            if new != dom[node]:
                dom[node] = new
                changed = True
    return dom


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def run_chokepoint_audit(
    resolved_raw: dict[str, str],
    edges_raw: Iterable[Any],
) -> dict[str, Any]:
    """Run the chokepoint (dominator) audit; see the module docstring."""
    resolved = parse_resolved(resolved_raw)
    adjacency = parse_graph((_edge_view(edge) for edge in edges_raw), resolved)

    reachable = _reachable_nodes(adjacency)
    dom = _dominator_sets(adjacency, reachable)

    # Invert the per-package dominator sets into per-chokepoint dominated
    # sets.  ``<root>`` and self-domination never name a dependency, so both
    # are excluded; unreachable packages take no part at all.
    dominated: dict[str, list[str]] = {}
    for package in sorted(reachable):
        if package == ROOT:
            continue
        for chokepoint in dom[package] - {package, ROOT}:
            dominated.setdefault(chokepoint, []).append(package)

    chokepoints = [
        {
            "package": package,
            "version": str(resolved[package]),
            "dominated": sorted(packages),
            "dominated_count": len(packages),
        }
        for package, packages in sorted(dominated.items())
    ]
    unreachable = sorted(set(resolved) - (reachable - {ROOT}))

    return {
        "status": "ok",
        "summary": {
            "packages": len(resolved),
            "reachable": len(reachable) - 1,
            "unreachable": len(unreachable),
            "chokepoints": len(chokepoints),
        },
        "chokepoints": chokepoints,
        "unreachable": unreachable,
    }
