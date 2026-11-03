"""Find and rank attack paths from entry points to high-value targets."""
from itertools import islice

import networkx as nx

from falcon.graph.builder import INTERNET

MAX_HOPS = 8


def entry_nodes(g):
    return [n for n, d in g.nodes(data=True) if d.get("type") in ("Internet", "Account")]


def targets(g):
    return [n for n, d in g.nodes(data=True) if d.get("is_high_value")]


def score(g, path):
    """Higher = more urgent. impact / hops + bonus per weak node + bonus if internet-reachable."""
    tgt = g.nodes[path[-1]]
    impact = 10 if tgt.get("is_wildcard") else 5
    weak = sum(1 for n in path[1:] if g.nodes[n].get("is_wildcard")
               or g.nodes[n].get("privesc_primitive") or g.nodes[n].get("is_public"))
    hops = len(path) - 1
    s = impact / hops + 0.5 * weak + (2 if path[0] == INTERNET else 0)
    return round(s, 2)


def find_paths(g, k_per_pair=3, sources=None, tgts=None):
    sources = sources or entry_nodes(g)
    tgts = tgts or targets(g)
    simple = nx.DiGraph(g)  # collapse parallel edges for path search
    results = []
    for s in sources:
        for t in tgts:
            if s == t or not nx.has_path(simple, s, t):
                continue
            for p in islice(nx.shortest_simple_paths(simple, s, t), k_per_pair):
                if len(p) - 1 <= MAX_HOPS:
                    results.append({"path": p, "hops": len(p) - 1, "score": score(g, p)})
    results.sort(key=lambda r: (-r["score"], r["hops"]))
    return results


def describe(g, r):
    names = [g.nodes[n].get("name", n) for n in r["path"]]
    return " -> ".join(names)
