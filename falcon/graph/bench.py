"""Synthetic >=10k-node graph + p95 path-query latency (NFR-P1/P2)."""
import json
import random
import statistics
import time

import networkx as nx

from falcon.graph.paths import MAX_HOPS


def synthetic_graph(n_nodes=10_000, seed=7):
    rnd = random.Random(seed)
    g = nx.DiGraph()
    g.add_node("internet", type="Internet")
    ids = [f"role{i}" for i in range(n_nodes)]
    for i in ids:
        g.add_node(i, type="Role", is_high_value=False)
    for i in ids:                                   # sparse random trust edges
        for j in rnd.sample(ids, 2):
            g.add_edge(i, j, type="CAN_ASSUME")
    for i in rnd.sample(ids, 5):
        g.add_edge("internet", i, type="EXPOSES")
    for t in rnd.sample(ids, 20):
        g.nodes[t]["is_high_value"] = True
    return g


def run(n_nodes=10_000, queries=100, out="evidence/perf_report.json"):
    g = synthetic_graph(n_nodes)
    tgts = [n for n, d in g.nodes(data=True) if d.get("is_high_value")]
    rnd = random.Random(1)
    lat = []
    for _ in range(queries):
        t = rnd.choice(tgts)
        t0 = time.perf_counter()
        try:
            p = nx.shortest_path(g, "internet", t)
            _ = len(p) <= MAX_HOPS + 1
        except nx.NetworkXNoPath:
            pass
        lat.append((time.perf_counter() - t0) * 1000)
    lat.sort()
    rep = {"engine": "networkx", "nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
           "queries": queries, "p50_ms": round(statistics.median(lat), 3),
           "p95_ms": round(lat[int(0.95 * len(lat)) - 1], 3), "max_ms": round(lat[-1], 3),
           "target_p95_ms": 1000, "meets_target": lat[int(0.95 * len(lat)) - 1] < 1000}
    with open(out, "w") as f:
        json.dump(rep, f, indent=2)
    return rep
