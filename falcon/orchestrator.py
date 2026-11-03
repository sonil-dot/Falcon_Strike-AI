"""Run lifecycle (dry-run): preflight -> graph -> paths -> plan -> gate -> simulate.
Imports NO cloud SDK: dry-run cannot touch resources by construction."""
import json
from types import SimpleNamespace

from falcon.graph.builder import build_graph
from falcon.graph.paths import find_paths, describe
from falcon.guardrails.gate import check_campaign
from falcon.guardrails.preflight import preflight
from falcon.planner.schema import PlanValidationError
from falcon.techniques.registry import REGISTRY


def run_dry(snapshot, account_id, audit, planner, seed=0, say=print):
    preflight(account_id, "dry-run", audit)
    say(f"[1/5] preflight OK (account {account_id}, mode dry-run)")

    g = build_graph(snapshot)
    audit.append("graph_built", params={"nodes": g.number_of_nodes(), "edges": g.number_of_edges()})
    say(f"[2/5] graph built: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")

    paths = find_paths(g)
    if not paths:
        audit.append("no_paths", outcome="none")
        say("no attack paths found; nothing to plan")
        return {"paths": [], "results": []}
    top = paths[0]
    audit.append("paths_found", params={"count": len(paths), "top": describe(g, top), "score": top["score"]})
    say(f"[3/5] top path (score {top['score']}): {describe(g, top)}")

    try:
        campaign = planner.plan(g, top["path"], seed)
    except PlanValidationError as e:
        audit.append("plan_rejected_schema", outcome="blocked", actor="guardrail", params={"reason": str(e)})
        say(f"[4/5] BLOCKED (schema): {e}")
        raise
    audit.append("plan_generated", actor=f"planner:{planner.name}",
                 params={"seed": seed, "actions": [a.__dict__ for a in campaign.actions]})
    check_campaign(campaign, REGISTRY, audit, account_id)
    say(f"[4/5] plan approved by guardrails: {len(campaign.actions)} actions")

    ctx = SimpleNamespace(graph=g, account_id=account_id)
    results = []
    say("[5/5] dry-run simulation (touches nothing):")
    for i, a in enumerate(campaign.actions, 1):
        t = REGISTRY[a.technique_id]
        audit.append("action_start", actor="executor", technique_id=t.id, attack_id=t.attack_id,
                     target=str(next(iter(a.params.values()), "")), params={**a.params, "mode": "dry-run"})
        r = t.simulate(ctx, a.params)
        audit.append("action_end", actor="executor", technique_id=t.id, attack_id=t.attack_id,
                     target=str(next(iter(a.params.values()), "")),
                     outcome="simulated_ok" if r["ok"] else "precondition_failed", iocs=r["iocs"])
        results.append({"technique": t.id, "attack_id": t.attack_id, **r})
        say(f"   {i}. {t.attack_id:<6} {t.id:<26} {'OK  ' if r['ok'] else 'FAIL'} {r['detail']}")
    audit.append("run_end", params={"actions": len(results)})
    return {"paths": paths, "results": results}
