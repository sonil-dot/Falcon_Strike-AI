"""LIVE run lifecycle with safety controls:
two-key preflight -> account match -> plan -> gate -> baseline -> actions (kill switch,
time-box, caps, circuit breaker) -> ALWAYS teardown + verify (finally)."""
import time
from datetime import datetime, timezone
from types import SimpleNamespace

from falcon.c2.sink import Sink
from falcon.graph.builder import build_graph
from falcon.graph.paths import describe, find_paths
from falcon.guardrails.gate import check_campaign
from falcon.guardrails.preflight import GuardrailViolation, preflight
from falcon.planner.schema import PlanValidationError
from falcon.techniques.live import LIVE, CapExceeded
from falcon.techniques.registry import REGISTRY
from types import SimpleNamespace as NS

DEFAULT_CAPS = {"max_resources": 3, "max_seconds": 300, "max_consecutive_failures": 2}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _diff(a, b):
    return {k: {"added": sorted(set(b.get(k, [])) - set(a.get(k, []))),
                "removed": sorted(set(a.get(k, [])) - set(b.get(k, [])))}
            for k in set(a) | set(b) if a.get(k) != b.get(k)}


def teardown(cloud, run, baseline, audit, say):
    errors = []
    for kind, name in reversed(run.created):
        try:
            cloud.delete_role(name)
            audit.append("teardown_delete", actor="teardown", target=name, outcome="ok")
        except Exception as e:
            errors.append(name)
            audit.append("teardown_delete", actor="teardown", target=name, outcome="error",
                         params={"error": str(e)[:200]})
    after = cloud.snapshot_state()
    diff = _diff(baseline, after)
    ok = not errors and not diff
    audit.append("teardown_verify", actor="teardown", outcome="verified" if ok else "FAILED",
                 params={"baseline_equal": not diff, "diff": diff, "delete_errors": errors})
    say(f"teardown: {'VERIFIED - lab state equals baseline' if ok else 'FAILED - ' + str(diff or errors)}")
    return ok


def run_live(snapshot, cloud, audit, planner, token, confirm_live, killswitch, seed=0,
             caps=None, say=print, time_scale=1.0, clock=time.monotonic, sleep=time.sleep,
             after_action=None):
    caps = {**DEFAULT_CAPS, **(caps or {})}
    account = cloud.account_id()                     # the account we are REALLY connected to
    preflight(account, "live", audit, token=token, confirm_live=confirm_live)
    say(f"[1/6] preflight OK: account {account}, mode LIVE (token + second key verified)")
    if snapshot["account_id"] != account:
        audit.append("preflight_blocked", outcome="blocked",
                     params={"reason": "snapshot account differs from connected account"})
        raise GuardrailViolation("snapshot account differs from connected account")

    g = build_graph(snapshot)
    paths = find_paths(g)
    if not paths:
        audit.append("no_paths", outcome="none")
        return {"status": "no_paths", "results": [], "teardown_verified": None}
    top = paths[0]
    audit.append("paths_found", params={"top": describe(g, top), "score": top["score"]})
    say(f"[2/6] top path: {describe(g, top)}")

    try:
        campaign = planner.plan(g, top["path"], seed)
    except PlanValidationError as e:
        audit.append("plan_rejected_schema", outcome="blocked", actor="guardrail", params={"reason": str(e)})
        raise
    audit.append("plan_generated", actor=f"planner:{planner.name}",
                 params={"seed": seed, "actions": [a.__dict__ for a in campaign.actions]})
    check_campaign(campaign, REGISTRY, audit, account)
    say(f"[3/6] plan approved by guardrails ({len(campaign.actions)} actions)")

    baseline = cloud.snapshot_state()
    audit.append("baseline_recorded", params={"roles": len(baseline["roles"]), "params": len(baseline["params"])})
    say("[4/6] baseline recorded")

    run = NS(id=audit.run_id, created=[], seed=seed, max_resources=caps["max_resources"],
             sleep=sleep, time_scale=time_scale, should_stop=killswitch.is_set)
    ctx = SimpleNamespace(graph=g, account_id=account)

    sink = None
    beacon = next((a for a in campaign.actions if a.technique_id == "c2.https_beacon"), None)
    results, status, failures, t0 = [], "completed", 0, clock()
    try:
        if beacon:
            host, port = beacon.params["sink"].split(":")
            sink = Sink(host, int(port)).start()
            audit.append("sink_started", target=beacon.params["sink"])
        say("[5/6] executing (non-destructive, reversible):")
        for i, a in enumerate(campaign.actions, 1):
            if killswitch.is_set():
                audit.append("kill_switch_tripped", actor="killswitch", outcome="halted",
                             params={"before_action": i})
                say("   !! KILL SWITCH tripped - halting")
                status = "killed"
                break
            if clock() - t0 > caps["max_seconds"]:
                audit.append("timebox_exceeded", outcome="halted")
                status = "timeboxed"
                break
            t = REGISTRY[a.technique_id]
            target = str(next(iter(a.params.values()), ""))
            started = _now()
            audit.append("action_start", actor="executor", technique_id=t.id, attack_id=t.attack_id,
                         target=target, params={**a.params, "mode": "live"})
            pre = t.simulate(ctx, a.params)             # side-effect-free precondition check
            if not pre["ok"]:
                r = pre
            else:
                try:
                    r = LIVE[t.id](cloud, run, a.params)
                except CapExceeded:
                    raise
                except Exception as e:
                    r = {"ok": False, "detail": f"error: {str(e)[:150]}", "iocs": []}
            audit.append("action_end", actor="executor", technique_id=t.id, attack_id=t.attack_id,
                         target=target, outcome="executed_ok" if r["ok"] else "failed", iocs=r["iocs"])
            results.append({"technique": t.id, "attack_id": t.attack_id, "started_at": started,
                            "ended_at": _now(), **r})
            say(f"   {i}. {t.attack_id:<6} {t.id:<26} {'OK  ' if r['ok'] else 'FAIL'} {r['detail']}")
            failures = 0 if r["ok"] else failures + 1
            if failures >= caps["max_consecutive_failures"]:
                audit.append("circuit_breaker", outcome="halted", params={"failures": failures})
                status = "circuit_breaker"
                break
            if after_action:
                after_action(i, a)
        else:                                            # loop finished: was the kill tripped during the last action?
            if killswitch.is_set():
                audit.append("kill_switch_tripped", actor="killswitch", outcome="halted",
                             params={"during_last_action": True})
                say("   !! KILL SWITCH tripped during the final action")
                status = "killed"
    except CapExceeded as e:
        audit.append("cap_exceeded", outcome="halted", params={"reason": str(e)})
        status = "cap_exceeded"
    except Exception as e:
        audit.append("run_error", outcome="error", params={"error": repr(e)[:200]})
        status = f"error: {e!r}"
    finally:
        say("[6/6] teardown:")
        if sink:
            sink.stop()
        ok = teardown(cloud, run, baseline, audit, say)
    if not ok:
        status = "teardown_failed"
    audit.append("run_end", params={"status": status, "teardown_verified": ok})
    return {"status": status, "results": results, "teardown_verified": ok,
            "beacons_received": len(sink.received) if sink else 0}
