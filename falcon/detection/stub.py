"""Detection stub = a stand-in SIEM/EDR. It sees ONLY the ground-truth IOCs reconstructed from the
tamper-evident audit log, and decides what its rules would have caught. Detection latency is
SIMULATED (rule delay_s). Swap in a real SIEM query later without changing the report."""
import json
from datetime import datetime, timedelta

from falcon.audit.log import verify_chain


class TamperError(Exception):
    pass


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_rules(path):
    return json.load(open(path))


def ground_truth(log_path):
    ok, bad = verify_chain(log_path)
    if not ok:
        raise TamperError(f"audit log hash chain broken at line {bad}; refusing to build a report")
    meta, actions, pending = {"status": None, "teardown": None, "killed": False}, [], None
    for line in open(log_path):
        r = json.loads(line)
        ev, p = r["event"], r.get("params", {})
        meta["run_id"] = r["run_id"]
        if ev == "preflight_passed":
            meta["account"], meta["mode"] = p["account"], p["mode"]
        elif ev == "paths_found":
            meta["top_path"], meta["top_score"] = p["top"], p.get("score")
        elif ev == "action_start":
            pending = {"technique_id": r["technique_id"], "attack_id": r["attack_id"],
                       "target": r["target"], "started": r["ts"], "mode": p.get("mode")}
        elif ev == "action_end" and pending:
            pending.update(ended=r["ts"], outcome=r["outcome"], iocs=r["iocs"])
            actions.append(pending)
            pending = None
        elif ev == "kill_switch_tripped":
            meta["killed"] = True
        elif ev == "teardown_verify":
            meta["teardown"] = r["outcome"]
        elif ev == "run_end":
            meta["status"] = p.get("status", "completed")
    return meta, actions


def correlate(actions, rules):
    techs = {}
    for a in actions:
        t = techs.setdefault(a["technique_id"], {"technique_id": a["technique_id"], "attack_id": a["attack_id"],
                                                 "iocs": [], "first_start": a["started"], "runs": 0})
        t["runs"] += 1
        t["first_start"] = min(t["first_start"], a["started"])
        for ioc in a["iocs"]:
            hits = [r for r in rules if any(ioc.startswith(m) for m in r["match"])]
            best = min(hits, key=lambda r: r["delay_s"]) if hits else None
            t["iocs"].append({"ioc": ioc, "detected": bool(best), "rule": best["id"] if best else None,
                              "detected_at": (_ts(a["ended"]) + timedelta(seconds=best["delay_s"])).isoformat()
                              if best else None})
    for t in techs.values():
        n, d = len(t["iocs"]), sum(i["detected"] for i in t["iocs"])
        t["status"] = "missed" if d == 0 else ("detected" if d == n else "partial")
        times = [_ts(i["detected_at"]) for i in t["iocs"] if i["detected"]]
        t["ttd_s"] = round((min(times) - _ts(t["first_start"])).total_seconds(), 1) if times else None
    lst = sorted(techs.values(), key=lambda t: t["first_start"])
    n_iocs = sum(len(t["iocs"]) for t in lst)
    d_iocs = sum(i["detected"] for t in lst for i in t["iocs"])
    ttds = [t["ttd_s"] for t in lst if t["ttd_s"] is not None]
    return {"techniques": lst,
            "summary": {"techniques_total": len(lst),
                        "detected": sum(t["status"] == "detected" for t in lst),
                        "partial": sum(t["status"] == "partial" for t in lst),
                        "missed": sum(t["status"] == "missed" for t in lst),
                        "ioc_coverage_pct": round(100 * d_iocs / n_iocs, 1) if n_iocs else 0.0,
                        "mttd_s": round(sum(ttds) / len(ttds), 1) if ttds else None}}
