import argparse
import json
import os
import uuid

from falcon.audit.log import AuditLog, verify_chain

KILL_FILE = "KILL"


def _planner(args):
    from falcon.planner.planner import BAD_PLANS, LLMPlanner, MockPlanner, anthropic_call
    if args.demo_bad:
        return LLMPlanner(lambda s, p: json.dumps(BAD_PLANS[args.demo_bad]), name="demo-bad")
    if args.planner == "llm":
        return LLMPlanner(anthropic_call, name="anthropic")
    return MockPlanner()


def _finish(audit, status):
    ok, bad = verify_chain(audit.path)
    chain = "VALID" if ok else f"BROKEN at line {bad}"
    print(f"\nstatus: {status}\naudit log: {audit.path} (hash chain {chain})")


def cmd_collect(args):
    import boto3
    from falcon.collectors.aws_collector import collect, save
    run_id = uuid.uuid4().hex[:12]
    os.makedirs("runs", exist_ok=True)
    audit = AuditLog(f"runs/{run_id}.audit.jsonl", run_id)
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    snap = collect(session, audit, region=args.region)
    save(snap, args.out)
    print(f"run {run_id}: saved {args.out}")


def cmd_paths(args):
    from falcon.graph.builder import build_graph
    from falcon.graph.paths import describe, find_paths
    g = build_graph(json.load(open(args.snapshot)))
    res = find_paths(g)[: args.top]
    print(f"Graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
    if not res:
        print("No attack paths found.")
    for i, r in enumerate(res, 1):
        print(f"#{i}  score={r['score']}  hops={r['hops']}\n    {describe(g, r)}")


def cmd_run(args):
    from falcon.guardrails.preflight import GuardrailViolation
    from falcon.planner.schema import PlanValidationError
    os.makedirs("runs", exist_ok=True)
    run_id = uuid.uuid4().hex[:12]
    audit = AuditLog(f"runs/{run_id}.audit.jsonl", run_id)
    print(f"run id: {run_id}   mode: {args.mode}")
    try:
        if args.mode == "live":
            status = _run_live(args, audit)
        else:
            from falcon.orchestrator import run_dry
            snap = json.load(open(args.snapshot))
            run_dry(snap, args.account or snap["account_id"], audit, _planner(args), seed=args.seed)
            status = "completed"
    except (GuardrailViolation, PlanValidationError) as e:
        status = f"BLOCKED: {e}"
    _finish(audit, status)
    if args.report:
        if args.mode != "live" or status.startswith("BLOCKED"):
            print("report skipped: a report needs a completed LIVE run (dry-run emits no real signals).")
        else:
            _make_report(audit.path, f"runs/{run_id}.snapshot.json", args.rules, f"reports/{run_id}")


def _default_rules():
    return os.path.join(os.path.dirname(__file__), "detection", "rules_baseline.json")


def _make_report(log, snapshot, rules, out_dir):
    from falcon.detection.stub import TamperError
    from falcon.report.generate import write_reports
    try:
        rep, out = write_reports(log, snapshot, rules or _default_rules(), out_dir)
    except TamperError as e:
        raise SystemExit(f"REPORT REFUSED: {e}")
    s = rep["detection"]["summary"]
    print(f"\nSOC report written to {out}/ (report.html, report.md, report.json)")
    print(f"  detected {s['detected']} | partial {s['partial']} | missed {s['missed']} "
          f"| IOC coverage {s['ioc_coverage_pct']}% | MTTD {s['mttd_s']} s")


def cmd_report(args):
    run_id = os.path.basename(args.log).split(".")[0]
    snap = args.snapshot or f"runs/{run_id}.snapshot.json"
    _make_report(args.log, snap, args.rules, args.out or f"reports/{run_id}")


def _run_live(args, audit):
    from falcon.guardrails.killswitch import KillSwitch
    from falcon.live import run_live
    ks = KillSwitch(KILL_FILE)
    if ks.is_set():
        raise SystemExit(f"stale kill file '{KILL_FILE}' exists. Delete it (or run: python -m falcon.cli clear-kill) first.")
    ks.install_signal_handler()
    kw = dict(token=args.token, confirm_live=args.confirm_live, killswitch=ks, seed=args.seed,
              time_scale=args.time_scale)
    planner = _planner(args)

    if args.backend == "fake":
        from falcon.cloud.adapter import FakeCloud
        snap = json.load(open(args.snapshot))
        out = run_live(snap, FakeCloud.from_snapshot(snap), audit, planner, **kw)
    elif args.backend == "moto":
        try:
            import boto3
            from moto import mock_aws
        except ImportError:
            raise SystemExit("moto backend needs: pip install \"moto[all]\" boto3")
        from falcon.cloud.adapter import Boto3Cloud
        from falcon.collectors.aws_collector import collect
        from falcon.lab.moto_lab import seed
        for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                     "AWS_DEFAULT_REGION": "us-east-1"}.items():
            os.environ[k] = v                      # fake creds: real AWS can never be reached
        os.environ.pop("AWS_PROFILE", None)
        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            seed(session)
            snap = collect(session, audit, region="us-east-1")   # REAL collector against the mock
            out = run_live(snap, Boto3Cloud(session), audit, planner, **kw)
    else:  # real lab account
        import boto3
        from falcon.cloud.adapter import Boto3Cloud
        from falcon.collectors.aws_collector import collect
        print("!! REAL AWS backend: only your dedicated, allowlisted LAB account may be used !!")
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        snap = collect(session, audit, region=args.region)
        out = run_live(snap, Boto3Cloud(session, args.region), audit, planner, **kw)
    json.dump(snap, open(f"runs/{audit.run_id}.snapshot.json", "w"), indent=2, default=str)
    return out["status"] + ("  (teardown VERIFIED)" if out.get("teardown_verified") else "")


def cmd_issue_token(args):
    from falcon.config import TOKEN_SECRET_ENV
    from falcon.guardrails.token import issue_token
    secret = os.environ.get(TOKEN_SECRET_ENV)
    if not secret:
        raise SystemExit(f"set the {TOKEN_SECRET_ENV} environment variable first")
    print(issue_token(args.account, args.ttl, secret))


def cmd_kill(args):
    from falcon.guardrails.killswitch import KillSwitch
    KillSwitch(KILL_FILE).trip("manual kill via CLI")
    print(f"KILL switch tripped ({KILL_FILE}). In-flight live runs will halt and tear down.")


def cmd_clear_kill(args):
    from falcon.guardrails.killswitch import KillSwitch
    KillSwitch(KILL_FILE).clear()
    print("kill switch cleared")


def cmd_bench(args):
    from falcon.graph.bench import run
    print(run(args.nodes))


def main():
    p = argparse.ArgumentParser(prog="falcon")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="read-only snapshot of the lab account")
    c.add_argument("--profile", default=None)
    c.add_argument("--region", default="ap-south-1")
    c.add_argument("--out", default="snapshot.json")
    c.set_defaults(fn=cmd_collect)

    pp = sub.add_parser("paths", help="print ranked attack paths")
    pp.add_argument("--snapshot", default="samples/lab_snapshot.json")
    pp.add_argument("--top", type=int, default=5)
    pp.set_defaults(fn=cmd_paths)

    r = sub.add_parser("run", help="plan + run a campaign (dry-run by default)")
    r.add_argument("--snapshot", default="samples/lab_snapshot.json")
    r.add_argument("--account", default=None, help="(dry-run) override account id to demo the allowlist")
    r.add_argument("--mode", choices=["dry-run", "live"], default="dry-run")
    r.add_argument("--backend", choices=["fake", "moto", "aws"], default="fake", help="(live) where to run")
    r.add_argument("--profile", default=None, help="(live, aws backend)")
    r.add_argument("--region", default="ap-south-1")
    r.add_argument("--token", default=None, help="(live) signed authorisation token = key 1")
    r.add_argument("--confirm-live", action="store_true", help="(live) second confirmation = key 2")
    r.add_argument("--time-scale", type=float, default=1.0, help="shrink beacon waits, e.g. 0.2")
    r.add_argument("--planner", choices=["mock", "llm"], default="mock")
    r.add_argument("--demo-bad", choices=["unknown_technique", "foreign_account", "bad_sink"], default=None)
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--report", action="store_true", help="(live) write the SOC report after the run")
    r.add_argument("--rules", default=None, help="detection rule set (default: baseline)")
    r.set_defaults(fn=cmd_run)

    rp = sub.add_parser("report", help="rebuild a SOC report from a saved audit log")
    rp.add_argument("--log", required=True)
    rp.add_argument("--snapshot", default=None)
    rp.add_argument("--rules", default=None)
    rp.add_argument("--out", default=None)
    rp.set_defaults(fn=cmd_report)

    t = sub.add_parser("issue-token", help="create a signed, expiring live-run token")
    t.add_argument("--account", required=True)
    t.add_argument("--ttl", type=int, default=600, help="seconds")
    t.set_defaults(fn=cmd_issue_token)

    sub.add_parser("kill", help="KILL SWITCH: halt live runs and trigger teardown").set_defaults(fn=cmd_kill)
    sub.add_parser("clear-kill", help="clear the kill switch").set_defaults(fn=cmd_clear_kill)

    b = sub.add_parser("bench", help="p95 path-query latency on a synthetic graph")
    b.add_argument("--nodes", type=int, default=10000)
    b.set_defaults(fn=cmd_bench)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
