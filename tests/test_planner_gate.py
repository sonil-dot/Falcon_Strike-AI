import json
import pytest

from falcon.audit.log import AuditLog, verify_chain
from falcon.guardrails.gate import check_campaign
from falcon.guardrails.preflight import GuardrailViolation
from falcon.orchestrator import run_dry
from falcon.planner.planner import BAD_PLANS, LLMPlanner, MockPlanner
from falcon.planner.schema import PlanValidationError, parse_campaign
from falcon.techniques.base import ContractError, Technique
from falcon.techniques.registry import REGISTRY

ACCT = "123456789012"
SNAP = json.load(open("samples/lab_snapshot.json"))


def mk_log(tmp_path):
    return AuditLog(str(tmp_path / "a.jsonl"), "r1")


def quiet(*a, **k):
    pass


def test_valid_run_completes(tmp_path):
    log = mk_log(tmp_path)
    out = run_dry(SNAP, ACCT, log, MockPlanner(), say=quiet)
    assert len(out["results"]) == 6 and all(r["ok"] for r in out["results"])
    assert verify_chain(log.path)[0]


def test_mock_plan_is_deterministic():
    from falcon.graph.builder import build_graph
    from falcon.graph.paths import find_paths
    g = build_graph(SNAP)
    p = find_paths(g)[0]["path"]
    a = MockPlanner().plan(g, p, seed=3)
    b = MockPlanner().plan(g, p, seed=3)
    assert [x.__dict__ for x in a.actions] == [x.__dict__ for x in b.actions]


@pytest.mark.parametrize("kind", list(BAD_PLANS))
def test_bad_plans_blocked(tmp_path, kind):
    log = mk_log(tmp_path)
    planner = LLMPlanner(lambda s, p: json.dumps(BAD_PLANS[kind]))
    with pytest.raises(GuardrailViolation):
        run_dry(SNAP, ACCT, log, planner, say=quiet)
    assert '"plan_blocked"' in open(log.path).read()
    assert '"action_start"' not in open(log.path).read()      # nothing executed
    assert verify_chain(log.path)[0]


def test_out_of_scope_account_never_reaches_planner(tmp_path):
    log = mk_log(tmp_path)
    called = []
    planner = LLMPlanner(lambda s, p: called.append(1) or "{}")
    with pytest.raises(GuardrailViolation):
        run_dry(SNAP, "999999999999", log, planner, say=quiet)
    assert called == []


@pytest.mark.parametrize("raw", [
    "not json at all",
    '{"actions": []}',
    '{"actions": [{"technique_id": "discovery.cloud_infra", "params": {}, "rationale": "x"}], "extra": 1}',
    '{"actions": [{"technique_id": "discovery.cloud_infra", "params": {}, "rationale": "x", "shell": "rm -rf /"}]}',
    '{"actions": [{"technique_id": "Bad ID!", "params": {}, "rationale": "x"}]}',
    '{"actions": [{"technique_id": "a.b", "params": {"k": {"nested": 1}}, "rationale": "x"}]}',
])
def test_schema_rejects_malformed(raw):
    with pytest.raises(PlanValidationError):
        parse_campaign(raw)


def test_schema_accepts_fenced_json():
    raw = '```json\n{"actions": [{"technique_id": "discovery.cloud_infra", "params": {"scope": "account"}, "rationale": "r"}]}\n```'
    assert len(parse_campaign(raw).actions) == 1


def test_too_many_actions_blocked(tmp_path):
    acts = [{"technique_id": "discovery.cloud_infra", "params": {"scope": "account"}, "rationale": "r"}] * 11
    with pytest.raises(GuardrailViolation):
        check_campaign(parse_campaign({"actions": acts}), REGISTRY, mk_log(tmp_path), ACCT)


def test_out_of_range_param_blocked(tmp_path):
    a = [{"technique_id": "c2.https_beacon",
          "params": {"sink": "127.0.0.1:8443", "interval_s": 0, "jitter_pct": 10, "beacons": 5}, "rationale": "r"}]
    with pytest.raises(GuardrailViolation):
        check_campaign(parse_campaign({"actions": a}), REGISTRY, mk_log(tmp_path), ACCT)


def test_extra_param_blocked(tmp_path):
    a = [{"technique_id": "discovery.cloud_infra", "params": {"scope": "account", "cmd": "whoami"}, "rationale": "r"}]
    with pytest.raises(GuardrailViolation):
        check_campaign(parse_campaign({"actions": a}), REGISTRY, mk_log(tmp_path), ACCT)


def test_destructive_technique_cannot_exist():
    with pytest.raises(ContractError):
        Technique("x.y", "T0", "n", "t", [], "a", [], "td", {}, None, destructive=True)


def test_all_techniques_have_teardown_and_attack_id():
    for t in REGISTRY.values():
        assert t.teardown and t.attack_id.startswith("T") and not t.destructive


def test_precondition_failure_reported(tmp_path):
    snap = json.loads(json.dumps(SNAP))
    for r in snap["iam"]["RoleDetailList"]:            # break the deploy->admin edge
        if r["RoleName"] == "falcon-lab-wildcard-admin":
            r["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::123456789012:role/nobody"
    out = run_dry(snap, ACCT, mk_log(tmp_path), MockPlanner(), say=quiet)
    assert out["paths"] == [] or any(not r["ok"] for r in out["results"]) or out["results"] == []
