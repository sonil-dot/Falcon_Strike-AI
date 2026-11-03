import json
import socket

import pytest

from falcon.audit.log import AuditLog, verify_chain
from falcon.c2.beacon import EgressViolation, run_beacons
from falcon.c2.sink import Sink
from falcon.cloud.adapter import FakeCloud
from falcon.guardrails.killswitch import KillSwitch
from falcon.guardrails.preflight import GuardrailViolation
from falcon.guardrails.token import issue_token
from falcon.live import run_live
from falcon.planner.planner import LLMPlanner, MockPlanner

ACCT = "123456789012"
SECRET = "unit-test-secret"
SNAP = json.load(open("samples/lab_snapshot.json"))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def quiet(*a, **k):
    pass


def setup(tmp_path, monkeypatch=None, **cloud_kw):
    import os
    os.environ["FALCON_TOKEN_SECRET"] = SECRET
    log = AuditLog(str(tmp_path / "a.jsonl"), "run-live")
    cloud = FakeCloud.from_snapshot(SNAP, **cloud_kw)
    ks = KillSwitch(str(tmp_path / "KILL"))
    planner = MockPlanner(sink=f"127.0.0.1:{free_port()}")
    token = issue_token(ACCT, 300, SECRET)
    return log, cloud, ks, planner, token


def go(tmp_path, **over):
    log, cloud, ks, planner, token = setup(tmp_path, **over.pop("cloud_kw", {}))
    kw = dict(token=token, confirm_live=True, killswitch=ks, say=quiet, time_scale=0.0)
    kw.update(over)
    out = run_live(SNAP, cloud, log, over.pop("planner", planner), **kw)
    return out, log, cloud, ks


def test_live_run_completes_and_teardown_verified(tmp_path):
    out, log, cloud, _ = go(tmp_path)
    assert out["status"] == "completed" and out["teardown_verified"] is True
    assert all(r["ok"] for r in out["results"]) and len(out["results"]) == 6
    assert out["beacons_received"] == 4                      # sink really received inert beacons
    assert not any(n.startswith("falcon-run-") for n in cloud.roles)   # temp role is gone
    assert verify_chain(log.path)[0]


def test_live_requires_both_keys(tmp_path):
    log, cloud, ks, planner, token = setup(tmp_path)
    with pytest.raises(GuardrailViolation):
        run_live(SNAP, cloud, log, planner, None, True, ks, say=quiet)
    with pytest.raises(GuardrailViolation):
        run_live(SNAP, cloud, log, planner, token, False, ks, say=quiet)
    assert cloud.calls == []                                  # nothing touched the cloud


def test_live_wrong_account_blocked_before_anything(tmp_path):
    log, _, ks, planner, token = setup(tmp_path)
    other = FakeCloud(account="999999999999")
    with pytest.raises(GuardrailViolation):
        run_live(SNAP, other, log, planner, token, True, ks, say=quiet)
    assert other.calls == []


def test_snapshot_account_mismatch_blocked(tmp_path):
    log, cloud, ks, planner, _ = setup(tmp_path)
    snap = json.loads(json.dumps(SNAP))
    snap["account_id"] = "555555555555"
    with pytest.raises(GuardrailViolation):
        run_live(snap, cloud, log, planner, issue_token(ACCT, 60, SECRET), True, ks, say=quiet)


def test_kill_switch_halts_and_tears_down(tmp_path):
    log, cloud, ks, planner, token = setup(tmp_path)

    def trip_after_temp_role(i, action):
        if action.technique_id == "persist.temp_role":
            ks.trip("test")                                   # role exists NOW; beacon not yet run

    out = run_live(SNAP, cloud, log, planner, token, True, ks, say=quiet, time_scale=0.0,
                   after_action=trip_after_temp_role)
    assert out["status"] == "killed"
    assert [r["technique"] for r in out["results"]][-1] == "persist.temp_role"   # beacon never ran
    assert out["teardown_verified"] is True                   # temp role cleaned up anyway
    assert "falcon-run-0" not in cloud.roles
    text = open(log.path).read()
    assert '"kill_switch_tripped"' in text and '"teardown_verify"' in text
    assert verify_chain(log.path)[0]


def test_failed_teardown_is_detected(tmp_path):
    out, log, cloud, _ = go(tmp_path, cloud_kw={"fail_delete": True})
    assert out["status"] == "teardown_failed" and out["teardown_verified"] is False
    assert '"FAILED"' in open(log.path).read()


def test_resource_cap_enforced(tmp_path):
    out, log, cloud, _ = go(tmp_path, caps={"max_resources": 0})
    assert out["status"] == "cap_exceeded" and out["teardown_verified"] is True


def test_circuit_breaker_stops_run(tmp_path):
    log, cloud, ks, planner, token = setup(tmp_path)
    cloud.params.clear()                                      # marker secret missing -> failures
    bad = [{"technique_id": "credaccess.marker_secret", "params": {"parameter": "/falcon-lab/marker-secret"},
            "rationale": "r"}] * 4
    pl = LLMPlanner(lambda s, p: json.dumps({"actions": bad}))
    out = run_live(SNAP, cloud, log, pl, token, True, ks, say=quiet, time_scale=0.0)
    assert out["status"] == "circuit_breaker" and len(out["results"]) == 2


def test_audit_has_before_and_after_for_every_action(tmp_path):
    out, log, _, _ = go(tmp_path)
    lines = [json.loads(l) for l in open(log.path)]
    assert sum(l["event"] == "action_start" for l in lines) == sum(l["event"] == "action_end" for l in lines) == 6


def test_beacon_egress_allowlist():
    with pytest.raises(EgressViolation):
        run_beacons("evil.example.com:443", 1, 10, 1, 0, "r")


def test_sink_refuses_non_loopback():
    with pytest.raises(ValueError):
        Sink("0.0.0.0", 0)


def test_beacon_jitter_is_seeded_and_bounded():
    s = Sink("127.0.0.1", 0).start()
    try:
        a = run_beacons(f"127.0.0.1:{s.port}", 10, 20, 5, 42, "r", sleep=lambda d: None)
        b = run_beacons(f"127.0.0.1:{s.port}", 10, 20, 5, 42, "r", sleep=lambda d: None)
    finally:
        s.stop()
    assert [x["delay_s"] for x in a] == [x["delay_s"] for x in b]       # reproducible
    assert all(8.0 <= x["delay_s"] <= 12.0 for x in a)                  # 10s +/- 20%
    assert all(x["reply"]["cmd"] == "noop" for x in a)                   # inert tokens only
    assert all("FALCON-INERT-BEACON" in r["body"] for r in s.received)


def test_kill_during_last_action_reports_killed(tmp_path):
    log, cloud, ks, planner, token = setup(tmp_path)

    def trip_on_last(i, action):
        pass

    # trip from inside the beacon loop: sleep() is called between beacons
    def sleeper(d):
        ks.trip("mid-beacon")

    out = run_live(SNAP, cloud, log, planner, token, True, ks, say=quiet, time_scale=0.0, sleep=sleeper)
    assert out["status"] == "killed" and out["teardown_verified"] is True
    assert out["results"][-1]["ok"] is False                      # beacon marked interrupted
