import json
import os
import socket

import pytest

from falcon.audit.log import AuditLog
from falcon.cloud.adapter import FakeCloud
from falcon.detection.stub import TamperError, correlate, ground_truth, load_rules
from falcon.guardrails.killswitch import KillSwitch
from falcon.guardrails.token import issue_token
from falcon.live import run_live
from falcon.planner.planner import MockPlanner
from falcon.report.generate import build_report, to_html, to_markdown, write_reports

ACCT, SECRET = "123456789012", "report-test-secret"
SNAPFILE = "samples/lab_snapshot.json"
SNAP = json.load(open(SNAPFILE))
RULES = "falcon/detection/"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def live_log(tmp_path):
    os.environ["FALCON_TOKEN_SECRET"] = SECRET
    log = AuditLog(str(tmp_path / "a.jsonl"), "rep-run")
    out = run_live(SNAP, FakeCloud.from_snapshot(SNAP), log, MockPlanner(sink=f"127.0.0.1:{free_port()}"),
                   issue_token(ACCT, 300, SECRET), True, KillSwitch(str(tmp_path / "K")),
                   say=lambda *a: None, time_scale=0.0)
    assert out["status"] == "completed"
    return log.path


def test_baseline_rules_leave_realistic_gaps(tmp_path):
    meta, actions = ground_truth(live_log(tmp_path))
    c = correlate(actions, load_rules(RULES + "rules_baseline.json"))
    st = {t["technique_id"]: t["status"] for t in c["techniques"]}
    assert st["privesc.role_chain"] == "detected"
    assert st["credaccess.marker_secret"] == "detected"
    assert st["discovery.cloud_infra"] == "partial"        # s3:ListBuckets not covered
    assert st["c2.https_beacon"] == "partial"              # marker pattern not covered
    assert st["persist.temp_role"] == "missed"             # no CreateRole rule
    assert c["summary"]["missed"] == 1 and c["summary"]["mttd_s"] > 0


def test_tuned_rules_improve_coverage(tmp_path):
    _, actions = ground_truth(live_log(tmp_path))
    base = correlate(actions, load_rules(RULES + "rules_baseline.json"))["summary"]
    tuned = correlate(actions, load_rules(RULES + "rules_tuned.json"))["summary"]
    assert tuned["ioc_coverage_pct"] == 100.0 and tuned["missed"] == 0
    assert tuned["ioc_coverage_pct"] > base["ioc_coverage_pct"]


def test_ground_truth_refuses_tampered_log(tmp_path):
    p = live_log(tmp_path)
    lines = open(p).read().splitlines()
    i = next(n for n, l in enumerate(lines) if "executed_ok" in l)
    lines[i] = lines[i].replace("executed_ok", "failed")
    open(p, "w").write("\n".join(lines) + "\n")
    with pytest.raises(TamperError):
        ground_truth(p)


def test_ground_truth_refuses_deleted_line(tmp_path):
    p = live_log(tmp_path)
    lines = open(p).read().splitlines()
    del lines[5]
    open(p, "w").write("\n".join(lines) + "\n")
    with pytest.raises(TamperError):
        ground_truth(p)


def test_report_contents_and_outputs(tmp_path):
    p = live_log(tmp_path)
    rep, out = write_reports(p, SNAPFILE, RULES + "rules_baseline.json", str(tmp_path / "rep"))
    for f in ("report.json", "report.html", "report.md"):
        assert os.path.exists(os.path.join(out, f))
    assert rep["run"]["teardown"] == "verified"
    sev = [r["severity"] for r in rep["remediation"]]
    assert sev[0] == "Critical" and sev == sorted(sev, key=["Critical", "High", "Medium"].index)
    assert any("wildcard" in r["action"].lower() or "Action:*" in r["action"] for r in rep["remediation"])
    assert any("Detection gap" in r["action"] for r in rep["remediation"])
    h = open(os.path.join(out, "report.html")).read()
    assert "MISSED" in h and "DETECTED" in h and "not emulated" in h     # heatmap incl. honest gaps
    assert "falcon-lab-wildcard-admin" in rep["narrative"] or "wildcard-admin" in rep["narrative"]


def test_html_escapes_untrusted_text(tmp_path):
    rep = build_report(live_log(tmp_path), SNAPFILE, RULES + "rules_baseline.json")
    rep["narrative"] = "<script>alert(1)</script>"
    rep["remediation"][0]["action"] = "<img src=x onerror=alert(1)>"
    h = to_html(rep)
    assert "<script>alert(1)</script>" not in h and "<img src=x" not in h
    assert "&lt;script&gt;" in h
    assert "MTTD" in to_markdown(rep)


def test_report_is_deterministic(tmp_path):
    p = live_log(tmp_path)
    a = build_report(p, SNAPFILE, RULES + "rules_baseline.json")
    b = build_report(p, SNAPFILE, RULES + "rules_baseline.json")
    assert a == b
