"""Runs the REAL boto3 code paths (collector + live adapter) against moto's mock AWS.
Skipped automatically if moto/boto3 are not installed."""
import os

import pytest

moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")

from falcon.audit.log import AuditLog, verify_chain
from falcon.cloud.adapter import Boto3Cloud
from falcon.collectors.aws_collector import collect
from falcon.guardrails.killswitch import KillSwitch
from falcon.guardrails.token import issue_token
from falcon.lab.moto_lab import seed
from falcon.live import run_live
from falcon.planner.planner import MockPlanner

SECRET = "moto-test-secret"


def test_end_to_end_on_moto(tmp_path):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "us-east-1", "FALCON_TOKEN_SECRET": SECRET}.items():
        os.environ[k] = v
    os.environ.pop("AWS_PROFILE", None)
    with moto.mock_aws():
        session = boto3.Session(region_name="us-east-1")
        seed(session)
        log = AuditLog(str(tmp_path / "a.jsonl"), "moto-run")
        snap = collect(session, log, region="us-east-1")            # real collector code
        assert len(snap["iam"]["RoleDetailList"]) == 3
        cloud = Boto3Cloud(session)
        before = cloud.snapshot_state()
        out = run_live(snap, cloud, log, MockPlanner(sink="127.0.0.1:18443"),
                       issue_token("123456789012", 120, SECRET), True,
                       KillSwitch(str(tmp_path / "KILL")), say=lambda *a: None, time_scale=0.0)
        assert out["status"] == "completed" and out["teardown_verified"] is True
        assert cloud.snapshot_state() == before                      # baseline restored
        assert verify_chain(log.path)[0]
