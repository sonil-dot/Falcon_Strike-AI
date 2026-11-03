import pytest

from falcon.audit.log import AuditLog, verify_chain
from falcon.collectors import aws_collector as ac
from falcon.guardrails.preflight import GuardrailViolation
import falcon.guardrails.preflight as pf


class FakePaginator:
    def __init__(self, pages): self.pages = pages
    def paginate(self, **kw): return iter(self.pages)


class FakeClient:
    def __init__(self, account="111111111111"): self.account = account; self.calls = []
    def get_caller_identity(self): return {"Account": self.account}
    def get_paginator(self, op):
        self.calls.append(op)
        data = {
            "get_account_authorization_details": [{"RoleDetailList": [{"RoleName": "r1"}]}],
            "describe_security_groups": [{"SecurityGroups": [{"GroupId": "sg-1"}]}],
            "describe_instances": [{"Reservations": []}],
        }
        return FakePaginator(data[op])
    def list_buckets(self): return {"Buckets": [{"Name": "b1"}]}
    def get_public_access_block(self, Bucket):
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}
    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": True}}


class FakeSession:
    def __init__(self, account): self.c = FakeClient(account)
    def client(self, name, **kw): return self.c


def test_collect_in_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(pf, "ALLOWED_ACCOUNT_IDS", frozenset({"111111111111"}))
    import functools
    # preflight default arg binds at import; patch via wrapper
    monkeypatch.setattr(ac, "preflight",
        functools.partial(pf.preflight, allowlist=frozenset({"111111111111"})))
    log = AuditLog(str(tmp_path / "a.jsonl"), "r")
    snap = ac.collect(FakeSession("111111111111"), log)
    assert snap["iam"]["RoleDetailList"][0]["RoleName"] == "r1"
    assert snap["exposure"]["Buckets"][0]["IsPublic"] is True
    assert verify_chain(log.path)[0]


def test_collect_out_of_scope_blocks_before_enumeration(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"), "r")
    sess = FakeSession("999999999999")
    with pytest.raises(GuardrailViolation):
        ac.collect(sess, log)
    assert sess.c.calls == []   # NO enumeration calls were made
