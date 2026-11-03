import pytest

from falcon.audit.log import AuditLog, verify_chain
from falcon.guardrails.preflight import GuardrailViolation, preflight
from falcon.guardrails.token import issue_token

LAB = "111111111111"
SECRET = "test-secret"
ALLOW = frozenset({LAB})


@pytest.fixture
def log(tmp_path):
    return AuditLog(str(tmp_path / "a.jsonl"), "run1")


def test_out_of_scope_blocked_and_logged(log):
    with pytest.raises(GuardrailViolation):
        preflight("999999999999", "dry-run", log, allowlist=ALLOW)
    assert verify_chain(log.path)[0]
    assert '"preflight_blocked"' in open(log.path).read()


def test_dry_run_ok(log):
    assert preflight(LAB, "dry-run", log, allowlist=ALLOW) == "dry-run"


def test_live_without_token_blocked(log):
    with pytest.raises(GuardrailViolation):
        preflight(LAB, "live", log, allowlist=ALLOW, secret=SECRET, confirm_live=True)


def test_live_without_second_key_blocked(log):
    t = issue_token(LAB, 60, SECRET)
    with pytest.raises(GuardrailViolation):
        preflight(LAB, "live", log, token=t, allowlist=ALLOW, secret=SECRET)


def test_expired_token_blocked(log):
    t = issue_token(LAB, -1, SECRET)
    with pytest.raises(GuardrailViolation):
        preflight(LAB, "live", log, token=t, confirm_live=True, allowlist=ALLOW, secret=SECRET)


def test_token_for_other_account_blocked(log):
    t = issue_token("222222222222", 60, SECRET)
    with pytest.raises(GuardrailViolation):
        preflight(LAB, "live", log, token=t, confirm_live=True, allowlist=ALLOW, secret=SECRET)


def test_live_with_both_keys_ok(log):
    t = issue_token(LAB, 60, SECRET)
    assert preflight(LAB, "live", log, token=t, confirm_live=True,
                     allowlist=ALLOW, secret=SECRET) == "live"
