"""Runs BEFORE any other logic. Every refusal is written to the audit log."""
import os

from falcon.config import ALLOWED_ACCOUNT_IDS, TOKEN_SECRET_ENV
from falcon.guardrails.token import verify_token


class GuardrailViolation(Exception):
    pass


def preflight(account_id, mode, audit, token=None, confirm_live=False,
              allowlist=ALLOWED_ACCOUNT_IDS, secret=None):
    def block(reason):
        audit.append("preflight_blocked", outcome="blocked",
                     params={"reason": reason, "account": account_id, "mode": mode})
        raise GuardrailViolation(reason)

    # 1. Allowlist check is ALWAYS first.
    if account_id not in allowlist:
        block("out-of-scope account (not on allowlist)")
    if mode not in ("dry-run", "live"):
        block(f"invalid mode: {mode}")

    # 2. Live mode needs a valid token AND a second confirmation (two-key).
    if mode == "live":
        secret = secret or os.environ.get(TOKEN_SECRET_ENV)
        if not secret or not token or not verify_token(token, account_id, secret):
            block("missing, invalid or expired authorisation token")
        if not confirm_live:
            block("second confirmation (--confirm-live) missing")

    audit.append("preflight_passed", params={"account": account_id, "mode": mode})
    return mode
