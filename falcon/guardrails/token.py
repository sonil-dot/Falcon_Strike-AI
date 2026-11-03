"""Signed, time-boxed authorisation token (HMAC-SHA256)."""
import base64
import hashlib
import hmac
import json
import time


def issue_token(account_id: str, ttl_seconds: int, secret: str) -> str:
    payload = json.dumps({"account": account_id, "exp": int(time.time()) + ttl_seconds})
    b = base64.urlsafe_b64encode(payload.encode()).decode()
    sig = hmac.new(secret.encode(), b.encode(), hashlib.sha256).hexdigest()
    return f"{b}.{sig}"


def verify_token(token: str, account_id: str, secret: str, now: float = None) -> bool:
    try:
        b, sig = token.split(".")
        expected = hmac.new(secret.encode(), b.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        payload = json.loads(base64.urlsafe_b64decode(b.encode()))
        if payload["account"] != account_id:
            return False
        return (now or time.time()) < payload["exp"]
    except Exception:
        return False
