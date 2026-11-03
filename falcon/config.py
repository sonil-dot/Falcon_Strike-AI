"""Central config. The allowlist is compiled in on purpose: it is not read
from env vars or CLI flags, so it cannot be overridden at runtime."""

# !! Replace with YOUR dedicated lab account ID (12 digits) !!
ALLOWED_ACCOUNT_IDS = frozenset({"123456789012"})

DEFAULT_MODE = "dry-run"
TOKEN_SECRET_ENV = "FALCON_TOKEN_SECRET"
AUDIT_SCHEMA_VERSION = "1.0"
