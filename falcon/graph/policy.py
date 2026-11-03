"""Tiny IAM policy helpers (enough for sts:AssumeRole + wildcard detection).
Known limitation: conditions, permission boundaries and SCPs are not evaluated."""
from fnmatch import fnmatchcase

PRIVESC_PRIMITIVES = {
    "iam:passrole", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachrolepolicy", "iam:putrolepolicy", "iam:attachuserpolicy",
    "iam:createaccesskey", "iam:updateassumerolepolicy", "iam:createloginprofile",
}


def _as_list(x):
    return x if isinstance(x, list) else [x]


def statements(doc):
    return _as_list(doc.get("Statement", [])) if doc else []


def _match(patterns, value):
    return any(fnmatchcase(value.lower(), p.lower()) for p in _as_list(patterns))


def allows(docs, action, resource):
    """True if some Allow matches and no Deny matches (explicit deny wins)."""
    allowed = False
    for doc in docs:
        for st in statements(doc):
            acts = st.get("Action") or []
            ress = st.get("Resource") or []
            if not (_match(acts, action) and _match(ress, resource)):
                continue
            if st.get("Effect") == "Deny":
                return False
            if st.get("Effect") == "Allow":
                allowed = True
    return allowed


def is_wildcard(docs):
    for doc in docs:
        for st in statements(doc):
            if st.get("Effect") == "Allow" and "*" in _as_list(st.get("Action", [])) \
                    and "*" in _as_list(st.get("Resource", [])):
                return True
    return False


def privesc_primitives(docs):
    found = set()
    for doc in docs:
        for st in statements(doc):
            if st.get("Effect") != "Allow":
                continue
            for a in _as_list(st.get("Action", [])):
                if a.lower() in PRIVESC_PRIMITIVES:
                    found.add(a)
    return sorted(found)


def trusted_principals(trust_doc):
    out = []
    for st in statements(trust_doc):
        if st.get("Effect") == "Allow":
            p = st.get("Principal", {})
            if p == "*":
                out.append("*")
            elif isinstance(p, dict):
                out.extend(_as_list(p.get("AWS", [])))
    return out
