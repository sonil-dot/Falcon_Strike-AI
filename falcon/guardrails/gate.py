"""Policy gate: EVERY planned campaign must pass before anything runs.
One violation rejects the whole plan. Each rejection is audit-logged."""
from falcon.guardrails.preflight import GuardrailViolation

LAB_SINK_HOSTS = {"127.0.0.1", "localhost"}
MAX_ACTIONS = 10


def check_campaign(campaign, registry, audit, account_id, max_actions=MAX_ACTIONS):
    def block(reason, action=None):
        audit.append("plan_blocked", outcome="blocked", actor="guardrail",
                     technique_id=getattr(action, "technique_id", None),
                     params={"reason": reason})
        raise GuardrailViolation(reason)

    if len(campaign.actions) > max_actions:
        block(f"too many actions ({len(campaign.actions)} > {max_actions})")

    for a in campaign.actions:
        tech = registry.get(a.technique_id)
        if tech is None:
            block(f"technique '{a.technique_id}' is not in the approved library", a)
        if tech.destructive:
            block(f"technique '{a.technique_id}' is destructive", a)

        spec = tech.param_spec
        extra = set(a.params) - set(spec)
        missing = set(spec) - set(a.params)
        if extra or missing:
            block(f"param mismatch for {a.technique_id}: extra={sorted(extra)} missing={sorted(missing)}", a)

        for name, (typ, lo, hi) in spec.items():
            v = a.params[name]
            if isinstance(v, bool) or not isinstance(v, typ):
                block(f"param '{name}' must be {typ.__name__}", a)
            if typ is int and not (lo <= v <= hi):
                block(f"param '{name}'={v} outside allowed range {lo}..{hi}", a)
            if typ is str:
                if "arn:aws:" in v and f":{account_id}:" not in v:      # scope: lab account only
                    block(f"param '{name}' references a resource outside the lab account", a)
                if name == "sink" and v.split(":")[0] not in LAB_SINK_HOSTS:   # egress allowlist
                    block(f"sink '{v}' is not a lab-owned endpoint", a)

    audit.append("plan_approved", actor="guardrail",
                 params={"actions": [a.technique_id for a in campaign.actions]})
    return campaign
