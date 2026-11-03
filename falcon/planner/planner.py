"""The planner PROPOSES; it never executes. Output is untrusted data that must
pass schema validation and the guardrail gate."""
import json
import os

from falcon.planner.schema import parse_campaign
from falcon.techniques.registry import REGISTRY

SYSTEM = ("You are a red-team campaign planner for a detection-validation lab. "
          "Reply with JSON only, no prose. Use ONLY technique_ids from the catalog. "
          "You cannot run anything; you only propose an ordered list.")


def path_facts(g, path):
    return [{"arn": n, "name": g.nodes[n].get("name", n), "type": g.nodes[n].get("type")} for n in path]


def build_prompt(facts):
    catalog = [{"technique_id": t.id, "attack_id": t.attack_id, "tactic": t.tactic,
                "params": {k: v[0].__name__ for k, v in t.param_spec.items()}}
               for t in REGISTRY.values()]
    return json.dumps({
        "task": "Plan an ordered multi-stage campaign that walks this attack path.",
        "attack_path": facts, "catalog": catalog,
        "sink_must_be": "127.0.0.1:8443",
        "output_schema": {"actions": [{"technique_id": "str", "params": {"...": "..."},
                                       "rationale": "str <=500 chars"}]},
    }, indent=2)


class MockPlanner:
    """Deterministic, offline. Gives the same plan every time (reproducible)."""
    name = "mock"

    def __init__(self, sink="127.0.0.1:8443"):
        self.sink = sink

    def plan(self, g, path, seed=0):
        acts = [{"technique_id": "discovery.cloud_infra", "params": {"scope": "account"},
                 "rationale": "Enumerate the environment first."}]
        for a, b in zip(path, path[1:]):
            if g.nodes[a].get("type") == "Role" and g.nodes[b].get("type") == "Role":
                acts.append({"technique_id": "privesc.role_chain",
                             "params": {"from_arn": a, "to_arn": b},
                             "rationale": f"Chain from {g.nodes[a]['name']} to {g.nodes[b]['name']}."})
        acts += [
            {"technique_id": "credaccess.marker_secret", "params": {"parameter": "/falcon-lab/marker-secret"},
             "rationale": "Access the planted marker secret."},
            {"technique_id": "persist.temp_role", "params": {"role_name": f"falcon-run-{seed}"},
             "rationale": "Emulate persistence with a benign tagged role."},
            {"technique_id": "c2.https_beacon",
             "params": {"sink": self.sink, "interval_s": 2, "jitter_pct": 20, "beacons": 4},
             "rationale": "Emulate C2 beaconing to the lab sink."},
        ]
        return parse_campaign({"actions": acts}, seed)


class LLMPlanner:
    """`call_llm(system, prompt) -> str`. Output is parsed as untrusted data."""
    def __init__(self, call_llm, name="llm"):
        self.call_llm, self.name = call_llm, name

    def plan(self, g, path, seed=0):
        raw = self.call_llm(SYSTEM, build_prompt(path_facts(g, path)))
        return parse_campaign(raw, seed)


def anthropic_call(system, prompt):
    import anthropic                                   # needs ANTHROPIC_API_KEY in env
    client = anthropic.Anthropic()
    msg = client.messages.create(model=os.environ.get("FALCON_LLM_MODEL", "claude-sonnet-5-5"),
                                 max_tokens=1500, system=system,
                                 messages=[{"role": "user", "content": prompt}])
    return "".join(b.text for b in msg.content if b.type == "text")


# Canned "unsafe" planner outputs used to PROVE the guardrails block bad plans.
BAD_PLANS = {
    "unknown_technique": {"actions": [{"technique_id": "exploit.delete_bucket", "params": {},
                                       "rationale": "invented technique"}]},
    "foreign_account": {"actions": [{"technique_id": "privesc.role_chain",
        "params": {"from_arn": "arn:aws:iam::999999999999:role/x", "to_arn": "arn:aws:iam::999999999999:role/y"},
        "rationale": "targets another account"}]},
    "bad_sink": {"actions": [{"technique_id": "c2.https_beacon",
        "params": {"sink": "evil.example.com:443", "interval_s": 5, "jitter_pct": 10, "beacons": 3},
        "rationale": "non-lab egress"}]},
}
