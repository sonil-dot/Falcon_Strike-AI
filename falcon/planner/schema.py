"""Strict schema for LLM output. Anything that doesn't fit is rejected."""
import json
import re
from dataclasses import dataclass, field


class PlanValidationError(Exception):
    pass


ID_RE = re.compile(r"^[a-z0-9_.]{1,64}$")


@dataclass
class Action:
    technique_id: str
    params: dict
    rationale: str


@dataclass
class Campaign:
    actions: list
    seed: int = 0
    raw: str = field(default="", repr=False)


def _strip_fences(s):
    s = s.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    return re.sub(r"\s*```$", "", s)


def parse_campaign(raw, seed=0):
    try:
        data = json.loads(_strip_fences(raw)) if isinstance(raw, str) else raw
    except json.JSONDecodeError as e:
        raise PlanValidationError(f"planner output is not valid JSON: {e}")
    if not isinstance(data, dict) or set(data) != {"actions"}:
        raise PlanValidationError("top level must be exactly {\"actions\": [...]}")
    acts = data["actions"]
    if not isinstance(acts, list) or not 1 <= len(acts) <= 50:
        raise PlanValidationError("actions must be a list of 1..50 items")
    out = []
    for i, a in enumerate(acts):
        if not isinstance(a, dict) or set(a) != {"technique_id", "params", "rationale"}:
            raise PlanValidationError(f"action {i}: keys must be technique_id, params, rationale")
        if not isinstance(a["technique_id"], str) or not ID_RE.match(a["technique_id"]):
            raise PlanValidationError(f"action {i}: bad technique_id")
        if not isinstance(a["params"], dict) or not all(isinstance(k, str) for k in a["params"]):
            raise PlanValidationError(f"action {i}: params must be a flat object")
        if not all(isinstance(v, (str, int, float, bool)) for v in a["params"].values()):
            raise PlanValidationError(f"action {i}: param values must be simple (no nesting)")
        if not isinstance(a["rationale"], str) or len(a["rationale"]) > 500:
            raise PlanValidationError(f"action {i}: rationale must be a string <= 500 chars")
        out.append(Action(a["technique_id"], a["params"], a["rationale"]))
    return Campaign(out, seed, raw if isinstance(raw, str) else json.dumps(raw))
