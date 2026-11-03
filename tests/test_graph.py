import json

from falcon.graph.builder import build_graph
from falcon.graph.paths import find_paths, describe
from falcon.graph import policy as P

A = "123456789012"
ADMIN = f"arn:aws:iam::{A}:role/falcon-lab-wildcard-admin"


def load():
    return build_graph(json.load(open("samples/lab_snapshot.json")))


def test_wildcard_detected():
    g = load()
    assert g.nodes[ADMIN]["is_wildcard"] and g.nodes[ADMIN]["is_high_value"]


def test_attack_chain_found():
    g = load()
    res = find_paths(g)
    top = describe(g, res[0])
    assert top == ("Account 123456789012 (any principal) -> falcon-lab-lowpriv -> "
                   "falcon-lab-deploy -> falcon-lab-wildcard-admin")
    assert res[0]["hops"] == 3


def test_internet_exposure_modelled():
    g = load()
    assert g.has_edge("internet", "sg-0abc")
    assert g.has_edge("internet", f"s3:falcon-lab-public-{A}")


def test_explicit_deny_wins():
    docs = [{"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]},
            {"Statement": [{"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": ADMIN}]}]
    assert P.allows(docs, "sts:AssumeRole", "arn:aws:iam::1:role/x")
    assert not P.allows(docs, "sts:AssumeRole", ADMIN)


def test_privesc_primitive_label():
    docs = [{"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "s3:GetObject"], "Resource": "*"}]}]
    assert P.privesc_primitives(docs) == ["iam:PassRole"]


def test_no_path_when_chain_broken():
    snap = json.load(open("samples/lab_snapshot.json"))
    for r in snap["iam"]["RoleDetailList"]:
        if r["RoleName"] == "falcon-lab-deploy":
            r["RolePolicyList"] = []
            r["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::999:role/nobody"
        if r["RoleName"] == "falcon-lab-wildcard-admin":
            r["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::999:role/nobody"
    assert find_paths(build_graph(snap)) == []
