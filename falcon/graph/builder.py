"""Turn a collector snapshot into a property graph (NetworkX MultiDiGraph).

Nodes: Internet, Account, Role, User, Endpoint (public security group),
       Instance, Resource (bucket)
Edges: CAN_ASSUME, EXPOSES, BOUND_TO
"""
import networkx as nx

from falcon.graph import policy as P

INTERNET = "internet"


def _managed_docs(role, managed_index):
    docs = []
    for ap in role.get("AttachedManagedPolicies", []):
        d = managed_index.get(ap["PolicyArn"])
        if d:
            docs.append(d)
    return docs


def _index_managed(policies):
    idx = {}
    for pol in policies:
        for v in pol.get("PolicyVersionList", []):
            if v.get("IsDefaultVersion"):
                idx[pol["Arn"]] = v["Document"]
    return idx


def _identity_docs(item, managed_index):
    inline = [p["PolicyDocument"] for p in item.get("RolePolicyList", item.get("UserPolicyList", []))]
    return inline + _managed_docs(item, managed_index)


def build_graph(snap):
    g = nx.MultiDiGraph()
    acct = snap["account_id"]
    root = f"arn:aws:iam::{acct}:root"
    managed = _index_managed(snap["iam"].get("Policies", []))

    g.add_node(INTERNET, type="Internet", name="Internet")
    g.add_node(root, type="Account", name=f"Account {acct} (any principal)")

    identities = {}   # arn -> (node type, docs)
    for r in snap["iam"]["RoleDetailList"]:
        docs = _identity_docs(r, managed)
        g.add_node(r["Arn"], type="Role", name=r["RoleName"],
                   is_wildcard=P.is_wildcard(docs),
                   privesc_primitive=P.privesc_primitives(docs),
                   is_high_value=P.is_wildcard(docs))
        identities[r["Arn"]] = docs
    for u in snap["iam"].get("UserDetailList", []):
        docs = _identity_docs(u, managed)
        g.add_node(u["Arn"], type="User", name=u["UserName"],
                   is_wildcard=P.is_wildcard(docs),
                   privesc_primitive=P.privesc_primitives(docs),
                   is_high_value=P.is_wildcard(docs))
        identities[u["Arn"]] = docs

    # CAN_ASSUME: trust policy must allow the caller; for account-root trust
    # (or wildcard) the caller's own identity policy must also allow it.
    for r in snap["iam"]["RoleDetailList"]:
        target = r["Arn"]
        for trusted in P.trusted_principals(r.get("AssumeRolePolicyDocument")):
            if trusted in identities:                       # specific principal
                g.add_edge(trusted, target, type="CAN_ASSUME", via="trust-policy")
            elif trusted == root or trusted == "*":         # whole account
                g.add_edge(root, target, type="CAN_ASSUME", via="account-root trust")
                for arn, docs in identities.items():
                    if arn != target and P.allows(docs, "sts:AssumeRole", target):
                        g.add_edge(arn, target, type="CAN_ASSUME", via="identity+root trust")

    # Exposure: public security groups -> instances -> bound roles
    profile_to_role = {}
    for r in snap["iam"]["RoleDetailList"]:
        for ip in r.get("InstanceProfileList", []):
            profile_to_role[ip["Arn"]] = r["Arn"]
    public_sgs = set()
    for sg in snap["exposure"]["SecurityGroups"]:
        open_ports = [(p.get("FromPort"), p.get("ToPort")) for p in sg.get("IpPermissions", [])
                      if any(c.get("CidrIp") == "0.0.0.0/0" for c in p.get("IpRanges", []))]
        if open_ports:
            public_sgs.add(sg["GroupId"])
            g.add_node(sg["GroupId"], type="Endpoint", name=sg.get("GroupName", sg["GroupId"]),
                       is_public=True, open_ports=open_ports)
            g.add_edge(INTERNET, sg["GroupId"], type="EXPOSES")
    for inst in snap["exposure"].get("Instances", []):
        iid = inst["InstanceId"]
        g.add_node(iid, type="Instance", name=iid)
        for sg in inst.get("SecurityGroups", []):
            if sg["GroupId"] in public_sgs:
                g.add_edge(sg["GroupId"], iid, type="EXPOSES")
        arn = (inst.get("IamInstanceProfile") or {}).get("Arn")
        if arn in profile_to_role:
            g.add_edge(iid, profile_to_role[arn], type="BOUND_TO")
    for b in snap["exposure"].get("Buckets", []):
        g.add_node(f"s3:{b['Name']}", type="Resource", name=b["Name"],
                   is_public=bool(b.get("IsPublic")), is_high_value=False)
        if b.get("IsPublic"):
            g.add_edge(INTERNET, f"s3:{b['Name']}", type="EXPOSES")
    return g
