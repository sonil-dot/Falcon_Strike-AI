"""Read-only collector. Only List/Get/Describe calls. Never writes to AWS.

The allowlist check (preflight) runs BEFORE any enumeration call.
"""
import json

from falcon.guardrails.preflight import preflight

try:
    from botocore.exceptions import ClientError
except ImportError:  # lets tests run without boto3 installed
    class ClientError(Exception):
        pass


def _paginate(client, op, key=None, **kw):
    out = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page[key] if key else [page])
    return out


def collect_iam(iam):
    """get_account_authorization_details returns users, groups, roles, policies
    (including trust policies and attached/inline policies) in one paginated call."""
    snap = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate():
        for k in snap:
            snap[k].extend(page.get(k, []))
    return snap


def collect_exposure(ec2, s3):
    sgs = _paginate(ec2, "describe_security_groups", "SecurityGroups")
    instances = [i for r in _paginate(ec2, "describe_instances", "Reservations")
                 for i in r["Instances"]]
    buckets = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        info = {"Name": name, "PublicAccessBlock": None, "IsPublic": None}
        try:
            info["PublicAccessBlock"] = s3.get_public_access_block(Bucket=name)[
                "PublicAccessBlockConfiguration"]
        except Exception:
            info["PublicAccessBlock"] = None  # none configured
        try:
            info["IsPublic"] = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
        except Exception:
            info["IsPublic"] = False
        buckets.append(info)
    return {"SecurityGroups": sgs, "Instances": instances, "Buckets": buckets}


def collect(session, audit, region=None):
    account = session.client("sts").get_caller_identity()["Account"]
    preflight(account, "dry-run", audit)          # allowlist check first
    audit.append("collect_start", target=account, attack_id="read-only")
    snap = {"account_id": account,
            "iam": collect_iam(session.client("iam")),
            "exposure": collect_exposure(session.client("ec2", region_name=region),
                                         session.client("s3"))}
    audit.append("collect_done", target=account,
                 params={"roles": len(snap["iam"]["RoleDetailList"]),
                         "security_groups": len(snap["exposure"]["SecurityGroups"]),
                         "buckets": len(snap["exposure"]["Buckets"])})
    return snap


def save(snap, path):
    with open(path, "w") as f:
        json.dump(snap, f, indent=2, default=str)  # default=str handles datetimes
