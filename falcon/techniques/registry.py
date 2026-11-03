"""The approved (allowlisted) technique library. Day 2 = dry-run simulation only.
Nothing here calls AWS. Live versions arrive on Day 3 behind the same contracts."""
from falcon.techniques.base import Technique

LAB_SINK_HOSTS = {"127.0.0.1", "localhost"}        # egress allowlist (lab-owned only)


def _edge(ctx, a, b):
    return ctx.graph.has_edge(a, b) and any(
        d.get("type") == "CAN_ASSUME" for d in ctx.graph[a][b].values())


def sim_discovery(ctx, p):
    roles = sum(1 for _, d in ctx.graph.nodes(data=True) if d.get("type") == "Role")
    return {"ok": True, "detail": f"would enumerate {roles} roles + security groups (read-only)",
            "iocs": ["api:iam:ListRoles", "api:ec2:DescribeSecurityGroups", "api:s3:ListBuckets"]}


def sim_role_chain(ctx, p):
    if not _edge(ctx, p["from_arn"], p["to_arn"]):
        return {"ok": False, "detail": "precondition failed: no CAN_ASSUME edge in graph", "iocs": []}
    return {"ok": True, "detail": "would call sts:AssumeRole along an existing graph edge",
            "iocs": [f"api:sts:AssumeRole to={p['to_arn']}"]}


def sim_marker_secret(ctx, p):
    if not p["parameter"].startswith("/falcon-lab/"):
        return {"ok": False, "detail": "only /falcon-lab/ marker parameters allowed", "iocs": []}
    return {"ok": True, "detail": "would read a planted marker parameter",
            "iocs": [f"api:ssm:GetParameter name={p['parameter']}"]}


def sim_temp_role(ctx, p):
    if not p["role_name"].startswith("falcon-run-"):
        return {"ok": False, "detail": "role name must start with falcon-run-", "iocs": []}
    return {"ok": True, "detail": "would create a tagged, benign, auto-removed role",
            "iocs": [f"api:iam:CreateRole name={p['role_name']}"]}


def sim_beacon(ctx, p):
    return {"ok": True, "detail": f"would send {p['beacons']} jittered HTTPS beacons to lab sink",
            "iocs": [f"net:https-beacon sink={p['sink']} interval={p['interval_s']}s jitter={p['jitter_pct']}%"]}


REGISTRY = {t.id: t for t in [
    Technique("discovery.cloud_infra", "T1580", "Cloud Infrastructure Discovery", "Discovery",
              ["valid lab credentials"], "Read-only list/describe calls",
              ["IAM/EC2/S3 enumeration burst"], "nothing created",
              {"scope": (str, None, None)}, sim_discovery),
    Technique("privesc.role_chain", "T1098", "Role chaining via AssumeRole", "Privilege Escalation",
              ["CAN_ASSUME edge from -> to"], "Assume a higher-privilege lab role",
              ["sts:AssumeRole chain"], "temporary session expires; nothing persisted",
              {"from_arn": (str, None, None), "to_arn": (str, None, None)}, sim_role_chain),
    Technique("credaccess.marker_secret", "T1552", "Unsecured Credentials (marker only)", "Credential Access",
              ["planted marker parameter exists"], "Read a clearly-marked fake secret",
              ["ssm:GetParameter on marker"], "nothing created",
              {"parameter": (str, None, None)}, sim_marker_secret),
    Technique("persist.temp_role", "T1136", "Create Account (tagged temp role)", "Persistence",
              ["iam:CreateRole in lab"], "Create a benign, tagged, auto-expiring role",
              ["iam:CreateRole"], "role deleted + deletion verified at teardown",
              {"role_name": (str, None, None)}, sim_temp_role),
    Technique("c2.https_beacon", "T1071", "Application Layer Protocol (beacon)", "Command and Control",
              ["lab sink reachable"], "Jittered HTTPS beacons with inert marker payload to lab sink",
              ["periodic callbacks, jittered timing"], "sink container stopped",
              {"sink": (str, None, None), "interval_s": (int, 1, 60),
               "jitter_pct": (int, 0, 50), "beacons": (int, 1, 20)}, sim_beacon),
]}
