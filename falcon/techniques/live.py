"""Live (non-destructive, reversible) implementations of the approved techniques.
Each takes (cloud, run, params) and returns {"ok","detail","iocs"}.
Resource creation is RECORDED BEFORE it happens so teardown can always find it."""
from falcon.c2.beacon import MARKER, UA, run_beacons


class CapExceeded(Exception):
    pass


def x_discovery(cloud, run, p):
    r, s, b = cloud.list_roles(), cloud.list_security_groups(), cloud.list_buckets()
    return {"ok": True, "detail": f"enumerated {len(r)} roles, {len(s)} security groups, {len(b)} buckets",
            "iocs": ["api:iam:ListRoles", "api:ec2:DescribeSecurityGroups", "api:s3:ListBuckets"]}


def x_role_chain(cloud, run, p):
    cloud.assume_role(p["to_arn"])                  # session credentials are discarded
    return {"ok": True, "detail": "assumed role (short session, credentials discarded)",
            "iocs": [f"api:sts:AssumeRole to={p['to_arn']}"]}


def x_marker_secret(cloud, run, p):
    v = cloud.get_parameter(p["parameter"])
    if not str(v).startswith("FALCON-MARKER"):
        return {"ok": False, "detail": "value is not a Falcon marker; refusing (value not logged)", "iocs": []}
    return {"ok": True, "detail": "read marker parameter (value verified as marker, not logged)",
            "iocs": [f"api:ssm:GetParameter name={p['parameter']}"]}


def x_temp_role(cloud, run, p):
    if len(run.created) >= run.max_resources:
        raise CapExceeded(f"resource cap {run.max_resources} reached")
    run.created.append(("role", p["role_name"]))     # record BEFORE creating
    cloud.create_role(p["role_name"], run.id)
    return {"ok": True, "detail": "created tagged temp role (will be deleted at teardown)",
            "iocs": [f"api:iam:CreateRole name={p['role_name']}"]}


def x_beacon(cloud, run, p):
    sent = run_beacons(p["sink"], p["interval_s"], p["jitter_pct"], p["beacons"], run.seed, run.id,
                       sleep=run.sleep, should_stop=run.should_stop, time_scale=run.time_scale)
    iocs = [f"net:beacon sink={p['sink']} interval={p['interval_s']}s jitter={p['jitter_pct']}% ua={UA}",
            f"net:marker {MARKER} count={len(sent)}"]
    full = len(sent) == p["beacons"]
    return {"ok": full, "detail": f"sent {len(sent)}/{p['beacons']} inert beacons to lab sink"
            + ("" if full else " (interrupted)"), "iocs": iocs}


LIVE = {
    "discovery.cloud_infra": x_discovery,
    "privesc.role_chain": x_role_chain,
    "credaccess.marker_secret": x_marker_secret,
    "persist.temp_role": x_temp_role,
    "c2.https_beacon": x_beacon,
}
