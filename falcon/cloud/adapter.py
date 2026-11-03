"""Thin cloud interface used by the LIVE runner. Two backends:
  FakeCloud  - pure-Python lab (tests / offline demo)
  Boto3Cloud - real boto3 (works with moto or a real LAB account)
Only the operations the 5 approved techniques need. No credentials are ever returned or logged."""


class CloudError(Exception):
    pass


class FakeCloud:
    def __init__(self, account="123456789012", roles=None, params=None, fail_delete=False):
        self.account = account
        self.roles = dict(roles or {})                # name -> tags
        self.params = dict(params or {"/falcon-lab/marker-secret": "FALCON-MARKER-NOT-A-REAL-SECRET"})
        self.fail_delete = fail_delete
        self.calls = []

    @classmethod
    def from_snapshot(cls, snap, **kw):
        names = [r["RoleName"] for r in snap["iam"]["RoleDetailList"]]
        return cls(snap["account_id"], roles={n: {} for n in names}, **kw)

    def account_id(self): return self.account
    def list_roles(self): self.calls.append("list_roles"); return sorted(self.roles)
    def list_security_groups(self): self.calls.append("list_sgs"); return ["sg-fake"]
    def list_buckets(self): self.calls.append("list_buckets"); return ["falcon-lab-public"]

    def snapshot_state(self):
        return {"roles": sorted(self.roles), "params": sorted(self.params),
                "buckets": ["falcon-lab-public"], "security_groups": ["sg-fake"]}

    def assume_role(self, role_arn):
        self.calls.append(f"assume_role:{role_arn}")
        if role_arn.rsplit("/", 1)[-1] not in self.roles:
            raise CloudError("role not found")
        return {"assumed": role_arn}

    def get_parameter(self, name):
        self.calls.append(f"get_parameter:{name}")
        if name not in self.params:
            raise CloudError("parameter not found")
        return self.params[name]

    def create_role(self, name, run_id):
        self.calls.append(f"create_role:{name}")
        self.roles[name] = {"falcon-run": run_id}

    def delete_role(self, name):
        self.calls.append(f"delete_role:{name}")
        if self.fail_delete:
            raise CloudError("simulated delete failure")
        self.roles.pop(name, None)                    # idempotent


class Boto3Cloud:
    def __init__(self, session, region="us-east-1"):
        self.s = session
        self.iam = session.client("iam")
        self.ssm = session.client("ssm", region_name=region)
        self.sts = session.client("sts")
        self.ec2 = session.client("ec2", region_name=region)
        self.s3 = session.client("s3")

    def account_id(self): return self.sts.get_caller_identity()["Account"]

    def list_roles(self):
        return sorted(r["RoleName"] for p in self.iam.get_paginator("list_roles").paginate()
                      for r in p["Roles"])

    def list_security_groups(self):
        return sorted(g["GroupId"] for p in self.ec2.get_paginator("describe_security_groups").paginate()
                      for g in p["SecurityGroups"])

    def list_buckets(self):
        return sorted(b["Name"] for b in self.s3.list_buckets().get("Buckets", []))

    def _params(self):
        return sorted(p["Name"] for pg in self.ssm.get_paginator("describe_parameters").paginate()
                      for p in pg["Parameters"])

    def snapshot_state(self):
        return {"roles": self.list_roles(), "params": self._params(),
                "buckets": self.list_buckets(), "security_groups": self.list_security_groups()}

    def assume_role(self, role_arn):
        # Short session; credentials are dropped immediately and never logged.
        out = self.sts.assume_role(RoleArn=role_arn, RoleSessionName="falcon-emulation",
                                   DurationSeconds=900)
        return {"assumed": role_arn, "expires": str(out["Credentials"]["Expiration"])}

    def get_parameter(self, name):
        return self.ssm.get_parameter(Name=name)["Parameter"]["Value"]

    def create_role(self, name, run_id):
        import json
        trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole",
            "Principal": {"AWS": f"arn:aws:iam::{self.account_id()}:root"}}]}
        self.iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                             Tags=[{"Key": "falcon-run", "Value": run_id}])

    def delete_role(self, name):
        try:
            self.iam.delete_role(RoleName=name)
        except self.iam.exceptions.NoSuchEntityException:
            pass                                       # idempotent
