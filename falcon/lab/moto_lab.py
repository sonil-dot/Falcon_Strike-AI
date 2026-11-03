"""Seeds a MOCK AWS (moto) with the same 5 deliberate weaknesses as infra/main.tf.
Only ever call this inside moto's mock_aws() - it refuses to run otherwise."""
import json

ACCT = "123456789012"


def _trust(principal):
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": principal}}]})


def _allow(action, resource):
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": action, "Resource": resource}]})


def seed(session):
    sts = session.client("sts")
    acct = sts.get_caller_identity()["Account"]
    if acct != ACCT:                                       # moto's default account
        raise RuntimeError(f"refusing to seed: account {acct} is not the moto mock account")
    iam = session.client("iam")
    arn = lambda n: f"arn:aws:iam::{acct}:role/{n}"
    iam.create_role(RoleName="falcon-lab-lowpriv", AssumeRolePolicyDocument=_trust(f"arn:aws:iam::{acct}:root"))
    iam.create_role(RoleName="falcon-lab-deploy", AssumeRolePolicyDocument=_trust(arn("falcon-lab-lowpriv")))
    iam.create_role(RoleName="falcon-lab-wildcard-admin", AssumeRolePolicyDocument=_trust(arn("falcon-lab-deploy")))
    iam.put_role_policy(RoleName="falcon-lab-lowpriv", PolicyName="assume-deploy",
                        PolicyDocument=_allow("sts:AssumeRole", arn("falcon-lab-deploy")))
    iam.put_role_policy(RoleName="falcon-lab-deploy", PolicyName="assume-admin",
                        PolicyDocument=_allow("sts:AssumeRole", arn("falcon-lab-wildcard-admin")))
    iam.put_role_policy(RoleName="falcon-lab-wildcard-admin", PolicyName="wildcard-all",
                        PolicyDocument=_allow("*", "*"))

    s3 = session.client("s3", region_name="us-east-1")
    bucket = f"falcon-lab-public-{acct}"
    s3.create_bucket(Bucket=bucket)
    s3.put_object(Bucket=bucket, Key="FALCON-MARKER.txt", Body=b"FALCON-LAB-MARKER: not real data")
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]}))

    ec2 = session.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="falcon-lab-open-sg", Description="Lab: SSH open to world")
    ec2.authorize_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    ssm = session.client("ssm", region_name="us-east-1")
    ssm.put_parameter(Name="/falcon-lab/marker-secret", Value="FALCON-MARKER-NOT-A-REAL-SECRET", Type="String")
