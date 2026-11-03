# Falcon Strike-AI: detection-validation report

Run `5bfe1ae34f65` | account 123456789012 | mode live | teardown verified | rules rules_baseline.json

**Detected 2 / partial 2 / missed 1** of 5 techniques | IOC coverage 66.7% | MTTD 102.2 s

## Narrative
Top-ranked attack path: Account 123456789012 (any principal) -> falcon-lab-lowpriv -> falcon-lab-deploy -> falcon-lab-wildcard-admin. The engine emulated an adversary walking this path in account 123456789012 (live mode). Stages executed, in order: T1580 (discovery.cloud_infra); T1098 (privesc.role_chain); T1098 (privesc.role_chain); T1552 (credaccess.marker_secret); T1136 (persist.temp_role); T1071 (c2.https_beacon). All behaviour was non-destructive and reversible; teardown result: verified.

## Per-technique status

| ATT&CK | Technique | Status | TTD (s) |
|---|---|---|---|
| T1580 | discovery.cloud_infra | PARTIAL | 42.0 |
| T1098 | privesc.role_chain | DETECTED | 65.0 |
| T1552 | credaccess.marker_secret | DETECTED | 120.0 |
| T1136 | persist.temp_role | MISSED | None |
| T1071 | c2.https_beacon | PARTIAL | 181.7 |

## Prioritised remediation

| # | Severity | Action |
|---|---|---|
| 1 | Critical | Remove Action:* / Resource:* from role 'falcon-lab-wildcard-admin'; grant least privilege. |
| 2 | High | Tighten trust/permissions so 'falcon-lab-lowpriv' cannot assume 'falcon-lab-deploy' (add conditions: MFA, ExternalId, source). |
| 3 | High | Tighten trust/permissions so 'falcon-lab-deploy' cannot assume 'falcon-lab-wildcard-admin' (add conditions: MFA, ExternalId, source). |
| 4 | High | Tighten trust/permissions so 'falcon-lab-wildcard-admin' cannot assume 'falcon-lab-lowpriv' (add conditions: MFA, ExternalId, source). |
| 5 | High | Enable S3 Block Public Access on 'falcon-lab-public-123456789012'. |
| 6 | High | Detection gap (missed) for T1136 persist.temp_role: Alert on iam:CreateRole/CreateUser outside an approved change window or by non-pipeline principals. |
| 7 | Medium | Restrict 0.0.0.0/0 ingress on security group 'falcon-lab-open-sg'. |
| 8 | Medium | Detection gap (partial) for T1580 discovery.cloud_infra: Alert on bursts of List*/Describe* API calls from a single principal (incl. s3:ListBuckets). |
| 9 | Medium | Detection gap (partial) for T1071 c2.https_beacon: Alert on fixed-interval outbound callbacks (low timing variance) and on the beacon payload pattern. |

_Detection latency is SIMULATED by the detection stub (rule delay_s)._