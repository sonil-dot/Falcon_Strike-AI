# Falcon Strike-AI: detection-validation report

Run `5bfe1ae34f65` | account 123456789012 | mode live | teardown verified | rules rules_tuned.json

**Detected 5 / partial 0 / missed 0** of 5 techniques | IOC coverage 100.0% | MTTD 81.7 s

## Narrative
Top-ranked attack path: Account 123456789012 (any principal) -> falcon-lab-lowpriv -> falcon-lab-deploy -> falcon-lab-wildcard-admin. The engine emulated an adversary walking this path in account 123456789012 (live mode). Stages executed, in order: T1580 (discovery.cloud_infra); T1098 (privesc.role_chain); T1098 (privesc.role_chain); T1552 (credaccess.marker_secret); T1136 (persist.temp_role); T1071 (c2.https_beacon). All behaviour was non-destructive and reversible; teardown result: verified.

## Per-technique status

| ATT&CK | Technique | Status | TTD (s) |
|---|---|---|---|
| T1580 | discovery.cloud_infra | DETECTED | 42.0 |
| T1098 | privesc.role_chain | DETECTED | 65.0 |
| T1552 | credaccess.marker_secret | DETECTED | 120.0 |
| T1136 | persist.temp_role | DETECTED | 30.0 |
| T1071 | c2.https_beacon | DETECTED | 151.7 |

## Prioritised remediation

| # | Severity | Action |
|---|---|---|
| 1 | Critical | Remove Action:* / Resource:* from role 'falcon-lab-wildcard-admin'; grant least privilege. |
| 2 | High | Tighten trust/permissions so 'falcon-lab-lowpriv' cannot assume 'falcon-lab-deploy' (add conditions: MFA, ExternalId, source). |
| 3 | High | Tighten trust/permissions so 'falcon-lab-deploy' cannot assume 'falcon-lab-wildcard-admin' (add conditions: MFA, ExternalId, source). |
| 4 | High | Tighten trust/permissions so 'falcon-lab-wildcard-admin' cannot assume 'falcon-lab-lowpriv' (add conditions: MFA, ExternalId, source). |
| 5 | High | Enable S3 Block Public Access on 'falcon-lab-public-123456789012'. |
| 6 | Medium | Restrict 0.0.0.0/0 ingress on security group 'falcon-lab-open-sg'. |

_Detection latency is SIMULATED by the detection stub (rule delay_s)._