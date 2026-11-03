# Falcon Strike-AI

An autonomous, **safety-first** red-team emulation engine for cloud (AWS-first). It maps the identity/exposure
graph of a *laboratory* account, finds attack paths, has an LLM **plan** (never execute) a campaign from an
approved library of harmless techniques, runs it non-destructively, emulates C2 beacon traffic to a lab-owned
sink, then reports which behaviours a SOC would have **detected, partially detected, or missed**.

> Lab only. The engine refuses any account not on the compiled allowlist (`falcon/config.py`).
> No real exploits, malware, credentials or destructive actions. Everything it creates is torn down and verified.

## Quick start (Windows PowerShell; Linux/macOS similar)
```
cd falcon-strike
pip install -r requirements.txt
python -m pytest -q

python -m falcon.cli paths --top 3                      # ranked attack paths (sample lab data)
python -m falcon.cli run                                # planner + guardrails + DRY-RUN (default, touches nothing)

$env:FALCON_TOKEN_SECRET = "choose-a-secret"            # CMD: set FALCON_TOKEN_SECRET=choose-a-secret
$T = python -m falcon.cli issue-token --account 123456789012 --ttl 600
python -m falcon.cli run --mode live --backend moto --token $T --confirm-live --time-scale 0.2 --report
python scripts/make_evidence.py                         # regenerate all evidence files
```
`--backend fake` needs no extra packages; `--backend moto` uses mock AWS (no AWS account needed);
`--backend aws --profile <lab-profile>` targets a real, dedicated, allowlisted lab account.

## Pipeline
ingest (read-only) -> graph -> ranked attack paths -> LLM planner (JSON only) -> guardrail gate ->
sandboxed live emulation + C2 beacons -> ground-truth IOCs -> detection correlation -> SOC report -> verified teardown.
See `docs/ARCHITECTURE.md` and `docs/architecture.svg`.

## Safety model (enforced in code, with tests)
| Control | Where |
|---|---|
| Account allowlist checked before anything else | `guardrails/preflight.py` |
| Dry-run default; live needs signed expiring token **and** `--confirm-live` | `guardrails/preflight.py`, `token.py` |
| Planner output is untrusted: strict schema + technique allowlist + scope/egress/range checks | `planner/schema.py`, `guardrails/gate.py` |
| Destructive techniques cannot be constructed | `techniques/base.py` |
| Kill switch (`python -m falcon.cli kill`, Ctrl+C) | `guardrails/killswitch.py` |
| Time-box, resource cap, circuit breaker | `live.py` |
| Verified teardown to recorded baseline, even on error/kill | `live.py` |
| Hash-chained append-only audit log; reports refuse a broken chain | `audit/log.py`, `detection/stub.py` |

## Layout
`falcon/` code | `tests/` | `infra/main.tf` (real-lab Terraform) | `samples/` offline lab snapshot |
`scripts/make_evidence.py` | `evidence/` proof from real runs | `docs/` architecture, runbook, schema, write-up
