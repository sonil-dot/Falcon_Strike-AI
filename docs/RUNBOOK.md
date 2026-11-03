 Runbook

 1. Set up
1. `pip install -r requirements.txt`, then `python -m pytest -q` (all tests should pass; the moto test is skipped if moto is absent).
2. Edit `falcon/config.py`: `ALLOWED_ACCOUNT_IDS`. Moto's mock account is `123456789012` (default). For a real lab, put its 12-digit ID.
3. Choose a lab backend:
   - fake: pure-Python lab; no install.
   - moto: mock AWS; `pip install "moto[all]" boto3`; no AWS account.
   - aws: a  dedicated empty AWS account, budget alert set, credentials in a named profile; `cd infra && terraform init && terraform apply`.

2. Dry-run (default, touches nothing)
`python -m falcon.cli run` -> preflight, graph, plan, guardrail gate, simulation. Audit log in `runs/<run_id>.audit.jsonl`.

3. Live run (two keys)
```
set FALCON_TOKEN_SECRET=<secret>
python -m falcon.cli issue-token --account <lab account> --ttl 600     # key 1
python -m falcon.cli run --mode live --backend moto --token <TOKEN> --confirm-live --report   # key 2 = --confirm-live
```
Outputs: console progress, `runs/<id>.audit.jsonl`, `reports/<id>/report.{html,md,json}`.

 4. Kill switch
From any second terminal: `python -m falcon.cli kill`. The run halts before the next action (or mid-beacon), then **teardown runs and is verified**.
Afterwards: `python -m falcon.cli clear-kill`. A stale `KILL` file blocks new live runs on purpose.

 5. Teardown
Automatic after every live run (`teardown: VERIFIED` in the console and `teardown_verify` in the audit log).
If it prints `FAILED`, inspect the diff in the audit log, delete the listed resources by hand, and re-run.
Real lab: `cd infra && terraform destroy` removes the whole lab.

 6. Reports and detection tuning
`python -m falcon.cli report --log runs/<id>.audit.jsonl --rules falcon/detection/rules_tuned.json`
Compare `rules_baseline.json` vs `rules_tuned.json` to show coverage improving over time. Reports refuse a tampered log.

 7. Troubleshooting
| Symptom | Fix |
|---|---|
| pytest scans `C:\WINDOWS\system32` | `cd` into the project folder first |
| `stale kill file` | `python -m falcon.cli clear-kill` |
| `BLOCKED: out-of-scope account` | account not in `falcon/config.py`: working as designed |
| beacon port in use | change the sink port in `MockPlanner(sink=...)` |
