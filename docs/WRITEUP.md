# Final write-up: Falcon Strike-AI

## Results (replace the numbers with those from YOUR runs in `evidence/`)
- Attack path found end-to-end: Account -> falcon-lab-lowpriv -> falcon-lab-deploy -> falcon-lab-wildcard-admin (3 hops).
- Scale: 10,001 nodes / 20,005 edges; p95 path query ~0.26 ms (target < 1 s). See `evidence/perf_report.json`.
- Live emulation: 6 actions, 0 destructive; 4/4 inert beacons received by the lab sink; teardown VERIFIED equal to baseline.
- Safety proofs: blocked out-of-scope account; blocked invented technique / foreign-account ARN / non-lab egress; live blocked without token or second key;
  kill switch halted a run mid-beacon with verified teardown; tampered or truncated audit logs are detected and reports refuse to build.
- Detection validation: baseline rules detected 2 / partial 2 / missed 1 (IOC coverage 66.7%, MTTD ~102 s simulated);
  tuned rules reached 100% coverage. This demonstrates the continuous tune-and-re-test loop.

## Design decisions and trade-offs
1. **Safety first.** Allowlist, two-key live mode, kill switch, caps and verified teardown were built before any emulation.
2. **Model plans, code executes.** LLM output is untrusted data: schema + allowlist + scope/egress checks; a rejected plan runs nothing.
3. **Adapter pattern for the cloud.** A pure-Python fake lab made the safety logic fully testable; boto3/moto verifies the real API path.
4. **NetworkX instead of Neo4j** to fit the time budget; path logic is isolated in `graph/` so a Cypher backend can replace it.
5. **Rules-based detection stub** instead of a live SIEM, with simulated latency; the report reads only ground truth from the log.

## Known limitations (be explicit in review)
- 5 live techniques (not 12-15); remaining ATT&CK techniques are not implemented. Initial Access, Execution and Exfiltration are shown as "not emulated".
- Beacons use plain HTTP to loopback (not TLS); DNS signalling and domain-fronting traffic shapes are not implemented; no TLS fingerprinting.
- Sandbox is the local process plus a loopback sink, not Docker/Kubernetes Jobs; credentials/egress isolation is enforced in code, not by container networking.
- Guardrails are a Python policy module, not OPA/Rego. IAM analysis ignores conditions, permission boundaries and SCPs.
- Detection latency is simulated. Moto is not a full AWS emulation. No dashboard. The LLM planner path (`--planner llm`) is optional and was exercised with canned outputs in tests.

## Future work
Neo4j backend, Docker/K8s runners with network policies, OPA/Rego, TLS + DNS beacons, real SIEM/CloudTrail correlation, Azure/GCP providers, dashboard.
