"""Generates all Day 1-3 evidence from REAL runs into evidence/. Works on Windows/Linux/Mac.
Usage:  python scripts/make_evidence.py            (uses the fake lab; add --backend moto if installed)"""
import glob
import os
import shutil
import subprocess
import sys
import time

BACKEND = "moto" if "--backend" in sys.argv and sys.argv[sys.argv.index("--backend") + 1] == "moto" else "fake"
PY = sys.executable
ENV = dict(os.environ, FALCON_TOKEN_SECRET="evidence-secret", PYTHONIOENCODING="utf-8")
os.makedirs("evidence", exist_ok=True)


def falcon(*args, out=None, bg=False):
    cmd = [PY, "-m", "falcon.cli", *args]
    if bg:
        return subprocess.Popen(cmd, env=ENV, stdout=open(out, "w"), stderr=subprocess.STDOUT)
    r = subprocess.run(cmd, env=ENV, capture_output=True, text=True)
    text = r.stdout + r.stderr
    if out:
        open(out, "w", encoding="utf-8").write(text)
    return text.strip()


def newest_log():
    return max(glob.glob("runs/*.audit.jsonl"), key=os.path.getmtime)


def keep(name):
    shutil.copy(newest_log(), f"evidence/{name}")


if os.path.exists("KILL"):
    os.remove("KILL")
token = falcon("issue-token", "--account", "123456789012", "--ttl", "600")

falcon("run", out="evidence/1_dry_run_valid.txt"); keep("1_dry_run_audit.jsonl")
falcon("run", "--account", "999999999999", out="evidence/2_blocked_out_of_scope.txt"); keep("2_blocked_out_of_scope_audit.jsonl")
falcon("run", "--demo-bad", "unknown_technique", out="evidence/3_blocked_unknown_technique.txt")
falcon("run", "--demo-bad", "bad_sink", out="evidence/4_blocked_non_lab_egress.txt")
falcon("run", "--mode", "live", out="evidence/5_blocked_live_without_token.txt")
live = ["run", "--mode", "live", "--backend", BACKEND, "--token", token, "--confirm-live"]
falcon(*live, "--time-scale", "0.2", "--report", out="evidence/6_live_run_teardown_verified.txt"); keep("6_live_run_audit.jsonl")
rd = max(glob.glob("reports/*/"), key=os.path.getmtime)
for ext in ("html", "md", "json"):
    shutil.copy(os.path.join(rd, f"report.{ext}"), f"evidence/9_soc_report_baseline_rules.{ext}")
falcon("report", "--log", newest_log(), "--rules", "falcon/detection/rules_tuned.json", "--out", "reports/tuned",
       out="evidence/10_report_tuned_console.txt")
for ext in ("html", "md", "json"):
    shutil.copy(f"reports/tuned/report.{ext}", f"evidence/10_soc_report_tuned_rules.{ext}")

p = falcon(*live, "--time-scale", "1.0", out="evidence/7_kill_switch_demo.txt", bg=True)
time.sleep(4.5 if BACKEND == "fake" else 8)
falcon("kill"); p.wait(); keep("7_kill_switch_audit.jsonl")
falcon("clear-kill")
falcon("bench", out="evidence/8_perf_report_console.txt")
print("evidence written to ./evidence:")
for f in sorted(os.listdir("evidence")):
    print("  ", f)
