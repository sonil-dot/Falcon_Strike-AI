"""SOC detection-validation report: JSON + HTML + Markdown from the audit log (+ snapshot for context)."""
import html
import json
import os

from falcon.detection.stub import correlate, ground_truth, load_rules
from falcon.graph.builder import build_graph
from falcon.graph.paths import find_paths
from falcon.techniques.registry import REGISTRY

TACTICS = ["Initial Access", "Execution", "Discovery", "Privilege Escalation", "Persistence",
           "Credential Access", "Command and Control", "Exfiltration"]
DETECTION_FIX = {
    "discovery.cloud_infra": "Alert on bursts of List*/Describe* API calls from a single principal (incl. s3:ListBuckets).",
    "privesc.role_chain": "Alert on chained sts:AssumeRole (role-to-role) and on first-time role assumptions.",
    "credaccess.marker_secret": "Alert on ssm:GetParameter/secretsmanager:GetSecretValue by principals that do not normally read them.",
    "persist.temp_role": "Alert on iam:CreateRole/CreateUser outside an approved change window or by non-pipeline principals.",
    "c2.https_beacon": "Alert on fixed-interval outbound callbacks (low timing variance) and on the beacon payload pattern.",
}
SEV = {"Critical": 0, "High": 1, "Medium": 2}


def remediation(snap, corr):
    g = build_graph(snap)
    items = []
    for n, d in g.nodes(data=True):
        if d.get("is_wildcard"):
            items.append(("Critical", f"Remove Action:* / Resource:* from role '{d['name']}'; grant least privilege."))
    for a, b, d in g.edges(data=True):
        if d.get("type") == "CAN_ASSUME" and g.nodes[a].get("type") == "Role":
            items.append(("High", f"Tighten trust/permissions so '{g.nodes[a]['name']}' cannot assume "
                                  f"'{g.nodes[b]['name']}' (add conditions: MFA, ExternalId, source)."))
    for n, d in g.nodes(data=True):
        if d.get("type") == "Resource" and d.get("is_public"):
            items.append(("High", f"Enable S3 Block Public Access on '{d['name']}'."))
        if d.get("type") == "Endpoint" and d.get("is_public"):
            items.append(("Medium", f"Restrict 0.0.0.0/0 ingress on security group '{d['name']}'."))
    for t in corr["techniques"]:
        if t["status"] in ("missed", "partial"):
            items.append(("High" if t["status"] == "missed" else "Medium",
                          f"Detection gap ({t['status']}) for {t['attack_id']} {t['technique_id']}: "
                          f"{DETECTION_FIX.get(t['technique_id'], 'add a detection rule')}"))
    seen, out = set(), []
    for sev, text in sorted(items, key=lambda x: SEV[x[0]]):
        if text not in seen:
            seen.add(text)
            out.append({"priority": len(out) + 1, "severity": sev, "action": text})
    return out


def narrative(meta, snap, actions):
    steps = "; ".join(f"{a['attack_id']} ({a['technique_id']})" for a in actions)
    return (f"Top-ranked attack path: {meta.get('top_path', 'n/a')}. The engine emulated an adversary walking "
            f"this path in account {meta.get('account')} ({meta.get('mode')} mode). Stages executed, in order: {steps}. "
            f"All behaviour was non-destructive and reversible; teardown result: {meta.get('teardown')}.")


def build_report(log_path, snapshot_path, rules_path):
    meta, actions = ground_truth(log_path)
    snap = json.load(open(snapshot_path))
    corr = correlate(actions, load_rules(rules_path))
    return {"schema": "falcon-report/1.0", "run": meta, "rules_file": os.path.basename(rules_path),
            "latency_note": "Detection latency is SIMULATED by the detection stub (rule delay_s).",
            "narrative": narrative(meta, snap, actions), "detection": corr,
            "remediation": remediation(snap, corr)}


COLORS = {"detected": "#1b8a3b", "partial": "#c98a00", "missed": "#c62828", "not_run": "#8a8f98", "n/a": "#d9dce1"}


def _heatmap(rep):
    by_id = {t["technique_id"]: t for t in rep["detection"]["techniques"]}
    cols = []
    for tac in TACTICS:
        cells = []
        for t in REGISTRY.values():
            if t.tactic == tac:
                st = by_id.get(t.id, {}).get("status", "not_run")
                cells.append(f'<div class="cell" style="background:{COLORS[st]}">{html.escape(t.attack_id)}<br>'
                             f'<small>{html.escape(t.name)}</small><br><b>{st.upper()}</b></div>')
        if not cells:
            cells.append(f'<div class="cell" style="background:{COLORS["n/a"]};color:#444">not emulated<br>'
                         f'<small>(no module in this version)</small></div>')
        cols.append(f'<div class="col"><h4>{html.escape(tac)}</h4>{"".join(cells)}</div>')
    return f'<div class="grid">{"".join(cols)}</div>'


def to_html(rep):
    e, s = html.escape, rep["detection"]["summary"]
    rows = "".join(
        f"<tr><td>{e(t['attack_id'])}</td><td>{e(t['technique_id'])}</td>"
        f"<td style='color:{COLORS[t['status']]};font-weight:700'>{t['status'].upper()}</td>"
        f"<td>{'' if t['ttd_s'] is None else str(t['ttd_s']) + ' s'}</td>"
        f"<td>{'<br>'.join(e(i['ioc']) + ' &rarr; ' + (e(i['rule']) if i['rule'] else '<b>no rule</b>') for i in t['iocs'])}</td></tr>"
        for t in rep["detection"]["techniques"])
    rem = "".join(f"<tr><td>{r['priority']}</td><td>{e(r['severity'])}</td><td>{e(r['action'])}</td></tr>"
                  for r in rep["remediation"])
    m = rep["run"]
    mttd = "n/a" if s["mttd_s"] is None else f"{s['mttd_s']} s"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Falcon Strike-AI SOC report {e(str(m.get('run_id')))}</title>
<style>
:root{{--bg:#fff;--fg:#1d2330;--mut:#5b6472;--line:#d9dce1}}
@media (prefers-color-scheme:dark){{:root{{--bg:#14171d;--fg:#e8eaee;--mut:#9aa3b2;--line:#2c313b}}}}
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--fg);max-width:1100px;margin:24px auto;padding:0 16px;line-height:1.5}}
h1{{margin-bottom:0}} .mut{{color:var(--mut)}} table{{border-collapse:collapse;width:100%;margin:8px 0 24px}}
td,th{{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;font-size:14px}}
.kpis{{display:flex;gap:12px;flex-wrap:wrap}} .kpi{{border:1px solid var(--line);border-radius:8px;padding:10px 16px}}
.kpi b{{display:block;font-size:24px}} .grid{{display:flex;gap:8px;overflow-x:auto;margin:8px 0 24px}}
.col{{min-width:140px;flex:1}} .col h4{{margin:0 0 6px;font-size:12px;color:var(--mut)}}
.cell{{color:#fff;border-radius:6px;padding:8px;margin-bottom:6px;font-size:13px}}
</style></head><body>
<h1>Falcon Strike-AI: detection-validation report</h1>
<p class="mut">Run {e(str(m.get('run_id')))} &middot; account {e(str(m.get('account')))} &middot; mode {e(str(m.get('mode')))}
&middot; status {e(str(m.get('status')))} &middot; teardown {e(str(m.get('teardown')))} &middot; rules {e(rep['rules_file'])}</p>
<div class="kpis"><div class="kpi">Techniques<b>{s['techniques_total']}</b></div>
<div class="kpi">Detected<b style="color:{COLORS['detected']}">{s['detected']}</b></div>
<div class="kpi">Partial<b style="color:{COLORS['partial']}">{s['partial']}</b></div>
<div class="kpi">Missed<b style="color:{COLORS['missed']}">{s['missed']}</b></div>
<div class="kpi">IOC coverage<b>{s['ioc_coverage_pct']}%</b></div><div class="kpi">MTTD<b>{mttd}</b></div></div>
<h2>Attack-path narrative</h2><p>{e(rep['narrative'])}</p>
<h2>ATT&amp;CK coverage heatmap</h2>{_heatmap(rep)}
<h2>Per-technique detection status</h2>
<table><tr><th>ATT&amp;CK</th><th>Technique</th><th>Status</th><th>Time to detect</th><th>Ground-truth IOCs &rarr; rule</th></tr>{rows}</table>
<h2>Prioritised remediation</h2><table><tr><th>#</th><th>Severity</th><th>Action</th></tr>{rem}</table>
<p class="mut">{e(rep['latency_note'])} Emulation was non-destructive; every action is in the hash-chained audit log.</p>
</body></html>"""


def to_markdown(rep):
    s, m = rep["detection"]["summary"], rep["run"]
    L = [f"# Falcon Strike-AI: detection-validation report", "",
         f"Run `{m.get('run_id')}` | account {m.get('account')} | mode {m.get('mode')} | teardown {m.get('teardown')} | rules {rep['rules_file']}", "",
         f"**Detected {s['detected']} / partial {s['partial']} / missed {s['missed']}** of {s['techniques_total']} techniques "
         f"| IOC coverage {s['ioc_coverage_pct']}% | MTTD {s['mttd_s']} s", "", "## Narrative", rep["narrative"], "",
         "## Per-technique status", "", "| ATT&CK | Technique | Status | TTD (s) |", "|---|---|---|---|"]
    L += [f"| {t['attack_id']} | {t['technique_id']} | {t['status'].upper()} | {t['ttd_s']} |" for t in rep["detection"]["techniques"]]
    L += ["", "## Prioritised remediation", "", "| # | Severity | Action |", "|---|---|---|"]
    L += [f"| {r['priority']} | {r['severity']} | {r['action']} |" for r in rep["remediation"]]
    L += ["", f"_{rep['latency_note']}_"]
    return "\n".join(L)


def write_reports(log_path, snapshot_path, rules_path, out_dir):
    rep = build_report(log_path, snapshot_path, rules_path)
    os.makedirs(out_dir, exist_ok=True)
    json.dump(rep, open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8"), indent=2)
    open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8").write(to_html(rep))
    open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8").write(to_markdown(rep))
    return rep, out_dir
