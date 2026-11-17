#!/usr/bin/env python3
"""
Live dashboard for netshield-ai. Serves one auto-refreshing HTML page that
polls live_state.json (written by simple_switch.py every second) and lets
you trigger attacks / manual clearance by writing to the trigger files the
controller and topology watchers are already watching for.

Run separately from the controller and topology:
    python3 dashboard_server.py
Then open http://localhost:5000 in your browser.
"""
import json
import os
import time
from collections import defaultdict
from flask import Flask, jsonify, request, Response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LIVE_STATE_FILE = os.path.join(BASE_DIR, "live_state.json")
ATTACK_TRIGGER_FILE = os.path.join(BASE_DIR, "attack_trigger.txt")
CLEAR_TRIGGER_FILE = os.path.join(BASE_DIR, "clear_trigger.txt")

HOST_NAMES = {
    "10.0.0.1": "HR",
    "10.0.0.2": "Finance",
    "10.0.0.3": "Server",
    "10.0.0.4": "Guest",
}
NAME_TO_SHORT = {"HR": "hr", "Finance": "fin", "Server": "crit", "Guest": "guest"}

# Rolling in-memory history of active_flows counts, purely for the server's
# own chart; the controller doesn't need to know about this.
history = []
HISTORY_MAX = 300  # ~5 minutes at 1-second polling

app = Flask(__name__)


def name_for(ip):
    return HOST_NAMES.get(ip, ip)


@app.route("/api/state")
def api_state():
    """Returns the live controller state, annotated with human-readable
    host names, plus our own rolling active-connections history and a
    per-host connection-fan-out breakdown."""
    state = {}
    if os.path.exists(LIVE_STATE_FILE):
        try:
            with open(LIVE_STATE_FILE) as f:
                state = json.load(f)
        except Exception:
            state = {}

    active_flows = state.get("active_flows", 0)
    now = time.time()
    history.append({"t": now, "active_flows": active_flows})
    while len(history) > HISTORY_MAX:
        history.pop(0)

    quarantined = state.get("quarantined_hosts", [])
    restricted = state.get("restricted_pairs", [])
    decisions = state.get("recent_decisions", [])
    active_pairs = state.get("active_flow_pairs", [])

    # Build per-host connection fan-out: for each source host currently
    # active, how many DISTINCT other hosts is it talking to right now.
    fanout = defaultdict(set)
    pair_list = []
    for p in active_pairs:
        src, dst = p.get("src"), p.get("dst")
        if not src or not dst:
            continue
        fanout[src].add(dst)
        pair_list.append({
            "src": src, "src_name": name_for(src),
            "dst": dst, "dst_name": name_for(dst),
        })

    connections_by_host = [
        {"ip": ip, "name": name_for(ip), "count": len(dsts)}
        for ip, dsts in sorted(fanout.items(), key=lambda x: -len(x[1]))
    ]

    return jsonify({
        "timestamp": state.get("timestamp", "--"),
        "active_flows": active_flows,
        "quarantined_hosts": [
            {"ip": ip, "name": name_for(ip)} for ip in quarantined
        ],
        "restricted_pairs": [
            {"src": p["src"], "src_name": name_for(p["src"]),
             "dst": p["dst"], "dst_name": name_for(p["dst"])}
            for p in restricted
        ],
        "recent_decisions": [
            {**d, "src_name": name_for(d["src_ip"]), "dst_name": name_for(d["dst_ip"])}
            for d in decisions
        ],
        "history": history,
        "connections_by_host": connections_by_host,
        "active_pairs": pair_list,
    })


@app.route("/api/attack", methods=["POST"])
def api_attack():
    """Triggers a lateral-movement attack from the chosen host.
    Body: {"host": "hr" | "fin" | "crit"}"""
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host")
    if host not in ("hr", "fin", "crit"):
        return jsonify({"ok": False, "error": "invalid host"}), 400
    with open(ATTACK_TRIGGER_FILE, "w") as f:
        f.write(f"lateral:{host}")
    return jsonify({"ok": True, "message": f"Attack triggered from {host}"})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    """Clears quarantine/restrict state.
    Body: {"scope": "all"} or {"scope": "quarantine", "ip": "10.0.0.1"}"""
    data = request.get_json(force=True, silent=True) or {}
    scope = data.get("scope", "all")
    if scope == "all":
        trigger = "all"
    elif scope == "quarantine":
        trigger = f"quarantine:{data.get('ip', '')}"
    elif scope == "restrict":
        trigger = f"restrict:{data.get('src', '')},{data.get('dst', '')}"
    else:
        return jsonify({"ok": False, "error": "invalid scope"}), 400

    with open(CLEAR_TRIGGER_FILE, "w") as f:
        f.write(trigger)
    return jsonify({"ok": True, "message": f"Clear triggered: {trigger}"})


PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Real-Time ML Detection</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #0f1117; color: #e0e0e0; margin: 0; padding: 24px; }
  h1 { color: #fff; margin: 0 0 4px 0; font-size: 26px; }
  .subtitle { color: #888; margin-top: 0; margin-bottom: 24px; font-size: 13px; }
  .status-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #4CAF50; margin-right: 8px; animation: pulse 1.5s infinite; }
  @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }
  .row { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 24px; }
  .col { flex: 1; min-width: 320px; }
  .card { background: #1c1f26; border-radius: 10px; padding: 18px; margin-bottom: 20px; }
  .card h2 { margin: 0 0 14px 0; font-size: 16px; color: #fff; border-bottom: 1px solid #333; padding-bottom: 8px; }
  .stats-row { display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 20px; }
  .stat-card { background: #1c1f26; border-radius: 10px; padding: 14px 18px; min-width: 140px; flex: 1; text-align: center; }
  .stat-value { font-size: 30px; font-weight: 700; }
  .stat-label { font-size: 12px; color: #aaa; margin-top: 4px; }
  select, button { font-size: 14px; padding: 8px 14px; border-radius: 6px; border: none; }
  select { background: #2a2e38; color: #fff; }
  button { cursor: pointer; font-weight: 600; margin-top: 10px; width: 100%; }
  .btn-attack { background: #F44336; color: #fff; }
  .btn-attack:hover { background: #d32f2f; }
  .btn-clear { background: #4CAF50; color: #fff; }
  .btn-clear:hover { background: #388E3C; }
  .btn-clear-pair { background: #FF9800; color: #000; font-size: 12px; padding: 4px 10px; width: auto; margin: 0; }
  .host-pill { display: inline-flex; align-items: center; gap: 8px; background: #3a1414; border: 1px solid #F44336; color: #ff8a80; padding: 8px 14px; border-radius: 20px; margin: 4px; font-weight: 600; }
  .pair-pill { display: inline-flex; align-items: center; gap: 8px; background: #3a2a0f; border: 1px solid #FF9800; color: #ffcc80; padding: 6px 12px; border-radius: 16px; margin: 4px; font-size: 13px; }
  .empty-msg { color: #666; font-style: italic; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 7px 10px; text-align: left; border-bottom: 1px solid #2a2e38; font-size: 12.5px; }
  th { color: #888; font-weight: 600; text-transform: uppercase; font-size: 11px; }
  .action-MONITOR { color: #4CAF50; font-weight: 700; }
  .action-RESTRICT { color: #FF9800; font-weight: 700; }
  .action-QUARANTINE { color: #F44336; font-weight: 700; }
  canvas { max-width: 100%; display: block; }
  .msg-toast { position: fixed; top: 20px; right: 20px; background: #2a2e38; color: #fff; padding: 12px 18px; border-radius: 8px; font-size: 13px; opacity: 0; transition: opacity 0.3s; z-index: 1000; }
  .msg-toast.show { opacity: 1; }
  .fanout-row { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .fanout-name { width: 90px; font-size: 13px; color: #ddd; font-weight: 600; flex-shrink: 0; }
  .fanout-bar-track { flex: 1; background: #2a2e38; border-radius: 4px; height: 18px; overflow: hidden; }
  .fanout-bar-fill { height: 100%; background: linear-gradient(90deg, #42a5f5, #1976d2); border-radius: 4px; transition: width 0.4s ease; }
  .fanout-count { width: 24px; text-align: right; font-size: 13px; font-weight: 700; color: #90caf9; flex-shrink: 0; }
</style>
</head>
<body>
  <h1><span class="status-dot"></span>Real-Time ML Detection</h1>
  <p class="subtitle">ML-driven lateral-movement detection &amp; adaptive SDN microsegmentation &middot; last update: <span id="last-update">--</span></p>

  <div class="stats-row" id="stats-row"></div>

  <div class="row">
    <div class="col">
      <div class="card">
        <h2>Launch Attack Simulation</h2>
        <label style="font-size:13px;color:#aaa;">Attacker host</label><br>
        <select id="attack-host" style="width:100%;margin-top:6px;">
          <option value="hr">HR (10.0.0.1)</option>
          <option value="fin">Finance (10.0.0.2)</option>
          <option value="crit">Server (10.0.0.3)</option>
        </select>
        <button class="btn-attack" onclick="startAttack()">Start Lateral Movement Attack</button>
      </div>

      <div class="card">
        <h2>Analyst Recovery</h2>
        <p style="font-size:13px;color:#aaa;margin-top:0;">Clears all quarantine and restriction rules, simulating an analyst confirming the threat is resolved.</p>
        <button class="btn-clear" onclick="clearAll()">Clear All Containment</button>
      </div>

      <div class="card">
        <h2>Connections by Host</h2>
        <p style="font-size:12px;color:#888;margin-top:0;">How many OTHER hosts each host is currently talking to (live fan-out). A sudden jump here is the signature of lateral movement.</p>
        <div id="fanout-list"><span class="empty-msg">No active connections</span></div>
      </div>
    </div>

    <div class="col">
      <div class="card">
        <h2>Quarantined Hosts</h2>
        <div id="quarantined-list"><span class="empty-msg">None</span></div>
      </div>
      <div class="card">
        <h2>Restricted Pairs</h2>
        <div id="restricted-list"><span class="empty-msg">None</span></div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Active Connections Over Time</h2>
    <canvas id="activeChart" height="70"></canvas>
  </div>

  <div class="card">
    <h2>Recent Decisions (live feed)</h2>
    <table>
      <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Prediction</th><th>Risk</th><th>Action</th></tr></thead>
      <tbody id="decisions-body"><tr><td colspan="6" class="empty-msg">No decisions yet</td></tr></tbody>
    </table>
  </div>

  <div class="msg-toast" id="toast"></div>

<script>
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}

function startAttack() {
  const host = document.getElementById('attack-host').value;
  fetch('/api/attack', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({host: host})
  }).then(r => r.json()).then(d => showToast(d.message || 'Attack triggered'));
}

function clearAll() {
  fetch('/api/clear', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scope: 'all'})
  }).then(r => r.json()).then(d => showToast(d.message || 'Cleared'));
}

function clearQuarantine(ip) {
  fetch('/api/clear', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scope: 'quarantine', ip: ip})
  }).then(r => r.json()).then(d => showToast(d.message || 'Cleared'));
}

function clearRestrict(src, dst) {
  fetch('/api/clear', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scope: 'restrict', src: src, dst: dst})
  }).then(r => r.json()).then(d => showToast(d.message || 'Cleared'));
}

let chartData = [];

function drawChart() {
  const canvas = document.getElementById('activeChart');
  const ctx = canvas.getContext('2d');
  const w = canvas.clientWidth || 600;
  const h = 150;
  canvas.width = w; canvas.height = h;
  ctx.clearRect(0, 0, w, h);

  if (chartData.length < 2) {
    ctx.fillStyle = '#666'; ctx.font = '13px sans-serif';
    ctx.fillText('Waiting for data...', 10, h/2);
    return;
  }

  const maxVal = Math.max(1, ...chartData.map(d => d.active_flows));
  const minT = chartData[0].t, maxT = chartData[chartData.length-1].t;
  const spanT = Math.max(1, maxT - minT);

  const pad = 10;
  const toX = t => pad + (t - minT) / spanT * (w - 2*pad);
  const toY = v => h - pad - (v / maxVal) * (h - 2*pad);

  ctx.strokeStyle = '#2a2e38'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad + i * (h - 2*pad) / 4;
    ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w-pad, y); ctx.stroke();
  }

  ctx.strokeStyle = '#4CAF50'; ctx.lineWidth = 2; ctx.beginPath();
  chartData.forEach((d, i) => {
    const x = toX(d.t), y = toY(d.active_flows);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.lineTo(toX(chartData[chartData.length-1].t), h-pad);
  ctx.lineTo(toX(chartData[0].t), h-pad);
  ctx.closePath();
  ctx.fillStyle = 'rgba(76,175,80,0.15)';
  ctx.fill();

  ctx.fillStyle = '#888'; ctx.font = '11px sans-serif';
  ctx.fillText('max: ' + maxVal, w - 60, 14);
}

function renderStats(d) {
  const quarantineCount = d.quarantined_hosts.length;
  const restrictCount = d.restricted_pairs.length;
  const stats = [
    {label: 'Active Connections', value: d.active_flows, cls: ''},
    {label: 'Quarantined Hosts', value: quarantineCount, cls: quarantineCount ? 'color:#F44336' : 'color:#4CAF50'},
    {label: 'Restricted Pairs', value: restrictCount, cls: restrictCount ? 'color:#FF9800' : 'color:#4CAF50'},
    {label: 'Total Decisions Seen', value: d.recent_decisions.length, cls: ''},
  ];
  document.getElementById('stats-row').innerHTML = stats.map(s =>
    `<div class="stat-card"><div class="stat-value" style="${s.cls}">${s.value}</div><div class="stat-label">${s.label}</div></div>`
  ).join('');
}

function renderQuarantined(hosts) {
  const el = document.getElementById('quarantined-list');
  if (!hosts.length) { el.innerHTML = '<span class="empty-msg">None — network fully operational</span>'; return; }
  el.innerHTML = hosts.map(h =>
    `<span class="host-pill">${h.name} (${h.ip}) <button class="btn-clear-pair" onclick="clearQuarantine('${h.ip}')">Clear</button></span>`
  ).join('');
}

function renderRestricted(pairs) {
  const el = document.getElementById('restricted-list');
  if (!pairs.length) { el.innerHTML = '<span class="empty-msg">None</span>'; return; }
  el.innerHTML = pairs.map(p =>
    `<span class="pair-pill">${p.src_name} &rarr; ${p.dst_name} <button class="btn-clear-pair" onclick="clearRestrict('${p.src}','${p.dst}')">Clear</button></span>`
  ).join('');
}

function renderFanout(list) {
  const el = document.getElementById('fanout-list');
  if (!list.length) { el.innerHTML = '<span class="empty-msg">No active connections</span>'; return; }
  const maxCount = Math.max(1, ...list.map(h => h.count));
  el.innerHTML = list.map(h => {
    const pct = Math.round((h.count / maxCount) * 100);
    const danger = h.count >= 3;
    const fillColor = danger ? 'linear-gradient(90deg, #ff7043, #d32f2f)' : 'linear-gradient(90deg, #42a5f5, #1976d2)';
    return `<div class="fanout-row">
      <div class="fanout-name">${h.name}</div>
      <div class="fanout-bar-track"><div class="fanout-bar-fill" style="width:${pct}%;background:${fillColor};"></div></div>
      <div class="fanout-count">${h.count}</div>
    </div>`;
  }).join('');
}

function renderDecisions(decisions) {
  const el = document.getElementById('decisions-body');
  if (!decisions.length) { el.innerHTML = '<tr><td colspan="6" class="empty-msg">No decisions yet</td></tr>'; return; }
  const rows = decisions.slice().reverse().slice(0, 15);
  el.innerHTML = rows.map(d =>
    `<tr><td>${d.timestamp.split(' ')[1] || d.timestamp}</td><td>${d.src_name}</td><td>${d.dst_name}</td>` +
    `<td>${d.ml_prediction}</td><td>${d.risk_score}</td><td class="action-${d.action}">${d.action}</td></tr>`
  ).join('');
}

function poll() {
  fetch('/api/state').then(r => r.json()).then(d => {
    document.getElementById('last-update').textContent = d.timestamp;
    renderStats(d);
    renderQuarantined(d.quarantined_hosts);
    renderRestricted(d.restricted_pairs);
    renderFanout(d.connections_by_host);
    renderDecisions(d.recent_decisions);
    chartData = d.history;
    drawChart();
  }).catch(e => console.error(e));
}

poll();
setInterval(poll, 2000);
window.addEventListener('resize', drawChart);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


if __name__ == "__main__":
    print(f"netshield-ai dashboard starting on http://localhost:5000")
    print(f"Reading live state from: {LIVE_STATE_FILE}")
    app.run(host="0.0.0.0", port=5000, debug=False)
