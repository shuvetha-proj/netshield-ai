#!/usr/bin/env python3
"""
netshield-ai  —  Review 3 Live Dashboard  (port 5001)

This is the Review 2 dashboard, extended for Review 3:
  * same look, cards, stat tiles, fan-out bars, decisions feed, chart, toasts
  * 8-host VLAN topology
  * PLUS a live Network graph card: pick a host -> it turns red IN PLACE,
    VLAN edges shown, quarantined hosts get a red ring, restrict = orange,
    critical assets (FileServer, Database) marked yellow.

It reads the controller's files (written by simple_switch.py):
    live_state.json   -> active_flows, quarantined_hosts, restricted_pairs,
                         active_flow_pairs, recent_decisions
    graph_state.json  -> hosts, edges            (for the network graph)
and triggers attacks / clears by writing the trigger files the controller
and the 8-host topology watcher already watch.

Run separately from the controller and topology:
    python3 graph_dashboard.py
Then open http://localhost:5001
"""
import json
import os
import time
from collections import defaultdict
from flask import Flask, jsonify, request, Response

BASE_DIR            = os.path.dirname(os.path.abspath(__file__))
LIVE_STATE_FILE     = os.path.join(BASE_DIR, "live_state.json")
GRAPH_STATE_FILE    = os.path.join(BASE_DIR, "graph_state.json")
ATTACK_TRIGGER_FILE = os.path.join(BASE_DIR, "attack_trigger.txt")
CLEAR_TRIGGER_FILE  = os.path.join(BASE_DIR, "clear_trigger.txt")

# 8-host topology (names match topology_8host.py HOSTS keys)
HOST_NAMES = {
    "10.0.0.1": "HR",
    "10.0.0.2": "Finance",
    "10.0.0.3": "FileServer",
    "10.0.0.4": "Guest",
    "10.0.0.5": "Database",
    "10.0.0.6": "IoT-1",
    "10.0.0.7": "IoT-2",
    "10.0.0.8": "Admin",
}
# dropdown key -> ip  (key is what the topology watcher expects: "lateral:<key>")
ATTACK_HOSTS = [
    ("hr",         "10.0.0.1", "HR"),
    ("fin",        "10.0.0.2", "Finance"),
    ("fileserver", "10.0.0.3", "FileServer"),
    ("guest",      "10.0.0.4", "Guest"),
    ("database",   "10.0.0.5", "Database"),
    ("iot1",       "10.0.0.6", "IoT-1"),
    ("iot2",       "10.0.0.7", "IoT-2"),
    ("admin",      "10.0.0.8", "Admin"),
]
VALID_ATTACK_KEYS = {k for k, _ip, _n in ATTACK_HOSTS}
KEY_TO_IP         = {k: ip for k, ip, _n in ATTACK_HOSTS}
CRITICAL_IPS      = {"10.0.0.3", "10.0.0.5"}
VLAN = {"10.0.0.1": 10, "10.0.0.2": 20, "10.0.0.3": 30, "10.0.0.4": 40,
        "10.0.0.5": 30, "10.0.0.6": 50, "10.0.0.7": 50, "10.0.0.8": 60}

# Rolling history of active_flows for the line chart (server-side only).
history = []
HISTORY_MAX = 300

app = Flask(__name__)


def name_for(ip):
    return HOST_NAMES.get(ip, ip)


def _load(path):
    if os.path.exists(path):
        try:
            with open(path) as f:
                txt = f.read().strip()
            return json.loads(txt) if txt else {}
        except Exception:
            return {}
    return {}


def _graph_hosts_edges():
    """hosts + edges for the network graph (from graph_state.json, with a
    built-in 8-host fallback so the page always draws)."""
    g = _load(GRAPH_STATE_FILE)
    hosts = g.get("hosts")
    if not hosts:
        hosts = [{"ip": ip, "name": HOST_NAMES[ip], "vlan": VLAN[ip],
                  "critical": ip in CRITICAL_IPS, "quarantined": False}
                 for ip in HOST_NAMES]
    norm = []
    for h in hosts:
        ip = h.get("ip")
        norm.append({"ip": ip, "name": h.get("name", name_for(ip)),
                     "vlan": h.get("vlan", VLAN.get(ip, 0)),
                     "critical": bool(h.get("critical", ip in CRITICAL_IPS))})
    # edges: controller writes [src, dst] arrays; dedupe undirected
    raw = g.get("edges") or []
    edges, seen = [], set()
    for e in raw:
        if isinstance(e, (list, tuple)) and len(e) == 2:
            a, b = e[0], e[1]
        elif isinstance(e, dict):
            a, b = e.get("src"), e.get("dst")
        else:
            continue
        key = tuple(sorted([str(a), str(b)]))
        if key in seen:
            continue
        seen.add(key)
        edges.append({"src": a, "dst": b})
    if not edges:
        ips = [h["ip"] for h in norm]
        for s in ("10.0.0.3", "10.0.0.5"):
            for ip in ips:
                if ip not in CRITICAL_IPS and ip != "10.0.0.4":
                    edges.append({"src": ip, "dst": s})
        edges.append({"src": "10.0.0.3", "dst": "10.0.0.5"})
        edges.append({"src": "10.0.0.6", "dst": "10.0.0.7"})
    return norm, edges


@app.route("/api/state")
def api_state():
    state = _load(LIVE_STATE_FILE)

    active_flows = state.get("active_flows", 0)
    now = time.time()
    history.append({"t": now, "active_flows": active_flows})
    while len(history) > HISTORY_MAX:
        history.pop(0)

    quarantined  = state.get("quarantined_hosts", [])
    restricted   = state.get("restricted_pairs", [])
    decisions    = state.get("recent_decisions", [])
    active_pairs = state.get("active_flow_pairs", [])

    # per-host fan-out from active pairs (dicts {src,dst})
    fanout = defaultdict(set)
    pair_list = []
    for p in active_pairs:
        src, dst = p.get("src"), p.get("dst")
        if not src or not dst:
            continue
        fanout[src].add(dst)
        pair_list.append({"src": src, "src_name": name_for(src),
                          "dst": dst, "dst_name": name_for(dst)})

    connections_by_host = [
        {"ip": ip, "name": name_for(ip), "count": len(d)}
        for ip, d in sorted(fanout.items(), key=lambda x: -len(x[1]))
    ]

    # attacker hint: biggest fan-out source, else first quarantined
    attacker = None
    if connections_by_host:
        attacker = connections_by_host[0]["ip"]
    elif quarantined:
        attacker = quarantined[0]

    hosts, edges = _graph_hosts_edges()

    return jsonify({
        "timestamp": state.get("timestamp", "--"),
        "active_flows": active_flows,
        "quarantined_hosts": [{"ip": ip, "name": name_for(ip)} for ip in quarantined],
        "restricted_pairs": [
            {"src": p.get("src"), "src_name": name_for(p.get("src")),
             "dst": p.get("dst"), "dst_name": name_for(p.get("dst"))}
            for p in restricted if isinstance(p, dict)
        ],
        "recent_decisions": [
            {**d,
             "src_name": name_for(d.get("src_ip")),
             "dst_name": name_for(d.get("dst_ip"))}
            for d in decisions
        ],
        "history": history,
        "connections_by_host": connections_by_host,
        "active_pairs": pair_list,
        # --- extra for the network graph ---
        "hosts": hosts,
        "edges": edges,
        "attacker": attacker,
    })


@app.route("/api/attack", methods=["POST"])
def api_attack():
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host")
    if host not in VALID_ATTACK_KEYS:
        return jsonify({"ok": False, "error": "invalid host"}), 400
    with open(ATTACK_TRIGGER_FILE, "w") as f:
        f.write(f"lateral:{host}")
    return jsonify({"ok": True, "message": f"Attack triggered from {host}", "ip": KEY_TO_IP[host]})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Single-target port scan -> low fan-out, medium risk -> RESTRICT.
       Writes 'scan:<src>:<dst>' which topology_8host.py watches."""
    data = request.get_json(force=True, silent=True) or {}
    src = data.get("src")
    dst = data.get("dst")
    if src not in VALID_ATTACK_KEYS or dst not in VALID_ATTACK_KEYS:
        return jsonify({"ok": False, "error": "invalid host"}), 400
    if src == dst:
        return jsonify({"ok": False, "error": "source and target must differ"}), 400
    with open(ATTACK_TRIGGER_FILE, "w") as f:
        f.write(f"scan:{src}:{dst}")
    return jsonify({"ok": True, "message": f"Port scan {src} -> {dst}", "ip": KEY_TO_IP[src]})


@app.route("/api/clear", methods=["POST"])
def api_clear():
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


PAGE = r"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>netshield-ai Live Dashboard</title>
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
  .btn-restrict { background: #FF9800; color: #000; }
  .btn-restrict:hover { background: #f57c00; }
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
  .msg-toast { position: fixed; top: 20px; right: 20px; background: #2a2e38; color: #fff; padding: 12px 18px; border-radius:8px; font-size: 13px; opacity: 0; transition: opacity 0.3s; z-index: 1000; }
  .msg-toast.show { opacity: 1; }
  .fanout-row { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .fanout-name { width: 90px; font-size: 13px; color: #ddd; font-weight: 600; flex-shrink: 0; }
  .fanout-bar-track { flex: 1; background: #2a2e38; border-radius: 4px; height: 18px; overflow: hidden; }
  .fanout-bar-fill { height: 100%; background: linear-gradient(90deg, #42a5f5, #1976d2); border-radius: 4px; transition: width 0.4s ease; }
  .fanout-count { width: 24px; text-align: right; font-size: 13px; font-weight: 700; color: #90caf9; flex-shrink: 0; }
  /* ---- network graph ---- */
  #netsvg { width: 100%; height: 440px; display: block; background: radial-gradient(circle at 50% 42%, #141922, #0f1117 72%); border-radius: 8px; }
  .edge { stroke: #2a2e38; stroke-width: 2; }
  .edge.active { stroke: #cfd8dc; stroke-width: 2.4; }
  .edge.restricted { stroke: #FF9800; stroke-width: 2.6; stroke-dasharray: 7 5; }
  .edge.cut { stroke: #F44336; stroke-width: 2.2; stroke-dasharray: 3 6; opacity: .7; }
  .gnode text { text-anchor: middle; font-weight: 600; }
  .gname { font-size: 12px; fill: #fff; }
  .gip { font-size: 9.5px; fill: #9aa4ad; }
  .gvlan { font-size: 9px; fill: #6e7681; }
  .gbadge { font-size: 9px; font-weight: 700; text-anchor: middle; }
  .glegend { display: flex; gap: 18px; flex-wrap: wrap; margin-top: 10px; font-size: 12px; color: #9aa4ad; }
  .glegend span { display: inline-flex; align-items: center; gap: 7px; }
  .gdot { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
  /* ---- layout v2 ---- */
  h1 { font-size: 22px; }
  .section-title { font-size: 18px; color: #fff; margin: 4px 0 4px; }
  .section-desc { font-size: 12px; color: #888; margin: 0 0 14px; }
  .ctrl-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: stretch; }
  .main-grid { display: grid; grid-template-columns: minmax(0, 3fr) minmax(300px, 2fr); gap: 20px; align-items: start; }
  .side-col .card { margin-bottom: 16px; }
  #quarantined-list, #restricted-list { max-height: 170px; overflow-y: auto; }
  .graph-card #netsvg { height: 520px; }
  @media (max-width: 1100px) { .ctrl-grid, .main-grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
  <h1><span class="status-dot"></span>ML-Driven Adaptive Micro-Segmentation for Ransomware Lateral-Movement Containment</h1>
  <p class="subtitle">netshield-ai &middot; ML-driven lateral-movement detection &amp; adaptive SDN microsegmentation &middot; 8-host VLAN &middot; last update: <span id="last-update">--</span></p>

  <div class="stats-row" id="stats-row"></div>

  <h2 class="section-title">Live Network &mdash; Attack &amp; Containment</h2>
  <p class="section-desc">Pick an attacker below and launch. The infected host turns <b style="color:#F44336">red in place</b>; quarantined hosts keep their position and gain a red ring; restricted links turn <b style="color:#FF9800">orange</b>; severed lateral paths show as red dashes. Critical assets are marked yellow.</p>

  <div class="ctrl-grid">
    <div class="card">
      <h2>Launch Attack Simulation</h2>
      <label style="font-size:13px;color:#aaa;">Attacker host</label><br>
      <select id="attack-host" style="width:100%;margin-top:6px;">
        <option value="hr">HR (10.0.0.1)</option>
        <option value="fin">Finance (10.0.0.2)</option>
        <option value="fileserver">FileServer (10.0.0.3)</option>
        <option value="guest">Guest (10.0.0.4)</option>
        <option value="database">Database (10.0.0.5)</option>
        <option value="iot1">IoT-1 (10.0.0.6)</option>
        <option value="iot2">IoT-2 (10.0.0.7)</option>
        <option value="admin">Admin (10.0.0.8)</option>
      </select>
      <button class="btn-attack" onclick="startAttack()">Start Lateral Movement Attack</button>
      <p style="font-size:11px;color:#777;margin:8px 0 0;">Full fan-out to all hosts &rarr; high risk &rarr; QUARANTINE (red).</p>

      <hr style="border:none;border-top:1px solid #2a2e38;margin:16px 0;">

      <label style="font-size:13px;color:#aaa;">Port scan &mdash; single target (medium risk &rarr; RESTRICT)</label>
      <div style="display:flex;gap:8px;margin-top:6px;">
        <select id="scan-src" style="flex:1;">
          <option value="hr">HR</option><option value="fin">Finance</option>
          <option value="fileserver">FileServer</option><option value="guest" selected>Guest</option>
          <option value="database">Database</option><option value="iot1">IoT-1</option>
          <option value="iot2">IoT-2</option><option value="admin">Admin</option>
        </select>
        <span style="align-self:center;color:#777;">&rarr;</span>
        <select id="scan-dst" style="flex:1;">
          <option value="hr">HR</option><option value="fin">Finance</option>
          <option value="fileserver">FileServer</option><option value="guest">Guest</option>
          <option value="database" selected>Database</option><option value="iot1">IoT-1</option>
          <option value="iot2">IoT-2</option><option value="admin">Admin</option>
        </select>
      </div>
      <button class="btn-restrict" onclick="startScan()">Run Port Scan (Restrict test)</button>
      <p style="font-size:11px;color:#777;margin:8px 0 0;">One source probing one target &rarr; low fan-out &rarr; RESTRICT (orange).</p>
    </div>

    <div class="card">
      <h2>Analyst Recovery</h2>
      <p style="font-size:13px;color:#aaa;margin-top:0;">Clears all quarantine and restriction rules. If a host is still attacking, the controller re-detects and re-quarantines it automatically.</p>
      <button class="btn-clear" onclick="clearAll()">Clear All Containment</button>
    </div>
  </div>

  <div class="main-grid">
    <div class="card graph-card">
      <svg id="netsvg" viewBox="0 0 760 440" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="glegend">
        <span><i class="gdot" style="background:#4CAF50"></i>Normal</span>
        <span><i class="gdot" style="background:#F44336"></i>Attacker / Infected</span>
        <span><i class="gdot" style="background:#F44336"></i>+ ring = Quarantined</span>
        <span><i class="gdot" style="background:#FF9800"></i>Restricted</span>
        <span><i class="gdot" style="background:#FFC107"></i>Critical asset</span>
      </div>
    </div>

    <div class="side-col">
      <div class="card">
        <h2>Quarantined Hosts</h2>
        <div id="quarantined-list"><span class="empty-msg">None</span></div>
      </div>
      <div class="card">
        <h2>Restricted Pairs</h2>
        <div id="restricted-list"><span class="empty-msg">None</span></div>
      </div>
      <div class="card">
        <h2>Connections by Host</h2>
        <p style="font-size:12px;color:#888;margin-top:0;">How many OTHER hosts each host is currently talking to (live fan-out). A sudden jump here is the signature of lateral movement.</p>
        <div id="fanout-list"><span class="empty-msg">No active connections</span></div>
      </div>
      <div class="card">
        <h2>Active Connections Over Time</h2>
        <canvas id="activeChart" height="70"></canvas>
      </div>
    </div>
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

// IP the user just launched from -> red IN PLACE immediately
let pendingAttackerIp = null;
const KEY_TO_IP = {hr:"10.0.0.1",fin:"10.0.0.2",fileserver:"10.0.0.3",guest:"10.0.0.4",
                   database:"10.0.0.5",iot1:"10.0.0.6",iot2:"10.0.0.7",admin:"10.0.0.8"};

function startAttack() {
  const host = document.getElementById('attack-host').value;
  pendingAttackerIp = KEY_TO_IP[host] || null;
  fetch('/api/attack', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({host: host})
  }).then(r => r.json()).then(d => showToast(d.message || 'Attack triggered'));
}

function startScan() {
  const src = document.getElementById('scan-src').value;
  const dst = document.getElementById('scan-dst').value;
  if (src === dst) { showToast('Pick different source and target'); return; }
  pendingAttackerIp = KEY_TO_IP[src] || null;
  fetch('/api/scan', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({src: src, dst: dst})
  }).then(r => r.json()).then(d => showToast(d.message || 'Scan triggered'));
}

function clearAll() {
  pendingAttackerIp = null;
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

/* -------- network graph -------- */
let POS = {};
function layout(hosts) {
  POS = {};
  const n = hosts.length, R = 150, CX = 380, CY = 210;
  hosts.forEach((h, i) => {
    const ang = (-Math.PI/2) + (2*Math.PI*i/n);
    POS[h.ip] = { x: CX + R*Math.cos(ang), y: CY + R*Math.sin(ang) };
  });
}

function drawGraph(d) {
  const hosts = d.hosts || [], edges = d.edges || [];
  if (!Object.keys(POS).length || Object.keys(POS).length !== hosts.length) layout(hosts);

  const quar = new Set((d.quarantined_hosts||[]).map(h => h.ip));
  const rsrc = new Set(), rpair = new Set();
  (d.restricted_pairs||[]).forEach(p => { rsrc.add(p.src); rpair.add(p.src+'>'+p.dst); });
  const active = new Set((d.active_pairs||[]).map(p => [p.src,p.dst].sort().join('>')));
  const attacker = pendingAttackerIp || d.attacker;
  const infected = new Set(quar); if (attacker) infected.add(attacker);

  const svg = document.getElementById('netsvg');
  let s = '';
  edges.forEach(e => {
    const a = POS[e.src], b = POS[e.dst]; if (!a || !b) return;
    let cls = 'edge';
    if (rpair.has(e.src+'>'+e.dst) || rpair.has(e.dst+'>'+e.src)) cls = 'edge restricted';
    else if (active.has([e.src,e.dst].sort().join('>'))) cls = 'edge active';
    s += '<line class="'+cls+'" x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'"/>';
  });
  if (quar.size) edges.forEach(e => {
    if (quar.has(e.src) || quar.has(e.dst)) {
      const a = POS[e.src], b = POS[e.dst];
      if (a && b) s += '<line class="edge cut" x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'"/>';
    }
  });
  hosts.forEach(h => {
    const p = POS[h.ip]; if (!p) return;
    const isQ = quar.has(h.ip), isInf = infected.has(h.ip), isR = rsrc.has(h.ip) && !isInf;
    let fill = '#4CAF50', stroke = '#66bb6a';
    if (isInf) { fill = '#d32f2f'; stroke = '#F44336'; }
    else if (isR) { fill = '#5a4215'; stroke = '#FF9800'; }
    s += '<g class="gnode">';
    if (isQ) s += '<circle cx="'+p.x+'" cy="'+p.y+'" r="34" fill="none" stroke="#F44336" stroke-width="2.5" stroke-dasharray="4 4" opacity=".9"/>';
    s += '<circle cx="'+p.x+'" cy="'+p.y+'" r="24" fill="'+fill+'" stroke="'+stroke+'" stroke-width="2.5"/>';
    if (h.critical) s += '<circle cx="'+(p.x+18)+'" cy="'+(p.y-18)+'" r="6" fill="#FFC107" stroke="#8a6d00" stroke-width="1"/>';
    s += '<text class="gname" x="'+p.x+'" y="'+(p.y+4)+'">'+h.name+'</text>';
    s += '<text class="gip" x="'+p.x+'" y="'+(p.y+40)+'">'+h.ip+'</text>';
    s += '<text class="gvlan" x="'+p.x+'" y="'+(p.y+52)+'">VLAN '+h.vlan+'</text>';
    if (h.ip === attacker) s += '<text class="gbadge" x="'+p.x+'" y="'+(p.y-32)+'" fill="#F44336">⚠ ATTACKER</text>';
    else if (isQ) s += '<text class="gbadge" x="'+p.x+'" y="'+(p.y-32)+'" fill="#F44336">QUARANTINED</text>';
    else if (isR) s += '<text class="gbadge" x="'+p.x+'" y="'+(p.y-32)+'" fill="#FF9800">RESTRICTED</text>';
    s += '</g>';
  });
  svg.innerHTML = s;
}

/* -------- line chart (Review 2) -------- */
let chartData = [];
function drawChart() {
  const canvas = document.getElementById('activeChart');
  const ctx = canvas.getContext('2d');
  const w = canvas.clientWidth || 600, h = 150;
  canvas.width = w; canvas.height = h;
  ctx.clearRect(0, 0, w, h);
  if (chartData.length < 2) { ctx.fillStyle = '#666'; ctx.font = '13px sans-serif'; ctx.fillText('Waiting for data...', 10, h/2); return; }
  const maxVal = Math.max(1, ...chartData.map(d => d.active_flows));
  const minT = chartData[0].t, maxT = chartData[chartData.length-1].t;
  const spanT = Math.max(1, maxT - minT);
  const pad = 10;
  const toX = t => pad + (t - minT) / spanT * (w - 2*pad);
  const toY = v => h - pad - (v / maxVal) * (h - 2*pad);
  ctx.strokeStyle = '#2a2e38'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) { const y = pad + i*(h-2*pad)/4; ctx.beginPath(); ctx.moveTo(pad,y); ctx.lineTo(w-pad,y); ctx.stroke(); }
  ctx.strokeStyle = '#4CAF50'; ctx.lineWidth = 2; ctx.beginPath();
  chartData.forEach((d,i) => { const x = toX(d.t), y = toY(d.active_flows); if (i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y); });
  ctx.stroke();
  ctx.lineTo(toX(chartData[chartData.length-1].t), h-pad);
  ctx.lineTo(toX(chartData[0].t), h-pad);
  ctx.closePath(); ctx.fillStyle = 'rgba(76,175,80,0.15)'; ctx.fill();
  ctx.fillStyle = '#888'; ctx.font = '11px sans-serif'; ctx.fillText('max: ' + maxVal, w - 60, 14);
}

function renderStats(d) {
  const q = d.quarantined_hosts.length, r = d.restricted_pairs.length;
  const stats = [
    {label: 'Active Connections', value: d.active_flows, cls: ''},
    {label: 'Quarantined Hosts', value: q, cls: q ? 'color:#F44336' : 'color:#4CAF50'},
    {label: 'Restricted Pairs', value: r, cls: r ? 'color:#FF9800' : 'color:#4CAF50'},
    {label: 'Total Decisions Seen', value: d.recent_decisions.length, cls: ''},
  ];
  document.getElementById('stats-row').innerHTML = stats.map(s =>
    '<div class="stat-card"><div class="stat-value" style="'+s.cls+'">'+s.value+'</div><div class="stat-label">'+s.label+'</div></div>'
  ).join('');
}

function renderQuarantined(hosts) {
  const el = document.getElementById('quarantined-list');
  if (!hosts.length) { el.innerHTML = '<span class="empty-msg">None &mdash; network fully operational</span>'; return; }
  el.innerHTML = hosts.map(h => '<span class="host-pill">'+h.name+' ('+h.ip+') <button class="btn-clear-pair" onclick="clearQuarantine(\''+h.ip+'\')">Clear</button></span>').join('');
}

function renderRestricted(pairs) {
  const el = document.getElementById('restricted-list');
  if (!pairs.length) { el.innerHTML = '<span class="empty-msg">None</span>'; return; }
  el.innerHTML = pairs.map(p => '<span class="pair-pill">'+p.src_name+' &rarr; '+p.dst_name+' <button class="btn-clear-pair" onclick="clearRestrict(\''+p.src+'\',\''+p.dst+'\')">Clear</button></span>').join('');
}

function renderFanout(list) {
  const el = document.getElementById('fanout-list');
  if (!list.length) { el.innerHTML = '<span class="empty-msg">No active connections</span>'; return; }
  const maxCount = Math.max(1, ...list.map(h => h.count));
  el.innerHTML = list.map(h => {
    const pct = Math.round((h.count / maxCount) * 100);
    const danger = h.count >= 3;
    const fill = danger ? 'linear-gradient(90deg, #ff7043, #d32f2f)' : 'linear-gradient(90deg, #42a5f5, #1976d2)';
    return '<div class="fanout-row"><div class="fanout-name">'+h.name+'</div><div class="fanout-bar-track"><div class="fanout-bar-fill" style="width:'+pct+'%;background:'+fill+';"></div></div><div class="fanout-count">'+h.count+'</div></div>';
  }).join('');
}

function renderDecisions(decisions) {
  const el = document.getElementById('decisions-body');
  if (!decisions.length) { el.innerHTML = '<tr><td colspan="6" class="empty-msg">No decisions yet</td></tr>'; return; }
  const rows = decisions.slice().reverse().slice(0, 15);
  el.innerHTML = rows.map(d => {
    const t = (d.timestamp||'').split(' ')[1] || d.timestamp || '';
    return '<tr><td>'+t+'</td><td>'+d.src_name+'</td><td>'+d.dst_name+'</td><td>'+(d.ml_prediction||'')+'</td><td>'+(d.risk_score!=null?d.risk_score:'')+'</td><td class="action-'+d.action+'">'+d.action+'</td></tr>';
  }).join('');
}

function poll() {
  fetch('/api/state').then(r => r.json()).then(d => {
    document.getElementById('last-update').textContent = d.timestamp;
    renderStats(d);
    drawGraph(d);
    renderQuarantined(d.quarantined_hosts);
    renderRestricted(d.restricted_pairs);
    renderFanout(d.connections_by_host);
    renderDecisions(d.recent_decisions);
    chartData = d.history;
    drawChart();
  }).catch(e => console.error(e));
}

poll();
setInterval(poll, 1500);
window.addEventListener('resize', drawChart);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


if __name__ == "__main__":
    print("netshield-ai Review 3 dashboard  ->  http://localhost:5001")
    print("Reading live state from:", LIVE_STATE_FILE)
    print("Reading graph state from:", GRAPH_STATE_FILE)
    app.run(host="0.0.0.0", port=5001, debug=False)