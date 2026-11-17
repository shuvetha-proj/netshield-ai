import shutil
F = "graph_dashboard.py"
lines = open(F).read().split("\n")

def find_one(s):
    hits = [i for i, l in enumerate(lines) if l.strip() == s]
    assert len(hits) == 1, f"expected 1 match for {s!r}, found {len(hits)}"
    return hits[0]

a = find_one('<h1><span class="status-dot"></span>netshield-ai Live Dashboard</h1>')
b = find_one('<div class="msg-toast" id="toast"></div>')
c = find_one('</style>')
assert c < a < b

CSS = '''  /* ---- layout v2 ---- */
  h1 { font-size: 22px; }
  .section-title { font-size: 18px; color: #fff; margin: 4px 0 4px; }
  .section-desc { font-size: 12px; color: #888; margin: 0 0 14px; }
  .ctrl-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: stretch; }
  .main-grid { display: grid; grid-template-columns: minmax(0, 3fr) minmax(300px, 2fr); gap: 20px; align-items: start; }
  .side-col .card { margin-bottom: 16px; }
  #quarantined-list, #restricted-list { max-height: 170px; overflow-y: auto; }
  .graph-card #netsvg { height: 520px; }
  @media (max-width: 1100px) { .ctrl-grid, .main-grid { grid-template-columns: 1fr; } }'''

BODY = '''  <h1><span class="status-dot"></span>ML-Driven Adaptive Micro-Segmentation for Ransomware Lateral-Movement Containment</h1>
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
'''

lines[a:b] = BODY.split("\n")
lines[c:c] = CSS.split("\n")
open(F, "w").write("\n".join(lines))
print("layout patched; backup is graph_dashboard_before_layout.py")
