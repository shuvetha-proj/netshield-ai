import shutil

def patch(path, bak, edits):
    src = open(path).read()
    for old, new in edits:
        n = src.count(old)
        assert n == 1, f"{path}: expected 1 match, found {n} for: {old[:60]!r}"
    shutil.copy2(path, bak)
    for old, new in edits:
        src = src.replace(old, new)
    open(path, "w").write(src)
    print(f"patched {path}; backup at {bak}")

# ---------- risk_engine_v2.py ----------
R = "risk_engine_v2.py"
src = open(R).read()
s = src.index('"""'); e = src.index('"""', s + 3) + 3
old_doc = src[s:e]
assert "STANDALONE / OFFLINE" in old_doc, "docstring not as expected"
new_doc = '"""' + '''
risk_engine_v2.py -- 5-term weighted risk model (0-100).

Used LIVE by the controller when RISK_MODEL=5factor (simple_switch.py).
RISK_MODEL=2factor falls back to the simpler risk_engine.py.

Terms (weights sum to 1.0):
  1. ML attack probability   -- 1 - P(normal) from model.predict_proba
  2. Connection rate         -- from connection_tracker.py, normalised by PPS_CEIL
  3. Failed-connection ratio -- from connection_tracker.py (5-tuple state,
                                retransmitted SYNs counted as one attempt)
  4. Unique destinations     -- fan-out (distinct_dst_hosts_recent)
  5. Asset criticality       -- destination weight, 8-host VLAN topology

Tiers: score < 30 -> MONITOR, 30-70 -> RESTRICT, >= 70 -> QUARANTINE.
Scope policy lives in the controller, not here: a single-target scan is
capped at pair-level RESTRICT; host-wide QUARANTINE needs multi-host initiation.
''' + '"""'

c0 = src.index("CRITICALITY = {")
assert src.count("CRITICALITY = {") == 1
c1 = src.index("\n}\n", c0) + 3
old_crit = src[c0:c1]
new_crit = '''CRITICALITY = {  # destination criticality, 0-1 (critical assets = 1.0)
    # same tiers as risk_engine.py multipliers, divided by 1.5
    "10.0.0.1": ("HR",         1.0 / 1.5),  # VLAN10
    "10.0.0.2": ("Finance",    1.2 / 1.5),  # VLAN20
    "10.0.0.3": ("FileServer", 1.5 / 1.5),  # VLAN30 - critical asset
    "10.0.0.4": ("Guest",      1.0 / 1.5),  # VLAN40 - also statically blocked
    "10.0.0.5": ("Database",   1.5 / 1.5),  # VLAN30 - critical asset
    "10.0.0.6": ("IoT-1",      1.0 / 1.5),  # VLAN50
    "10.0.0.7": ("IoT-2",      1.0 / 1.5),  # VLAN50
    "10.0.0.8": ("Admin",      1.1 / 1.5),  # VLAN60
}
'''

patch(R, "risk_engine_v2_before_8hostcrit.py", [
    (old_doc, new_doc),
    (old_crit, new_crit),
    ("(proxy via packets_per_sec)", "(connection_tracker.py)"),
    ("(placeholder -> 0 for now)", "(connection_tracker.py)"),
    ("# term 2: connection rate (proxy from packets_per_sec)",
     "# term 2: connection rate (from connection_tracker)"),
    ("# term 3: failed-connection ratio -- placeholder until instrumented",
     "# term 3: failed-connection ratio (from connection_tracker)"),
    ('"connection_rate": "proxy (packets_per_sec)",',
     '"connection_rate": "implemented (connection_tracker.py)",'),
    ('"failed_conn_ratio": "placeholder (needs connection-state tracking)",',
     '"failed_conn_ratio": "implemented (connection_tracker.py)",'),
])

# ---------- simple_switch.py: print the 5-factor breakdown ----------
S = "simple_switch.py"
lines = open(S).read().split("\n")
t = 'f"fail={f_ratio} fan={dist_hosts}) => {action}")'
hits = [i for i, l in enumerate(lines) if l.strip() == t]
assert len(hits) == 1, f"explanation line matches: {len(hits)}"
i = hits[0]
ind = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
shutil.copy2(S, "simple_switch_before_breakdown.py")
lines[i:i + 1] = [ind + 'f"fail={f_ratio} fan={dist_hosts}) => {action} "',
                  ind + 'f"terms={breakdown}")']
open(S, "w").write("\n".join(lines))
print(f"patched {S}; backup at simple_switch_before_breakdown.py")
