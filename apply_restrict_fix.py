import shutil, sys

SRC = "simple_switch.py"
BAK = "simple_switch_before_restrictfix.py"

with open(SRC) as f:
    lines = f.read().split("\n")

# 1. locate the GRAPH_CUT config line (insert SCAN_PORT_MIN after it)
gc = [i for i, l in enumerate(lines) if l.startswith("GRAPH_CUT = os.environ.get(")]
assert len(gc) == 1, f"GRAPH_CUT line matches: {len(gc)}"
assert not any(l.startswith("SCAN_PORT_MIN") for l in lines), "already patched"

# 2. locate the directional guard if-line
target = 'if action in ("QUARANTINE", "RESTRICT") and init_recent <= 1:'
g = [i for i, l in enumerate(lines) if l.strip() == target]
assert len(g) == 1, f"guard line matches: {len(g)}"
gi = g[0]
assert lines[gi + 4].strip() == 'action = "MONITOR"', "guard body not as expected"
ind = lines[gi][: len(lines[gi]) - len(lines[gi].lstrip())]

shutil.copy2(SRC, BAK)

new_block = [
    ind + "# SCAN EXCEPTION: an initiator that opened exactly one target and hit",
    ind + "# many distinct ports on it is a single-target port scan, not a",
    ind + "# responder. Allowed through as pair-level RESTRICT, capped there:",
    ind + "# one target is not evidence of spread, so no host-wide quarantine.",
    ind + "_n_ports = len(rec.dst_ports)",
    ind + "_is_scan = (init_recent == 1",
    ind + "            and rec.dst_ip in self.initiated_hosts.get(rec.src_ip, {})",
    ind + "            and _n_ports >= SCAN_PORT_MIN)",
    ind + 'if action in ("QUARANTINE", "RESTRICT") and init_recent <= 1 and _is_scan:',
    ind + '    if action == "QUARANTINE":',
    ind + '        action = "RESTRICT"',
    ind + '    print(f"    [scan] {rec.src_ip} -> {rec.dst_ip}: single-target scan "',
    ind + '          f"({_n_ports} ports) -- pair-level RESTRICT", flush=True)',
]
lines[gi] = ind + "el" + lines[gi].lstrip()          # if -> elif
lines[gi:gi] = new_block
lines.insert(gc[0] + 1, "SCAN_PORT_MIN = int(os.environ.get('SCAN_PORT_MIN', '20'))")

with open(SRC, "w") as f:
    f.write("\n".join(lines))
print(f"patched {SRC}; backup at {BAK}")
