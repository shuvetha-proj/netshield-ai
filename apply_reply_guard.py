F = "simple_switch.py"
lines = open(F).read().split("\n")
anchor = "init_recent = self.initiated_hosts_recent(rec.src_ip, rec.last_time)"
hits = [i for i, l in enumerate(lines) if l.strip() == anchor]
assert len(hits) == 1, f"anchor matches: {len(hits)}"
assert not any("[reply-guard]" in l for l in lines), "already patched"
i = hits[0]
ind = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
block = [
    "# REPLY GUARD: a flow to a host that recently initiated contact with",
    "# this source (and that this source did not itself initiate) is reply",
    "# traffic. The controller never contains a host for answering others.",
    "_ini = self.initiated_hosts",
    "_src_opened = (rec.last_time - _ini.get(rec.src_ip, {}).get(rec.dst_ip, -1e18)) <= HOST_ACTIVITY_WINDOW",
    "_dst_opened = (rec.last_time - _ini.get(rec.dst_ip, {}).get(rec.src_ip, -1e18)) <= HOST_ACTIVITY_WINDOW",
    'if action in ("QUARANTINE", "RESTRICT") and _dst_opened and not _src_opened:',
    '    print(f"    [reply-guard] {rec.src_ip} -> {rec.dst_ip} is reply traffic "',
    '          f"-- {action} suppressed", flush=True)',
    '    action = "MONITOR"',
]
lines[i + 1:i + 1] = [ind + b for b in block]
open(F, "w").write("\n".join(lines))
print("reply guard inserted after line", i + 1)
