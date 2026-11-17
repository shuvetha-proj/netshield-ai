#!/usr/bin/env python3
"""Make ENFORCEMENT directional: only contain a host that INITIATED contact
with multiple distinct hosts. A pure responder (victim reply traffic) is
never quarantined/restricted. Detection, logging, model, risk engine: unchanged.
Backs up first; asserts every edit matches exactly once."""
import os, shutil, sys

F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_switch.py")
src = open(F).read()
if "initiated_hosts" in src:
    sys.exit("Already patched (initiated_hosts present) -- no changes made.")

EDITS = []

# 1) New state dict: src_ip -> {dst_ip: last_time_it_INITIATED a flow to dst}
#    Added right after host_activity is created.
EDITS.append((
    "        self.flows = {}\n"
    "        self.host_activity = defaultdict(dict)\n",
    "        self.flows = {}\n"
    "        self.host_activity = defaultdict(dict)\n"
    "        # Directional signal: hosts THIS src initiated a NEW flow to.\n"
    "        # A pure responder never originates a flow, so this stays empty\n"
    "        # for victims -- that's what keeps them from being quarantined.\n"
    "        self.initiated_hosts = defaultdict(dict)\n",
))

# 2) record_packet: mark initiation only when this (src->dst) flow is NEW.
#    The 'key not in self.flows' check already tells us it's a first packet.
EDITS.append((
    "    def record_packet(self, src_ip, dst_ip, length, dst_port, proto):\n"
    "        key = (src_ip, dst_ip)\n"
    "        if key not in self.flows:\n"
    "            self.flows[key] = FlowRecord(src_ip, dst_ip)\n"
    "        self.flows[key].update(length, dst_port, proto)\n"
    "\n"
    "        now = time.time()\n"
    "        self.host_activity[src_ip][dst_ip] = now\n",

    "    def record_packet(self, src_ip, dst_ip, length, dst_port, proto):\n"
    "        key = (src_ip, dst_ip)\n"
    "        now = time.time()\n"
    "        is_new_flow = key not in self.flows\n"
    "        if is_new_flow:\n"
    "            self.flows[key] = FlowRecord(src_ip, dst_ip)\n"
    "            # Only the side that OPENS the flow is credited as initiator,\n"
    "            # and only if the reverse flow isn't already active (i.e. this\n"
    "            # isn't just the reply leg of a conversation already underway).\n"
    "            if (dst_ip, src_ip) not in self.flows:\n"
    "                self.initiated_hosts[src_ip][dst_ip] = now\n"
    "        self.flows[key].update(length, dst_port, proto)\n"
    "\n"
    "        self.host_activity[src_ip][dst_ip] = now\n",
))

# 3) New helper: directional fan-out, placed next to distinct_dst_hosts_recent.
EDITS.append((
    "    def distinct_dst_hosts_recent(self, src_ip, now):\n"
    "        activity = self.host_activity.get(src_ip, {})\n"
    "        recent = [dst for dst, t in activity.items()\n"
    "                  if (now - t) <= HOST_ACTIVITY_WINDOW]\n"
    "        return len(recent)\n",

    "    def distinct_dst_hosts_recent(self, src_ip, now):\n"
    "        activity = self.host_activity.get(src_ip, {})\n"
    "        recent = [dst for dst, t in activity.items()\n"
    "                  if (now - t) <= HOST_ACTIVITY_WINDOW]\n"
    "        return len(recent)\n"
    "\n"
    "    def initiated_hosts_recent(self, src_ip, now):\n"
    "        \"\"\"Distinct hosts THIS src opened a new flow to in the window.\n"
    "        Near-zero for a pure responder; high for a real lateral mover.\"\"\"\n"
    "        opened = self.initiated_hosts.get(src_ip, {})\n"
    "        recent = [dst for dst, t in opened.items()\n"
    "                  if (now - t) <= HOST_ACTIVITY_WINDOW]\n"
    "        return len(recent)\n",
))

# 4) Gate enforcement on directional fan-out. The detection prediction and
#    logging are unchanged; we only SKIP enforcement when the host did not
#    actually initiate contact with >1 host (i.e. it's a victim/responder).
EDITS.append((
    "                if self.mode in (\"flat\", \"static\"):\n"
    "                    action = \"MONITOR\"\n"
    "\n"
    "                if action == \"QUARANTINE\":\n"
    "                    self.enforce_quarantine(rec.src_ip)\n"
    "                elif action == \"RESTRICT\":\n"
    "                    self.enforce_restrict(rec.src_ip, rec.dst_ip)\n"
    "                # MONITOR: no enforcement action needed.",

    "                if self.mode in (\"flat\", \"static\"):\n"
    "                    action = \"MONITOR\"\n"
    "\n"
    "                # DIRECTIONAL GUARD: a host is only contained if it was the\n"
    "                # INITIATOR of multi-host contact. A victim whose flows are\n"
    "                # replies has initiated_recent <= 1 and is spared, fixing the\n"
    "                # victim-quarantine bug. (Applies to the adaptive configs;\n"
    "                # flat/static already forced MONITOR above.)\n"
    "                init_recent = self.initiated_hosts_recent(rec.src_ip, rec.last_time)\n"
    "                if action in (\"QUARANTINE\", \"RESTRICT\") and init_recent <= 1:\n"
    "                    print(f\"    [directional] sparing {rec.src_ip}: \"\n"
    "                          f\"initiated_recent={init_recent} (responder, not \"\n"
    "                          f\"initiator) -- {action} suppressed\", flush=True)\n"
    "                    action = \"MONITOR\"\n"
    "\n"
    "                if action == \"QUARANTINE\":\n"
    "                    self.enforce_quarantine(rec.src_ip)\n"
    "                elif action == \"RESTRICT\":\n"
    "                    self.enforce_restrict(rec.src_ip, rec.dst_ip)\n"
    "                # MONITOR: no enforcement action needed.",
))

for i, (old, new) in enumerate(EDITS, 1):
    n = src.count(old)
    if n != 1:
        sys.exit(f"ABORT: edit {i} matched {n} times (expected 1). No file written.")
    src = src.replace(old, new)

shutil.copy(F, F.replace("simple_switch.py", "simple_switch_before_directional.py"))
open(F, "w").write(src)
print("Patched. Backup -> simple_switch_before_directional.py")
