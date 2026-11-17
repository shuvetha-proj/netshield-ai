#!/usr/bin/env python3
"""Wire ConnectionTracker into simple_switch.py: import it, extract TCP flags
+ src_port in packet_in_handler, observe() each TCP packet, sweep() periodically.
Asserts each anchor matches exactly once."""
import os, sys

F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_switch.py")
src = open(F).read()
if "ConnectionTracker" in src:
    sys.exit("Already patched -- no changes made.")

edits = []

# 1) import the tracker (after the risk_engine import)
edits.append((
    "from risk_engine import compute_risk",
    "from risk_engine import compute_risk\nfrom connection_tracker import ConnectionTracker",
))

# 2) create a tracker instance (right after self.flows = {})
edits.append((
    "        self.flows = {}\n",
    "        self.flows = {}\n        self.conn_tracker = ConnectionTracker()\n",
))

# 3) in packet_in_handler, capture src_port + tcp flags where dst_port is set
edits.append((
    "            tcp_pkt = pkt.get_protocol(tcp.tcp)\n"
    "            udp_pkt = pkt.get_protocol(udp.udp)\n"
    "            if tcp_pkt:\n"
    "                dst_port = tcp_pkt.dst_port\n"
    "            elif udp_pkt:\n"
    "                dst_port = udp_pkt.dst_port\n",

    "            tcp_pkt = pkt.get_protocol(tcp.tcp)\n"
    "            udp_pkt = pkt.get_protocol(udp.udp)\n"
    "            _src_port = None; _tcp_flags = 0\n"
    "            if tcp_pkt:\n"
    "                dst_port = tcp_pkt.dst_port\n"
    "                _src_port = tcp_pkt.src_port\n"
    "                _tcp_flags = tcp_pkt.bits\n"
    "                # feed the connection tracker (for conn-rate / failed-ratio)\n"
    "                self.conn_tracker.observe(src_ip, dst_ip, _src_port,\n"
    "                                          dst_port, 'TCP', _tcp_flags)\n"
    "            elif udp_pkt:\n"
    "                dst_port = udp_pkt.dst_port\n",
))

# 4) sweep() the tracker each time idle flows are flushed (runs ~every second)
edits.append((
    "    def flush_idle_flows(self):\n",
    "    def flush_idle_flows(self):\n        self.conn_tracker.sweep()\n",
))

for i, (old, new) in enumerate(edits, 1):
    n = src.count(old)
    if n != 1:
        sys.exit(f"ABORT: edit {i} matched {n} times (expected 1). No change.")
    src = src.replace(old, new)

open(F, "w").write(src)
print("Patched simple_switch.py -- ConnectionTracker wired in.")
