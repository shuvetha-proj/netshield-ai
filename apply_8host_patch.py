#!/usr/bin/env python3
"""Expand the controller for the 8-host VLAN topology: add a VLAN/segment map
and the Guest-isolation ACL for all 8 hosts. Asserts the anchor matches once."""
import os, sys

F = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_switch.py")
src = open(F).read()
if "VLAN_SEGMENT" in src:
    sys.exit("Already patched (VLAN_SEGMENT present) -- no changes made.")

OLD = (
'        # Host IPs: hr=10.0.0.1, fin=10.0.0.2, crit=10.0.0.3, guest=10.0.0.4\n'
'        # Policy: HR, Finance, and Critical can all talk to each other.\n'
'        # Guest is fully isolated from everyone (both directions).\n'
'        self.blocked_pairs = {\n'
"            ('10.0.0.4', '10.0.0.1'), ('10.0.0.1', '10.0.0.4'),  # guest <-> hr\n"
"            ('10.0.0.4', '10.0.0.2'), ('10.0.0.2', '10.0.0.4'),  # guest <-> fin\n"
"            ('10.0.0.4', '10.0.0.3'), ('10.0.0.3', '10.0.0.4'),  # guest <-> crit\n"
'        }\n'
)

NEW = (
'        # ===== 8-HOST VLAN TOPOLOGY (Review 3) =====\n'
'        # Each host is associated with its VLAN/segment ID (logical\n'
'        # segmentation -- the controller enforces policy BETWEEN segments,\n'
'        # not by IP subnet alone). VLAN99 is the Quarantine segment.\n'
'        self.VLAN_SEGMENT = {\n'
'            "10.0.0.1": ("HR", 10), "10.0.0.8": ("Admin", 60),\n'
'            "10.0.0.2": ("Finance", 20),\n'
'            "10.0.0.3": ("Server", 30), "10.0.0.5": ("Server", 30),\n'
'            "10.0.0.4": ("Guest", 40),\n'
'            "10.0.0.6": ("IoT", 50), "10.0.0.7": ("IoT", 50),\n'
'        }\n'
'        self.QUARANTINE_VLAN = 99   # compromised hosts are moved here\n'
'        self.quarantine_vlan_members = set()\n'
'\n'
'        # Static ACL policy: the Guest segment (VLAN40) is fully isolated\n'
'        # from every other segment, in both directions.\n'
'        GUEST = "10.0.0.4"\n'
'        _others = ["10.0.0.1","10.0.0.2","10.0.0.3","10.0.0.5",\n'
'                   "10.0.0.6","10.0.0.7","10.0.0.8"]\n'
'        self.blocked_pairs = set()\n'
'        for _o in _others:\n'
'            self.blocked_pairs.add((GUEST, _o))\n'
'            self.blocked_pairs.add((_o, GUEST))\n'
)

if src.count(OLD) != 1:
    sys.exit(f"ABORT: anchor matched {src.count(OLD)} times (expected 1). No change.")
src = src.replace(OLD, NEW)
open(F, "w").write(src)
print("Patched simple_switch.py for 8-host VLAN topology.")
