#!/usr/bin/env python3
"""
8-host VLAN-segmented topology (Review 3).
Eight hosts across six network segments (VLANs). Segmentation is LOGICAL:
the controller associates each host with a VLAN/segment ID and enforces the
policy BETWEEN segments, rather than relying on IP alone. A quarantined host
is cut off from every segment, representing a move into the Quarantine VLAN99.

Run with: sudo python3 topology_8host.py
"""
import os
import threading
import time

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACK_TRIGGER_FILE = os.path.join(BASE_DIR, "attack_trigger.txt")
LATERAL_SCRIPT = os.path.join(BASE_DIR, "lateral_movement_sim.py")
SCAN_SCRIPT = os.path.join(BASE_DIR, "scan_sim.py")
LABEL_FILE = os.path.join(BASE_DIR, "current_label.txt")

# name -> (ip, segment_name, vlan_id). VLAN id is the LOGICAL segment identity.
HOSTS = {
    "hr":         ("10.0.0.1", "HR",      10),
    "fin":        ("10.0.0.2", "Finance", 20),
    "fileserver": ("10.0.0.3", "Server",  30),
    "guest":      ("10.0.0.4", "Guest",   40),
    "database":   ("10.0.0.5", "Server",  30),
    "iot1":       ("10.0.0.6", "IoT",     50),
    "iot2":       ("10.0.0.7", "IoT",     50),
    "admin":      ("10.0.0.8", "Admin",   60),
}
HOSTS_BY_NAME = {name: ip for name, (ip, _, _) in HOSTS.items()}
QUARANTINE_VLAN = 99  # where a compromised host is logically moved


def attack_trigger_watcher(net):
    last_seen = ""
    while True:
        time.sleep(1)
        try:
            if not os.path.exists(ATTACK_TRIGGER_FILE):
                continue
            with open(ATTACK_TRIGGER_FILE) as f:
                content = f.read().strip()
            if not content or content == last_seen:
                continue
            last_seen = content
            parts = content.split(":")
            kind = parts[0]

            if kind == "lateral" and len(parts) >= 2:
                src_name = parts[1]
                if src_name not in HOSTS_BY_NAME:
                    print(f"[attack_trigger] unknown host: {src_name}")
                    continue
                src_ip = HOSTS_BY_NAME[src_name]
                targets = [ip for name, ip in HOSTS_BY_NAME.items() if name != src_name]
                host = net.get(src_name)
                print(f"[attack_trigger] lateral movement from {src_name} ({src_ip}) -> {targets}")
                with open(LABEL_FILE, "w") as f:
                    f.write("lateral_movement\n")
                host.cmd(f"python3 {LATERAL_SCRIPT} {' '.join(targets)} "
                         f"> /tmp/attack_{src_name}.log 2>&1 &")

            elif kind == "scan" and len(parts) >= 3:
                src_name, dst_name = parts[1], parts[2]
                if src_name not in HOSTS_BY_NAME or dst_name not in HOSTS_BY_NAME:
                    print(f"[attack_trigger] unknown host(s): {src_name}, {dst_name}")
                    continue
                dst_ip = HOSTS_BY_NAME[dst_name]
                host = net.get(src_name)
                print(f"[attack_trigger] port scan from {src_name} -> {dst_name} ({dst_ip})")
                with open(LABEL_FILE, "w") as f:
                    f.write("attack\n")
                host.cmd(f"python3 {SCAN_SCRIPT} {dst_ip} 1 150 "
                         f"> /tmp/scan_{src_name}.log 2>&1 &")
            else:
                print(f"[attack_trigger] unrecognized trigger: {content}")

            open(ATTACK_TRIGGER_FILE, "w").close()
            last_seen = ""
        except Exception as e:
            print(f"[attack_trigger] error: {e}")


def create_topology():
    net = Mininet(controller=RemoteController)

    print("*** Adding controller")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    print("*** Adding 8 hosts across 6 VLAN segments")
    host_objs = {}
    for name, (ip, segment, vlan) in HOSTS.items():
        host_objs[name] = net.addHost(name, ip=ip)
        print(f"    {name:11s} {ip:11s}  segment={segment:8s} VLAN={vlan}")

    print("*** Adding core switch")
    s1 = net.addSwitch('s1')

    print("*** Creating links")
    for name, h in host_objs.items():
        net.addLink(h, s1)

    print("*** Starting network")
    net.build()
    c0.start()
    s1.start([c0])

    print("*** Starting attack-trigger watcher (background)")
    threading.Thread(target=attack_trigger_watcher, args=(net,), daemon=True).start()

    print("")
    print("*** 8-host VLAN-segmented network ready ***")
    print("***   VLAN10 HR      : hr")
    print("***   VLAN20 Finance : fin")
    print("***   VLAN30 Server  : fileserver, database  (critical assets)")
    print("***   VLAN40 Guest   : guest  (isolated)")
    print("***   VLAN50 IoT     : iot1, iot2")
    print("***   VLAN60 Admin   : admin")
    print("***   VLAN99 Quarantine : (compromised hosts moved here on quarantine)")
    print("*** Running CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
