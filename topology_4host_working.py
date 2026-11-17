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

HOSTS_BY_NAME = {
    "hr": "10.0.0.1",
    "fin": "10.0.0.2",
    "crit": "10.0.0.3",
    "guest": "10.0.0.4",
}


def attack_trigger_watcher(net):
    """Runs in a background thread. Watches ATTACK_TRIGGER_FILE for a line
    like 'lateral:hr' or 'scan:hr:fin' written by the dashboard, and
    launches the matching attack script inside that host's namespace.
    """
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
                targets = [ip for name, ip in HOSTS_BY_NAME.items()
                           if name != src_name]
                host = net.get(src_name)
                print(f"[attack_trigger] launching lateral movement from "
                      f"{src_name} ({src_ip}) -> {targets}")
                with open(LABEL_FILE, "w") as f:
                    f.write("lateral_movement\n")
                targets_str = " ".join(targets)
                host.cmd(f"python3 {LATERAL_SCRIPT} {targets_str} "
                         f"> /tmp/attack_{src_name}.log 2>&1 &")

            elif kind == "scan" and len(parts) >= 3:
                src_name, dst_name = parts[1], parts[2]
                if src_name not in HOSTS_BY_NAME or dst_name not in HOSTS_BY_NAME:
                    print(f"[attack_trigger] unknown host(s): {src_name}, {dst_name}")
                    continue
                dst_ip = HOSTS_BY_NAME[dst_name]
                host = net.get(src_name)
                print(f"[attack_trigger] launching port scan from "
                      f"{src_name} -> {dst_name} ({dst_ip})")
                with open(LABEL_FILE, "w") as f:
                    f.write("attack\n")
                host.cmd(f"python3 {SCAN_SCRIPT} {dst_ip} 1 150 "
                         f"> /tmp/scan_{src_name}.log 2>&1 &")

            else:
                print(f"[attack_trigger] unrecognized trigger: {content}")

            # clear the trigger so we don't repeat it
            open(ATTACK_TRIGGER_FILE, "w").close()
            last_seen = ""

        except Exception as e:
            print(f"[attack_trigger] error: {e}")


def create_topology():
    net = Mininet(controller=RemoteController)

    print("*** Adding controller")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    print("*** Adding hosts")
    hr = net.addHost('hr', ip='10.0.0.1')
    fin = net.addHost('fin', ip='10.0.0.2')
    crit = net.addHost('crit', ip='10.0.0.3')
    guest = net.addHost('guest', ip='10.0.0.4')

    print("*** Adding switch")
    s1 = net.addSwitch('s1')

    print("*** Creating links")
    net.addLink(hr, s1)
    net.addLink(fin, s1)
    net.addLink(crit, s1)
    net.addLink(guest, s1)

    print("*** Starting network")
    net.build()
    c0.start()
    s1.start([c0])

    print("*** Starting attack-trigger watcher (background)")
    watcher = threading.Thread(target=attack_trigger_watcher, args=(net,), daemon=True)
    watcher.start()

    print("*** Running CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
