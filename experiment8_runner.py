#!/usr/bin/env python3
"""
experiment8_runner.py -- Review 3 comparison on the 8-host topology.

The controller must ALREADY be running in the configuration being measured:
  flat   : NETSHIELD_MODE=flat   python3 run_controller.py
  static : NETSHIELD_MODE=static python3 run_controller.py
  rule   : NETSHIELD_MODE=rule   python3 run_controller.py
  ml5    : NETSHIELD_MODE=ml RISK_MODEL=5factor python3 run_controller.py
  ml2    : NETSHIELD_MODE=ml RISK_MODEL=2factor python3 run_controller.py
  mlgc   : NETSHIELD_MODE=ml RISK_MODEL=5factor GRAPH_CUT=on python3 run_controller.py
topology_8host.py must NOT be running (this script builds its own s1).

Usage: sudo python3 experiment8_runner.py <config> [runs] [scenarios]
  config    : flat | static | rule | ml5 | ml2  (label; must match controller)
  runs      : repeats per scenario (default 3)
  scenarios : comma list of benign,lateral,scan (default all, in that order)

Writes results/exp8/<config>_<scenario>_run<k>.json.
Never touches results/exp_*.json (Review 2) and never truncates decisions_log.csv.
"""
import csv, json, os, re, sys, time

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel

BASE = os.path.dirname(os.path.abspath(__file__))
LATERAL = os.path.join(BASE, "lateral_movement_sim.py")
SCAN = os.path.join(BASE, "scan_sim.py")
LABEL = os.path.join(BASE, "current_label.txt")
CLEAR = os.path.join(BASE, "clear_trigger.txt")
DECISIONS = os.path.join(BASE, "decisions_log.csv")
OUT = os.path.join(BASE, "results", "exp8")

HOSTS = {  # identical to topology_8host.py
    "hr": "10.0.0.1", "fin": "10.0.0.2", "fileserver": "10.0.0.3",
    "guest": "10.0.0.4", "database": "10.0.0.5", "iot1": "10.0.0.6",
    "iot2": "10.0.0.7", "admin": "10.0.0.8",
}
CRITICAL = ["fileserver", "database"]
CONFIGS = ("flat", "static", "rule", "ml5", "ml2", "mlgc")
CONTAIN = ("RESTRICT", "QUARANTINE")
SETTLE = 8   # > FLOW_IDLE_TIMEOUT (3 s) so flows flush and enforce
GAP = 12     # > HOST_ACTIVITY_WINDOW / RATE_WINDOW (10 s): history expires
WAVES = 3

UID = int(os.environ.get("SUDO_UID", os.getuid()))
GID = int(os.environ.get("SUDO_GID", os.getgid()))


def own(path):
    try:
        os.chown(path, UID, GID)
    except OSError:
        pass


def write_user_file(path, text):
    with open(path, "w") as f:
        f.write(text)
    own(path)   # controller runs as the normal user and must be able to truncate it


def set_label(v):
    write_user_file(LABEL, v + "\n")


def ping(src, dst_ip):
    m = re.search(r"(\d+) received", src.cmd(f"ping -c2 -W1 {dst_ip}"))
    return bool(m and int(m.group(1)) > 0)


def log_size():
    return os.path.getsize(DECISIONS) if os.path.exists(DECISIONS) else 0


def decisions_since(offset):
    rows = []
    if not os.path.exists(DECISIONS):
        return rows
    with open(DECISIONS) as f:
        f.seek(offset)
        for r in csv.reader(f):
            if len(r) < 6:
                continue
            try:
                t = time.mktime(time.strptime(r[0], "%Y-%m-%d %H:%M:%S"))
                risk = float(r[4])
            except ValueError:
                continue
            rows.append({"t": t, "src": r[1], "dst": r[2], "pred": r[3],
                         "risk": risk, "action": r[5]})
    return rows


def clear_controller():
    write_user_file(CLEAR, "all")
    for _ in range(20):
        time.sleep(0.5)
        if os.path.getsize(CLEAR) == 0:
            return True
    return False


def analyse(rows, t0, att_ip, target_ip=None):
    att = [r for r in rows if r["src"] == att_ip]
    hits = [r for r in att if r["action"] in CONTAIN
            and (target_ip is None or r["dst"] == target_ip)]
    others = [r for r in rows if r["src"] != att_ip]
    return {
        "time_to_contain_s": round(max(0.0, min(r["t"] for r in hits) - t0), 1) if hits else None,
        "attacker_actions": {a: sum(1 for r in att if r["action"] == a)
                             for a in ("MONITOR", "RESTRICT", "QUARANTINE")},
        "attacker_max_risk": max((r["risk"] for r in att), default=None),
        "others_max_risk": max((r["risk"] for r in others), default=None),
        "collateral_hosts": sorted({r["src"] for r in others if r["action"] in CONTAIN}),
        "rows": [{"dt": round(r["t"] - t0, 1), **{k: r[k] for k in ("src", "dst", "pred", "risk", "action")}} for r in rows],
    }


def run_benign(h):
    pairs = [("hr", "fileserver"), ("fin", "database"), ("admin", "fileserver"),
             ("admin", "database"), ("iot1", "admin"), ("iot2", "admin")]
    set_label("normal")
    off, t0 = log_size(), time.time()
    ok = {f"{a}->{b}": True for a, b in pairs}
    for _ in range(3):
        for a, b in pairs:
            ok[f"{a}->{b}"] = ping(h[a], HOSTS[b]) and ok[f"{a}->{b}"]
        time.sleep(2)
    time.sleep(SETTLE)
    rows = decisions_since(off)
    fps = [r for r in rows if r["action"] in CONTAIN]
    return {"benign_pairs_ok": ok,
            "false_containments": len(fps),
            "false_containment_detail": [f'{r["src"]}->{r["dst"]} {r["action"]} {r["risk"]}' for r in fps],
            "max_risk": max((r["risk"] for r in rows), default=None),
            "decisions": len(rows),
            "rows": [{"dt": round(r["t"] - t0, 1), **{k: r[k] for k in ("src", "dst", "pred", "risk", "action")}} for r in rows]}


def run_lateral(h, att="hr"):
    targets = [ip for n, ip in HOSTS.items() if n != att]
    set_label("lateral_movement")
    off, t0 = log_size(), time.time()
    for _ in range(WAVES):
        h[att].cmd(f"python3 {LATERAL} {' '.join(targets)} > /tmp/exp8_lateral.log 2>&1")
        time.sleep(SETTLE)
    set_label("normal")
    legit = {f"{a}->{b}": ping(h[a], HOSTS[b]) for a, b in [p for p in [("fin", "database"), ("admin", "fileserver"),
                                      ("hr", "fileserver"), ("iot1", "admin")] if att not in p][:2]}
    reach = {n: ping(h[att], HOSTS[n]) for n in HOSTS if n != att}
    res = {"attacker": att, "reach": reach,
           "hosts_reached": sum(reach.values()),
           "critical_reached": sum(reach[c] for c in CRITICAL if c != att),
           "critical_total": sum(1 for c in CRITICAL if c != att),
           "contained": all(not reach[c] for c in CRITICAL if c != att),
           "legit": legit, "legit_preserved": all(legit.values())}
    res.update(analyse(decisions_since(off), t0, HOSTS[att]))
    return res


def run_scan(h):
    att, tgt = "iot2", "database"
    set_label("attack")
    off, t0 = log_size(), time.time()
    h[att].cmd(f"python3 {SCAN} {HOSTS[tgt]} 1 150 > /tmp/exp8_scan.log 2>&1")
    time.sleep(SETTLE)
    set_label("normal")
    legit = {f"{a}->{b}": ping(h[a], HOSTS[b]) for a, b in [("hr", "fileserver"), ("fin", "database")]}
    res = {"attacker": att, "target": tgt,
           "target_reachable": ping(h[att], HOSTS[tgt]),
           "attacker_other_access": ping(h[att], HOSTS["fileserver"]),
           "attacker_noncritical_access": ping(h[att], HOSTS["hr"]),
           "legit": legit, "legit_preserved": all(legit.values())}
    res.update(analyse(decisions_since(off), t0, HOSTS[att], HOSTS[tgt]))
    return res


RUNNERS = {"benign": run_benign, "lateral": run_lateral, "scan": run_scan}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in CONFIGS:
        raise SystemExit(f"usage: sudo python3 {sys.argv[0]} <{'|'.join(CONFIGS)}> [runs] [scenarios]")
    config = sys.argv[1]
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    scenarios = sys.argv[3].split(",") if len(sys.argv) > 3 else ["benign", "lateral", "scan"]
    assert all(s in RUNNERS or s == "lateralall" for s in scenarios), f"unknown scenario in {scenarios}"
    os.makedirs(OUT, exist_ok=True); own(os.path.dirname(OUT)); own(OUT)

    net = Mininet(controller=RemoteController)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    h = {n: net.addHost(n, ip=ip) for n, ip in HOSTS.items()}
    s1 = net.addSwitch("s1")
    for n in HOSTS:
        net.addLink(h[n], s1)
    net.start()
    try:
        try:
            net.waitConnected(timeout=15)
        except (AttributeError, TypeError):
            time.sleep(5)
        time.sleep(3)
        if not clear_controller():
            raise SystemExit("ERROR: controller did not consume clear_trigger.txt -- is it running?")
        time.sleep(GAP)
        jobs = []
        for sc in scenarios:
            jobs += [(sc, a) for a in HOSTS] if sc == "lateralall" else [(sc, None)]
        for sc, att in jobs:
            for k in range(1, runs + 1):
                tag = f"{sc}_{att}" if att else sc
                print(f"[{config}] {tag} run {k}/{runs} ...", flush=True)
                res = run_lateral(h, att) if att else RUNNERS[sc](h)
                res.update({"config": config, "scenario": sc, "run": k,
                            "finished": time.strftime("%Y-%m-%d %H:%M:%S")})
                path = os.path.join(OUT, f"{config}_{tag}_run{k}.json")
                with open(path, "w") as f:
                    json.dump(res, f, indent=2)
                own(path)
                brief = {k2: res[k2] for k2 in ("hosts_reached", "critical_reached", "contained",
                         "target_reachable", "attacker_other_access", "time_to_contain_s",
                         "collateral_hosts", "legit_preserved", "false_containments",
                         "attacker_max_risk", "others_max_risk", "max_risk") if k2 in res}
                print(f"    {brief}", flush=True)
                if not clear_controller():
                    print("    WARNING: clear not consumed", flush=True)
                set_label("normal")
                time.sleep(GAP)
    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("warning")
    main()
