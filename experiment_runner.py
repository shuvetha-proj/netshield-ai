#!/usr/bin/env python3
"""
Runs ONE configuration end-to-end and writes results/exp_<mode>.json.
The controller must ALREADY be running in the SAME mode (via mode.txt).

Usage:  sudo python3 experiment_runner.py <flat|static|rule|ml>

Scenario: HR (10.0.0.1) is the infected host. It runs repeated waves of
lateral probes toward Finance, Critical and Guest. After each wave we wait
for the controller to flush+enforce, then measure what HR can still reach
and whether legitimate Finance->Critical traffic survives.
"""
import json, os, sys, time, shutil

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel

BASE = os.path.dirname(os.path.abspath(__file__))
LATERAL = os.path.join(BASE, "lateral_movement_sim.py")
LABEL = os.path.join(BASE, "current_label.txt")
DECISIONS = os.path.join(BASE, "decisions_log.csv")
RESULTS = os.path.join(BASE, "results"); os.makedirs(RESULTS, exist_ok=True)

IP = {"hr": "10.0.0.1", "fin": "10.0.0.2", "crit": "10.0.0.3", "guest": "10.0.0.4"}
WAVES = 4
SETTLE = 7          # > FLOW_IDLE_TIMEOUT(3) so flows flush and enforce
MODE = sys.argv[1] if len(sys.argv) > 1 else "ml"


def ping(src, dst_ip):
    return "1 received" in src.cmd(f"ping -c1 -W1 {dst_ip}")


def set_label(v):
    open(LABEL, "w").write(v + "\n")


def main():
    # clean decision log so results/decisions_<mode>.csv is this run only
    open(DECISIONS, "w").write(
        "timestamp,src_ip,dst_ip,ml_prediction,risk_score,action\n")

    net = Mininet(controller=RemoteController)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    h = {n: net.addHost(n, ip=IP[n]) for n in IP}
    s1 = net.addSwitch("s1")
    for n in IP:
        net.addLink(h[n], s1)
    net.build(); net.get("c0").start(); s1.start([net.get("c0")])
    time.sleep(3)  # let controller install baseline flows

    hr, fin, crit, guest = h["hr"], h["fin"], h["crit"], h["guest"]
    res = {"mode": MODE, "waves": []}

    # --- Baseline: fan-out-1 legit pings (populate ARP, confirm reachability)
    set_label("normal")
    base = {
        "hr_to_fin":  ping(hr, IP["fin"]),
        "fin_to_crit": ping(fin, IP["crit"]),
        "crit_to_fin": ping(crit, IP["fin"]),
        "hr_to_guest": ping(hr, IP["guest"]),  # flat: True; others: blocked
    }
    res["baseline"] = base
    time.sleep(SETTLE)  # let baseline flows flush as 'normal' before attack

    # --- Attack waves
    t0 = time.time()
    contained_at = None
    for w in range(1, WAVES + 1):
        set_label("lateral_movement")
        hr.cmd(f"python3 {LATERAL} {IP['fin']} {IP['crit']} {IP['guest']} "
               f">/tmp/exp_attack.log 2>&1")
        time.sleep(SETTLE)
        reach = {
            "fin":   ping(hr, IP["fin"]),
            "crit":  ping(hr, IP["crit"]),
            "guest": ping(hr, IP["guest"]),
        }
        legit_fin_crit = ping(fin, IP["crit"])   # must stay up (no collateral)
        res["waves"].append({"wave": w, "hr_reaches": reach,
                             "legit_fin_crit": legit_fin_crit,
                             "t": round(time.time() - t0, 1)})
        if contained_at is None and not reach["crit"]:
            contained_at = round(time.time() - t0, 1)

    # --- Metrics
    last = res["waves"][-1]["hr_reaches"]
    res["protected_reachable_final"] = int(last["fin"]) + int(last["crit"])
    res["crit_reachable_final"] = last["crit"]
    res["fin_reachable_final"] = last["fin"]
    res["guest_reachable_final"] = last["guest"]
    res["contained_crit"] = contained_at is not None
    res["time_to_contain_s"] = contained_at
    res["legit_preserved"] = all(x["legit_fin_crit"] for x in res["waves"])

    with open(os.path.join(RESULTS, f"exp_{MODE}.json"), "w") as f:
        json.dump(res, f, indent=2)
    try:
        shutil.copy(DECISIONS, os.path.join(RESULTS, f"decisions_{MODE}.csv"))
    except Exception:
        pass

    print(json.dumps(res, indent=2))
    print(f"\n[{MODE}] protected hosts HR can still reach at end: "
          f"{res['protected_reachable_final']}/2  "
          f"| contained={res['contained_crit']} "
          f"| time_to_contain={res['time_to_contain_s']}s "
          f"| legit_preserved={res['legit_preserved']}")
    net.stop()


if __name__ == "__main__":
    setLogLevel("warning")
    main()
