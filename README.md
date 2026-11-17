# NetShield-AI: ML-Driven Adaptive Micro-Segmentation for Ransomware Lateral-Movement Containment

NetShield-AI detects ransomware-style lateral movement inside a network and contains it automatically. A Software-Defined Networking (SDN) controller watches every flow, a Random Forest model classifies it, a five-factor risk score decides how serious it is, and the controller installs OpenFlow rules to monitor, restrict one link, or quarantine only the infected host, while normal traffic keeps flowing.

## How it works

Scapy traffic -> Open vSwitch (OpenFlow 1.3) -> os-ken controller -> flow features + connection tracking -> Random Forest -> five-factor risk score -> safeguards -> OpenFlow drop rule -> decision log -> user interface (Flask, port 5001)

Risk score: R = 100 x (0.35 P + 0.15 C + 0.15 F + 0.20 H + 0.15 D)

| Factor | Meaning |
| --- | --- |
| P | ML probability that the flow is not normal (Random Forest) |
| C | Connection rate (attempts per second over 10 s, divided by 20, capped at 1) |
| F | Failed-connection ratio (no SYN-ACK within 3 s) |
| H | Fan-out (distinct hosts contacted, divided by 3, capped at 1) |
| D | Destination criticality (FileServer and Database highest) |

| Risk | Action |
| --- | --- |
| below 30 | MONITOR (log only) |
| 30 to 70 | RESTRICT (block one source-destination pair) |
| 70 and above | QUARANTINE (cut the host off) |

## Network topology

Eight Mininet hosts on one Open vSwitch, in six logical VLANs enforced by the controller.

| Host | IP | VLAN | Role |
| --- | --- | --- | --- |
| HR | 10.0.0.1 | 10 | Workstation |
| Finance | 10.0.0.2 | 20 | Workstation |
| FileServer | 10.0.0.3 | 30 | Critical asset |
| Guest | 10.0.0.4 | 40 | Guest (isolated by static ACL) |
| Database | 10.0.0.5 | 30 | Critical asset |
| IoT-1 | 10.0.0.6 | 50 | IoT device |
| IoT-2 | 10.0.0.7 | 50 | IoT device |
| Admin | 10.0.0.8 | 60 | Administrative host |

VLAN 99 is the logical quarantine zone.

## Main files

| File | Purpose |
| --- | --- |
| topology_8host.py | Builds the 8-host Mininet network |
| run_controller.py | Starts the os-ken controller (port 6633) |
| simple_switch.py | Controller: flow tracking, ML prediction, risk, safeguards, OpenFlow enforcement |
| connection_tracker.py | Connection rate and failed-connection ratio |
| risk_engine_v2.py | Five-factor risk model |
| rule_baseline.py | Threshold-rule detector (non-ML baseline) |
| live_graph.py | NetworkX reachability graph and path cutting |
| lateral_movement_sim.py, scan_sim.py, normal_traffic.py | Scapy traffic generators |
| train_model_v2.py | Trains the Random Forest on flow_stats.csv |
| graph_dashboard.py | Flask user interface on port 5001 |
| experiment8_runner.py | Runs the recorded experiments |
| build_compare_r3.py, build_compare8.py | Build the comparison pages |

## How to run

Terminal 1: `RISK_MODEL=5factor python3 run_controller.py`

Terminal 2: `echo reset > attack_trigger.txt && sudo mn -c && sudo python3 topology_8host.py`

Terminal 3: `python3 graph_dashboard.py`, then open http://localhost:5001

Comparison page: `python3 build_compare_r3.py && explorer.exe compare_review3.html`

## Results

54 runs (6 configurations x 3 scenarios x 3 repetitions) plus 32 runs with each host as the attacker.

| Configuration | HR attack: hosts reached (of 7) | Contained | Benign: false quarantines | Benign flows mislabelled |
| --- | --- | --- | --- | --- |
| Flat | 7 | 0/3 | 0 | 6% |
| Static segmentation | 6 | 0/3 | 0 | 6% |
| Rule-based adaptive | 0 | 3/3 | 6 | 41% |
| ML five-factor | 0 | 3/3 | 0 | 9% |

Random Forest macro-F1 0.985 on the project dataset (rule baseline 0.749); about 99.99% accuracy on CIC-IDS2017 PortScan data.

## Limitations

Simulated network and attacks; logical VLANs without 802.1Q tagging; some false link restrictions on the Admin host remain.
