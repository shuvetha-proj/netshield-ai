import csv
import json
import os
import time
from collections import defaultdict

import pandas as pd
import joblib

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import arp
from os_ken.lib.packet import tcp
from os_ken.lib.packet import udp
from os_ken.lib import hub

from risk_engine import compute_risk
from connection_tracker import ConnectionTracker
from risk_engine_v2 import compute_risk_v2
from live_graph import LiveReachabilityGraph
RISK_MODEL = os.environ.get('RISK_MODEL', '2factor').lower()
GRAPH_CUT = os.environ.get('GRAPH_CUT', 'off').lower() == 'on'
SCAN_PORT_MIN = int(os.environ.get('SCAN_PORT_MIN', '20'))
from rule_baseline import rule_decide

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "blocked_log.csv")
FLOW_LOG_FILE = os.path.join(BASE_DIR, "flow_stats.csv")
LABEL_FILE = os.path.join(BASE_DIR, "current_label.txt")
MODEL_PATH = os.path.join(BASE_DIR, "ransomware_model_v2.joblib")
DECISION_LOG_FILE = os.path.join(BASE_DIR, "decisions_log.csv")
LIVE_STATE_FILE = os.path.join(BASE_DIR, "live_state.json")
GRAPH_STATE_FILE = os.path.join(BASE_DIR, "graph_state.json")
CLEAR_TRIGGER_FILE = os.path.join(BASE_DIR, "clear_trigger.txt")

DROP_PRIORITY = 10          # static ACL drops (Guest isolation)
RESTRICT_PRIORITY = 20      # ML-driven single-pair restrictions
QUARANTINE_PRIORITY = 30    # ML-driven full-host quarantine (highest priority)
DROP_IDLE_TIMEOUT = 60
# NOTE: RESTRICT and QUARANTINE are now PERMANENT (idle_timeout=0) until a
# human analyst manually clears them via the dashboard. This mirrors real
# incident response: automated containment is instant, but recovery
# requires manual confirmation that the threat is actually resolved.
RESTRICT_IDLE_TIMEOUT = 0
QUARANTINE_IDLE_TIMEOUT = 0

FLOW_IDLE_TIMEOUT = 3
FLOW_CHECK_PERIOD = 1

HOST_ACTIVITY_WINDOW = 10

ML_FEATURES = [
    "distinct_dst_ports",
    "distinct_dst_hosts_recent",
    "has_icmp",
    "has_tcp",
    "has_udp",
    "has_arp",
]


class FlowRecord:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.start_time = time.time()
        self.last_time = self.start_time
        self.packet_count = 0
        self.byte_count = 0
        self.dst_ports = set()
        self.protocols = set()

    def update(self, length, dst_port, proto):
        self.last_time = time.time()
        self.packet_count += 1
        self.byte_count += length
        if dst_port is not None:
            self.dst_ports.add(dst_port)
        self.protocols.add(proto)

    def is_idle(self, now):
        return (now - self.last_time) > FLOW_IDLE_TIMEOUT

    def to_row(self, label, distinct_dst_hosts_recent):
        duration = max(self.last_time - self.start_time, 0.001)
        pps = self.packet_count / duration
        return [
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.start_time)),
            self.src_ip,
            self.dst_ip,
            round(duration, 3),
            self.packet_count,
            self.byte_count,
            len(self.dst_ports),
            round(pps, 2),
            "+".join(sorted(self.protocols)),
            distinct_dst_hosts_recent,
            label,
        ]

    def to_ml_features(self, distinct_dst_hosts_recent):
        proto_str = "+".join(sorted(self.protocols))
        return {
            "distinct_dst_ports": len(self.dst_ports),
            "distinct_dst_hosts_recent": distinct_dst_hosts_recent,
            "has_icmp": int("ICMP" in proto_str),
            "has_tcp": int("TCP" in proto_str),
            "has_udp": int("UDP" in proto_str),
            "has_arp": int("ARP" in proto_str),
        }


class SimpleSwitch13(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # ===== 8-HOST VLAN TOPOLOGY (Review 3) =====
        # Each host is associated with its VLAN/segment ID (logical
        # segmentation -- the controller enforces policy BETWEEN segments,
        # not by IP subnet alone). VLAN99 is the Quarantine segment.
        self.VLAN_SEGMENT = {
            "10.0.0.1": ("HR", 10), "10.0.0.8": ("Admin", 60),
            "10.0.0.2": ("Finance", 20),
            "10.0.0.3": ("Server", 30), "10.0.0.5": ("Server", 30),
            "10.0.0.4": ("Guest", 40),
            "10.0.0.6": ("IoT", 50), "10.0.0.7": ("IoT", 50),
        }
        self.QUARANTINE_VLAN = 99   # compromised hosts are moved here
        self.quarantine_vlan_members = set()

        # Static ACL policy: the Guest segment (VLAN40) is fully isolated
        # from every other segment, in both directions.
        GUEST = "10.0.0.4"
        _others = ["10.0.0.1","10.0.0.2","10.0.0.3","10.0.0.5",
                   "10.0.0.6","10.0.0.7","10.0.0.8"]
        self.blocked_pairs = set()
        for _o in _others:
            self.blocked_pairs.add((GUEST, _o))
            self.blocked_pairs.add((_o, GUEST))
        # live reachability graph (Review 3 -- path analysis + cutting)
        self.live_graph = LiveReachabilityGraph(self.blocked_pairs)

        # --- Experiment configuration switch (objective 7) ----------
        # NETSHIELD_MODE picks which of the 4 evaluated configs runs:
        #   flat   (A) no segmentation, no response
        #   static (B) Guest ACL only, no dynamic response
        #   rule   (C) Guest ACL + threshold-rule response (no ML)
        #   ml     (D) Guest ACL + ML-driven response        [default]
        _mode_file = os.path.join(BASE_DIR, 'mode.txt')
        _experiment = ('NETSHIELD_MODE' in os.environ) or os.path.exists(_mode_file)
        self.mode = (os.environ.get('NETSHIELD_MODE')
                     or (open(_mode_file).read().strip()
                         if os.path.exists(_mode_file) else 'ml')).lower()
        print(f'*** NETSHIELD_MODE = {self.mode}  (experiment={_experiment}) ***',
              flush=True)
        print(f'*** RISK_MODEL = {RISK_MODEL} ***', flush=True)
        print(f'*** GRAPH_CUT = {"on" if GRAPH_CUT else "off"} ***', flush=True)
        if self.mode == 'flat':
            self.blocked_pairs = set()   # config A: no static ACL at all
        # Experiment runs log flows to a per-mode scratch file so the
        # training dataset (flow_stats.csv) is never contaminated.
        self.flow_log_file = (
            os.path.join(BASE_DIR, f'flow_stats_exp_{self.mode}.csv')
            if _experiment else FLOW_LOG_FILE)
        # ------------------------------------------------------------

        self.flows = {}
        self.conn_tracker = ConnectionTracker()
        self.host_activity = defaultdict(dict)
        # Directional signal: hosts THIS src initiated a NEW flow to.
        # A pure responder never originates a flow, so this stays empty
        # for victims -- that's what keeps them from being quarantined.
        self.initiated_hosts = defaultdict(dict)

        # NEW: ML-driven enforcement state.
        # quarantined_hosts: source IPs fully cut off from everyone.
        # restricted_pairs: (src_ip, dst_ip) pairs blocked individually.
        self.quarantined_hosts = set()
        self.restricted_pairs = set()
        # NEW: remember exactly which (datapath, match) rules we installed,
        # so a manual clear can delete precisely those flow entries.
        self.quarantine_installs = defaultdict(list)   # src_ip -> [(datapath, match)]
        self.restrict_installs = defaultdict(list)     # (src_ip,dst_ip) -> [(datapath, match)]

        # Remember datapaths as they connect, so we can push rules to them
        # even when the decision happens outside packet_in_handler (i.e. in
        # the background flow monitor thread).
        self.datapaths = {}

        print(f"Loading ML model from {MODEL_PATH} ...", flush=True)
        self.model = joblib.load(MODEL_PATH)
        print("Model loaded successfully.", flush=True)

        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "dpid", "src_ip", "dst_ip",
                     "protocol", "src_mac", "dst_mac", "in_port"])

        if not os.path.exists(self.flow_log_file):
            with open(self.flow_log_file, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["start_time", "src_ip", "dst_ip", "duration_sec",
                     "packet_count", "byte_count", "distinct_dst_ports",
                     "packets_per_sec", "protocols",
                     "distinct_dst_hosts_recent", "label"])

        if not os.path.exists(DECISION_LOG_FILE):
            with open(DECISION_LOG_FILE, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "src_ip", "dst_ip", "ml_prediction",
                     "risk_score", "action"])

        if not os.path.exists(LABEL_FILE):
            with open(LABEL_FILE, "w") as f:
                f.write("normal\n")

        # NEW: in-memory history of recent decisions, for the live dashboard
        self.recent_decisions = []

        self.monitor_thread = hub.spawn(self._flow_monitor)
        self.live_state_thread = hub.spawn(self._live_state_writer)
        self.clear_trigger_thread = hub.spawn(self._clear_trigger_watcher)

    def _flow_monitor(self):
        while True:
            hub.sleep(FLOW_CHECK_PERIOD)
            self.flush_idle_flows()

    def _live_state_writer(self):
        """Writes a live snapshot of network state to LIVE_STATE_FILE every
        second, so the dashboard can poll it and show real-time activity."""
        while True:
            hub.sleep(1)
            try:
                state = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "active_flows": len(self.flows),
                    "active_flow_pairs": [
                        {"src": s, "dst": d} for (s, d) in self.flows.keys()
                    ],
                    "quarantined_hosts": sorted(self.quarantined_hosts),
                    "restricted_pairs": [
                        {"src": s, "dst": d} for (s, d) in self.restricted_pairs
                    ],
                    "recent_decisions": self.recent_decisions[-20:],
                }
                with open(LIVE_STATE_FILE, "w") as f:
                    json.dump(state, f)
                # --- live reachability graph snapshot (Review 3) ---
                try:
                    from live_graph import NAME as _GNAME, CRITICAL_ASSETS as _GCRIT, ALL_HOSTS as _GALL
                    _VLAN = {"10.0.0.1":10,"10.0.0.2":20,"10.0.0.3":30,
                             "10.0.0.4":40,"10.0.0.5":30,"10.0.0.6":50,
                             "10.0.0.7":50,"10.0.0.8":60}
                    _edges = [[s, d] for (s, d) in self.live_graph.G.edges()]
                    _quar = sorted(self.live_graph.quarantined)
                    # path status for any quarantined/active attacker
                    _attackers = _quar or [p['src'] for p in state['restricted_pairs']]
                    _paths = {}
                    for _atk in set(_attackers):
                        _a, _p = self.live_graph.path_to_critical(_atk)
                        _paths[_atk] = ([_GNAME.get(h,h) for h in _p] if _p else None)
                    gstate = {
                        "timestamp": state["timestamp"],
                        "hosts": [{"ip": h, "name": _GNAME.get(h,h),
                                   "vlan": _VLAN.get(h,0),
                                   "critical": h in _GCRIT,
                                   "quarantined": h in _quar} for h in _GALL],
                        "edges": _edges,
                        "quarantined": _quar,
                        "paths": _paths,
                    }
                    with open(GRAPH_STATE_FILE, "w") as gf:
                        json.dump(gstate, gf)
                except Exception as _ge:
                    pass
            except Exception as e:
                print(f"live_state_writer error: {e}", flush=True)

    def current_label(self):
        try:
            with open(LABEL_FILE) as f:
                return f.read().strip() or "normal"
        except Exception:
            return "normal"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        print(f"Switch {datapath.id} connected", flush=True)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, match, priority=DROP_PRIORITY,
                       idle_timeout=DROP_IDLE_TIMEOUT):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=[],
                                idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def enforce_quarantine(self, src_ip):
        """Install a drop rule for EVERY packet from src_ip, to any
        destination. This is the full-host cutoff action."""
        if src_ip in self.quarantined_hosts:
            return  # already quarantined, nothing new to install
        self.quarantined_hosts.add(src_ip)
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            # Match on IPv4 source only -- catches every destination.
            match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            self.add_drop_flow(datapath, match_ip,
                                priority=QUARANTINE_PRIORITY,
                                idle_timeout=QUARANTINE_IDLE_TIMEOUT)
            self.quarantine_installs[src_ip].append((datapath, match_ip))
            # Also block ARP from this host, so it can't even resolve
            # other hosts' MACs while quarantined.
            match_arp = parser.OFPMatch(eth_type=0x0806, arp_spa=src_ip)
            self.add_drop_flow(datapath, match_arp,
                                priority=QUARANTINE_PRIORITY,
                                idle_timeout=QUARANTINE_IDLE_TIMEOUT)
            self.quarantine_installs[src_ip].append((datapath, match_arp))
        print(f"*** QUARANTINE ENFORCED: {src_ip} is now cut off from the "
              f"entire network ***", flush=True)

    def enforce_restrict(self, src_ip, dst_ip):
        """Install a drop rule for just this one (src_ip, dst_ip) pair."""
        pair = (src_ip, dst_ip)
        if pair in self.restricted_pairs:
            return
        self.restricted_pairs.add(pair)
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            match_ip = parser.OFPMatch(eth_type=0x0800,
                                       ipv4_src=src_ip, ipv4_dst=dst_ip)
            self.add_drop_flow(datapath, match_ip,
                                priority=RESTRICT_PRIORITY,
                                idle_timeout=RESTRICT_IDLE_TIMEOUT)
            self.restrict_installs[pair].append((datapath, match_ip))
            match_arp = parser.OFPMatch(eth_type=0x0806,
                                        arp_spa=src_ip, arp_tpa=dst_ip)
            self.add_drop_flow(datapath, match_arp,
                                priority=RESTRICT_PRIORITY,
                                idle_timeout=RESTRICT_IDLE_TIMEOUT)
            self.restrict_installs[pair].append((datapath, match_arp))
        print(f"*** RESTRICT ENFORCED: {src_ip} -> {dst_ip} blocked ***",
              flush=True)

    def delete_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

    def clear_quarantine(self, src_ip):
        if src_ip not in self.quarantined_hosts:
            print(f"Clear requested for {src_ip}, but it is not quarantined.",
                  flush=True)
            return
        for datapath, match in self.quarantine_installs.get(src_ip, []):
            self.delete_flow(datapath, match)
        self.quarantine_installs.pop(src_ip, None)
        self.quarantined_hosts.discard(src_ip)
        print(f"*** QUARANTINE CLEARED (manual): {src_ip} restored to the "
              f"network ***", flush=True)

    def clear_restrict(self, src_ip, dst_ip):
        pair = (src_ip, dst_ip)
        if pair not in self.restricted_pairs:
            return
        for datapath, match in self.restrict_installs.get(pair, []):
            self.delete_flow(datapath, match)
        self.restrict_installs.pop(pair, None)
        self.restricted_pairs.discard(pair)
        print(f"*** RESTRICT CLEARED (manual): {src_ip} -> {dst_ip} "
              f"restored ***", flush=True)

    def clear_all(self):
        for src_ip in list(self.quarantined_hosts):
            self.clear_quarantine(src_ip)
        for pair in list(self.restricted_pairs):
            self.clear_restrict(*pair)
        # rebuild live graph on clear: all hosts reachable again
        try:
            self.live_graph = LiveReachabilityGraph(self.blocked_pairs)
            print('*** CLEARED: live graph reset -- all hosts restored ***', flush=True)
        except Exception:
            pass

    def _clear_trigger_watcher(self):
        """Watches CLEAR_TRIGGER_FILE for manual-clear requests written by
        the dashboard (e.g. 'quarantine:10.0.0.1' or 'all')."""
        last_seen = ""
        while True:
            hub.sleep(1)
            try:
                if not os.path.exists(CLEAR_TRIGGER_FILE):
                    continue
                with open(CLEAR_TRIGGER_FILE) as f:
                    content_ = f.read().strip()
                if not content_ or content_ == last_seen:
                    continue
                last_seen = content_
                print(f"Clear trigger received: {content_}", flush=True)
                if content_ == "all":
                    self.clear_all()
                elif content_.startswith("quarantine:"):
                    self.clear_quarantine(content_.split(":", 1)[1])
                elif content_.startswith("restrict:"):
                    _, pair_str = content_.split(":", 1)
                    s, d = pair_str.split(",")
                    self.clear_restrict(s, d)
                # clear the file so we don't reprocess the same trigger
                open(CLEAR_TRIGGER_FILE, "w").close()
                last_seen = ""
            except Exception as e:
                print(f"clear_trigger_watcher error: {e}", flush=True)

    def log_blocked(self, dpid, src_ip, dst_ip, proto, src_mac, dst_mac, in_port):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", newline="") as f:
            csv.writer(f).writerow(
                [ts, dpid, src_ip, dst_ip, proto, src_mac, dst_mac, in_port])
        print(f"BLOCKED: {src_ip} -> {dst_ip} ({proto})", flush=True)

    def log_decision(self, src_ip, dst_ip, prediction, risk, action):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(DECISION_LOG_FILE, "a", newline="") as f:
            csv.writer(f).writerow([ts, src_ip, dst_ip, prediction,
                                    round(risk, 3), action])
        # NEW: keep an in-memory copy for the live dashboard feed
        self.recent_decisions.append({
            "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
            "ml_prediction": prediction, "risk_score": round(risk, 3),
            "action": action,
        })

    def record_packet(self, src_ip, dst_ip, length, dst_port, proto):
        key = (src_ip, dst_ip)
        now = time.time()
        is_new_flow = key not in self.flows
        if is_new_flow:
            self.flows[key] = FlowRecord(src_ip, dst_ip)
            # Only the side that OPENS the flow is credited as initiator,
            # and only if the reverse flow isn't already active (i.e. this
            # isn't just the reply leg of a conversation already underway).
            if (dst_ip, src_ip) not in self.flows:
                self.initiated_hosts[src_ip][dst_ip] = now
        self.flows[key].update(length, dst_port, proto)

        self.host_activity[src_ip][dst_ip] = now

    def distinct_dst_hosts_recent(self, src_ip, now):
        activity = self.host_activity.get(src_ip, {})
        recent = [dst for dst, t in activity.items()
                  if (now - t) <= HOST_ACTIVITY_WINDOW]
        return len(recent)

    def initiated_hosts_recent(self, src_ip, now):
        """Distinct hosts THIS src opened a new flow to in the window.
        Near-zero for a pure responder; high for a real lateral mover."""
        opened = self.initiated_hosts.get(src_ip, {})
        recent = [dst for dst, t in opened.items()
                  if (now - t) <= HOST_ACTIVITY_WINDOW]
        return len(recent)

    def flush_idle_flows(self):
        self.conn_tracker.sweep()
        now = time.time()
        label = self.current_label()
        done = [k for k, rec in self.flows.items() if rec.is_idle(now)]
        for key in done:
            rec = self.flows.pop(key)
            dist_hosts = self.distinct_dst_hosts_recent(rec.src_ip, rec.last_time)

            with open(self.flow_log_file, "a", newline="") as f:
                csv.writer(f).writerow(rec.to_row(label, dist_hosts))
            print(f"FLOW LOGGED: {rec.src_ip} -> {rec.dst_ip} "
                  f"pkts={rec.packet_count} ports={len(rec.dst_ports)} "
                  f"dist_hosts={dist_hosts} label={label}", flush=True)

            try:
                features = rec.to_ml_features(dist_hosts)
                if self.mode == "rule":
                    # Config C: fixed-threshold detector, NO ML model.
                    prediction, risk, action, explanation = rule_decide(
                        dist_hosts, len(rec.dst_ports), rec.dst_ip)
                else:
                    X = pd.DataFrame([features], columns=ML_FEATURES)
                    prediction = self.model.predict(X)[0]
                    if RISK_MODEL == '5factor':
                        # 5-FACTOR model: all five factors with REAL data
                        proba = self.model.predict_proba(X)[0]
                        classes = list(self.model.classes_)
                        # probability the flow is malicious (not 'normal')
                        mal_p = 1.0 - (proba[classes.index('normal')]
                                       if 'normal' in classes else 0.0)
                        c_rate, f_ratio = self.conn_tracker.features_for(rec.src_ip)
                        score, action, breakdown = compute_risk_v2(
                            mal_p, rec.dst_ip,
                            distinct_dst_hosts_recent=dist_hosts,
                            packets_per_sec=c_rate,
                            failed_conn_ratio=f_ratio)
                        risk = score / 100.0
                        explanation = (f"prediction={prediction} 5F-score={score} "
                                       f"(ml_p={mal_p:.2f} rate={c_rate} "
                                       f"fail={f_ratio} fan={dist_hosts}) => {action} "
                                       f"terms={breakdown}")
                    else:
                        risk, action, explanation = compute_risk(prediction, rec.dst_ip)
                print(f"[{self.mode}] DETECTED: {rec.src_ip} -> {rec.dst_ip}  {explanation}",
                      flush=True)

                # Configs A (flat) and B (static) do NO dynamic response:
                # detection may run, but containment is disabled so the
                # blast radius can be measured with no adaptive defence.
                if self.mode in ("flat", "static"):
                    action = "MONITOR"

                # DIRECTIONAL GUARD: a host is only contained if it was the
                # INITIATOR of multi-host contact. A victim whose flows are
                # replies has initiated_recent <= 1 and is spared, fixing the
                # victim-quarantine bug. (Applies to the adaptive configs;
                # flat/static already forced MONITOR above.)
                init_recent = self.initiated_hosts_recent(rec.src_ip, rec.last_time)
                # REPLY GUARD: a flow to a host that recently initiated contact with
                # this source (and that this source did not itself initiate) is reply
                # traffic. The controller never contains a host for answering others.
                _ini = self.initiated_hosts
                _src_opened = (rec.last_time - _ini.get(rec.src_ip, {}).get(rec.dst_ip, -1e18)) <= HOST_ACTIVITY_WINDOW
                _dst_opened = (rec.last_time - _ini.get(rec.dst_ip, {}).get(rec.src_ip, -1e18)) <= HOST_ACTIVITY_WINDOW
                if action in ("QUARANTINE", "RESTRICT") and _dst_opened and not _src_opened:
                    print(f"    [reply-guard] {rec.src_ip} -> {rec.dst_ip} is reply traffic "
                          f"-- {action} suppressed", flush=True)
                    action = "MONITOR"
                # SCAN EXCEPTION: an initiator that opened exactly one target and hit
                # many distinct ports on it is a single-target port scan, not a
                # responder. Allowed through as pair-level RESTRICT, capped there:
                # one target is not evidence of spread, so no host-wide quarantine.
                _n_ports = len(rec.dst_ports)
                _is_scan = (init_recent == 1
                            and rec.dst_ip in self.initiated_hosts.get(rec.src_ip, {})
                            and _n_ports >= SCAN_PORT_MIN)
                if action in ("QUARANTINE", "RESTRICT") and init_recent <= 1 and _is_scan:
                    if action == "QUARANTINE":
                        action = "RESTRICT"
                    print(f"    [scan] {rec.src_ip} -> {rec.dst_ip}: single-target scan "
                          f"({_n_ports} ports) -- pair-level RESTRICT", flush=True)
                elif action in ("QUARANTINE", "RESTRICT") and init_recent <= 1:
                    print(f"    [directional] sparing {rec.src_ip}: "
                          f"initiated_recent={init_recent} (responder, not "
                          f"initiator) -- {action} suppressed", flush=True)
                    action = "MONITOR"

                # log AFTER directional guard: record the action actually
                # ENFORCED, so decisions_log.csv matches live reachability.
                self.log_decision(rec.src_ip, rec.dst_ip, prediction, risk, action)
                if action == "QUARANTINE":
                    self.enforce_quarantine(rec.src_ip)
                    self.live_graph.cut_host(rec.src_ip)
                    print("    " + self.live_graph.report(rec.src_ip), flush=True)
                elif action == "RESTRICT":
                    self.enforce_restrict(rec.src_ip, rec.dst_ip)
                    self.live_graph.cut_pair(rec.src_ip, rec.dst_ip)
                    # GRAPH_CUT: if the attacker still has a path to a
                    # critical asset, cut the next edge on that path too.
                    if GRAPH_CUT:
                        _asset, _path = self.live_graph.path_to_critical(rec.src_ip)
                        if _path and len(_path) >= 2:
                            _a, _b = _path[0], _path[1]
                            self.enforce_restrict(_a, _b)
                            self.live_graph.cut_pair(_a, _b)
                            self.log_decision(_a, _b, "path-cut", risk, "RESTRICT")
                            print(f"    [graph-cut] severing path edge "
                                  f"{_a} -> {_b} toward critical asset", flush=True)
                    print("    " + self.live_graph.report(rec.src_ip), flush=True)
                # MONITOR: no enforcement action needed.

            except Exception as e:
                print(f"ML DECISION ERROR for {rec.src_ip} -> {rec.dst_ip}: {e}",
                      flush=True)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src_ip = dst_ip = None
        proto = None
        dst_port = None
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        if ip_pkt:
            src_ip, dst_ip = ip_pkt.src, ip_pkt.dst
            proto_num = ip_pkt.proto
            proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, str(proto_num))
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            _src_port = None; _tcp_flags = 0
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
                _src_port = tcp_pkt.src_port
                _tcp_flags = tcp_pkt.bits
                # feed the connection tracker (for conn-rate / failed-ratio)
                self.conn_tracker.observe(src_ip, dst_ip, _src_port,
                                          dst_port, 'TCP', _tcp_flags)
            elif udp_pkt:
                dst_port = udp_pkt.dst_port
        elif arp_pkt:
            src_ip, dst_ip = arp_pkt.src_ip, arp_pkt.dst_ip
            proto = "ARP"

        # NEW: immediately drop anything from an already-quarantined host,
        # before even recording it as a flow -- it's fully cut off.
        if src_ip and src_ip in self.quarantined_hosts:
            if ip_pkt:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            else:
                match = parser.OFPMatch(eth_type=0x0806, arp_spa=src_ip)
            self.add_drop_flow(datapath, match, priority=QUARANTINE_PRIORITY,
                                idle_timeout=QUARANTINE_IDLE_TIMEOUT)
            return

        # NEW: drop anything matching an already-restricted pair.
        if src_ip and (src_ip, dst_ip) in self.restricted_pairs:
            if ip_pkt:
                match = parser.OFPMatch(eth_type=0x0800,
                                        ipv4_src=src_ip, ipv4_dst=dst_ip)
            else:
                match = parser.OFPMatch(eth_type=0x0806,
                                        arp_spa=src_ip, arp_tpa=dst_ip)
            self.add_drop_flow(datapath, match, priority=RESTRICT_PRIORITY,
                                idle_timeout=RESTRICT_IDLE_TIMEOUT)
            return

        if src_ip:
            self.record_packet(src_ip, dst_ip, len(msg.data), dst_port, proto)

        if src_ip and (src_ip, dst_ip) in self.blocked_pairs:
            self.log_blocked(dpid, src_ip, dst_ip, proto, src, dst, in_port)
            if ip_pkt:
                match = parser.OFPMatch(eth_type=0x0800,
                                        ipv4_src=src_ip, ipv4_dst=dst_ip)
            else:
                match = parser.OFPMatch(eth_type=0x0806,
                                        arp_spa=src_ip, arp_tpa=dst_ip)
            self.add_drop_flow(datapath, match)
            return

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD and not ip_pkt and arp_pkt:
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0806,
                                    eth_src=src, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
