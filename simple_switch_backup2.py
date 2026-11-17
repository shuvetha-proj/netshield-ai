import csv
import os
import time
from collections import defaultdict

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
from os_ken.lib import hub  # NEW: lets us run a periodic background task

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "blocked_log.csv")
FLOW_LOG_FILE = os.path.join(BASE_DIR, "flow_stats.csv")
LABEL_FILE = os.path.join(BASE_DIR, "current_label.txt")

DROP_PRIORITY = 10
DROP_IDLE_TIMEOUT = 60

FLOW_IDLE_TIMEOUT = 3
FLOW_CHECK_PERIOD = 1  # NEW: seconds between background idle-flow sweeps


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

    def to_row(self, label):
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
            label,
        ]


class SimpleSwitch13(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Host IPs: hr=10.0.0.1, fin=10.0.0.2, crit=10.0.0.3, guest=10.0.0.4
        # Policy: HR, Finance, and Critical can all talk to each other.
        # Guest is fully isolated from everyone (both directions).
        self.blocked_pairs = {
            ('10.0.0.4', '10.0.0.1'), ('10.0.0.1', '10.0.0.4'),  # guest <-> hr
            ('10.0.0.4', '10.0.0.2'), ('10.0.0.2', '10.0.0.4'),  # guest <-> fin
            ('10.0.0.4', '10.0.0.3'), ('10.0.0.3', '10.0.0.4'),  # guest <-> crit
        }

        self.flows = {}

        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "dpid", "src_ip", "dst_ip",
                     "protocol", "src_mac", "dst_mac", "in_port"])

        if not os.path.exists(FLOW_LOG_FILE):
            with open(FLOW_LOG_FILE, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["start_time", "src_ip", "dst_ip", "duration_sec",
                     "packet_count", "byte_count", "distinct_dst_ports",
                     "packets_per_sec", "protocols", "label"])

        if not os.path.exists(LABEL_FILE):
            with open(LABEL_FILE, "w") as f:
                f.write("normal\n")

        # NEW: background green-thread that sweeps for idle flows every second,
        # independent of whether new packets are arriving.
        self.monitor_thread = hub.spawn(self._flow_monitor)

    def _flow_monitor(self):
        while True:
            hub.sleep(FLOW_CHECK_PERIOD)
            self.flush_idle_flows()

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

    def add_drop_flow(self, datapath, match):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, priority=DROP_PRIORITY,
                                match=match, instructions=[],
                                idle_timeout=DROP_IDLE_TIMEOUT)
        datapath.send_msg(mod)

    def log_blocked(self, dpid, src_ip, dst_ip, proto, src_mac, dst_mac, in_port):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", newline="") as f:
            csv.writer(f).writerow(
                [ts, dpid, src_ip, dst_ip, proto, src_mac, dst_mac, in_port])
        print(f"BLOCKED: {src_ip} -> {dst_ip} ({proto})", flush=True)

    def record_packet(self, src_ip, dst_ip, length, dst_port, proto):
        key = (src_ip, dst_ip)
        if key not in self.flows:
            self.flows[key] = FlowRecord(src_ip, dst_ip)
        self.flows[key].update(length, dst_port, proto)

    def flush_idle_flows(self):
        now = time.time()
        label = self.current_label()
        done = [k for k, rec in self.flows.items() if rec.is_idle(now)]
        for key in done:
            rec = self.flows.pop(key)
            with open(FLOW_LOG_FILE, "a", newline="") as f:
                csv.writer(f).writerow(rec.to_row(label))
            print(f"FLOW LOGGED: {rec.src_ip} -> {rec.dst_ip} "
                  f"pkts={rec.packet_count} ports={len(rec.dst_ports)} "
                  f"label={label}", flush=True)

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
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                dst_port = udp_pkt.dst_port
        elif arp_pkt:
            src_ip, dst_ip = arp_pkt.src_ip, arp_pkt.dst_ip
            proto = "ARP"

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

        # FIXED: only cache a flow for ARP (never for IP), and restrict the
        # match to eth_type=ARP so it can't accidentally also match ICMP/TCP
        # packets between the same two MACs.
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