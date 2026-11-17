#!/usr/bin/env python3
"""
connection_tracker.py -- Review 3: TCP connection-state tracking for the
two new risk features (connection rate + failed-connection ratio).

Design (per the stated precautions):
  * A connection is identified by the 5-tuple:
        (src_ip, dst_ip, src_port, dst_port, proto)
  * A SYN (no ACK) starts a PENDING attempt, timestamped.
  * A retransmitted SYN for the SAME 5-tuple is NOT a new attempt -- it only
    refreshes the timestamp (so retransmissions aren't over-counted).
  * A SYN-ACK on the REVERSE 5-tuple marks the attempt SUCCEEDED.
  * A PENDING attempt with no SYN-ACK within CONN_TIMEOUT is counted FAILED.

Per-source features (over a recent sliding window):
  * connection_rate   = attempts / window_seconds
  * failed_conn_ratio = failed / total_attempts
"""
import time
from collections import defaultdict, deque

CONN_TIMEOUT = 3.0        # seconds: a pending SYN with no SYN-ACK = failed
RATE_WINDOW = 10.0        # seconds: window for connection-rate / ratio

# TCP flag bits
FIN = 0x01; SYN = 0x02; RST = 0x04; PSH = 0x08; ACK = 0x10


class ConnectionTracker:
    def __init__(self):
        # 5-tuple -> {"t": timestamp, "state": "PENDING"/"DONE"}
        self.pending = {}
        # per-source rolling logs of (timestamp, outcome) where outcome in
        # {"attempt","failed"} -- used for windowed rate/ratio
        self.attempts = defaultdict(deque)   # src_ip -> deque[timestamps]
        self.failures = defaultdict(deque)   # src_ip -> deque[timestamps]

    def _key(self, s_ip, d_ip, s_port, d_port, proto):
        return (s_ip, d_ip, s_port, d_port, proto)

    def observe(self, src_ip, dst_ip, src_port, dst_port, proto, tcp_flags):
        """Call for every TCP packet. tcp_flags is the TCP flags int."""
        if proto != "TCP" or src_port is None or dst_port is None:
            return
        now = time.time()
        is_syn = (tcp_flags & SYN) and not (tcp_flags & ACK)
        is_synack = (tcp_flags & SYN) and (tcp_flags & ACK)

        if is_syn:
            key = self._key(src_ip, dst_ip, src_port, dst_port, proto)
            if key in self.pending and self.pending[key]["state"] == "PENDING":
                # retransmitted SYN for same 5-tuple: refresh only, NOT a new attempt
                self.pending[key]["t"] = now
                return
            # brand-new connection attempt
            self.pending[key] = {"t": now, "state": "PENDING"}
            self.attempts[src_ip].append(now)

        elif is_synack:
            # SYN-ACK flows back: reverse 5-tuple matches the pending attempt
            rev = self._key(dst_ip, src_ip, dst_port, src_port, proto)
            if rev in self.pending and self.pending[rev]["state"] == "PENDING":
                self.pending[rev]["state"] = "DONE"   # succeeded

    def sweep(self):
        """Call periodically (e.g. once per second). Times out pending SYNs
        with no SYN-ACK -> counted as failed connections."""
        now = time.time()
        expired = []
        for key, info in self.pending.items():
            if info["state"] == "PENDING" and (now - info["t"]) > CONN_TIMEOUT:
                src_ip = key[0]
                self.failures[src_ip].append(now)
                expired.append(key)
        for key in expired:
            del self.pending[key]

    def _prune(self, dq, now):
        while dq and (now - dq[0]) > RATE_WINDOW:
            dq.popleft()

    def features_for(self, src_ip):
        """Return (connection_rate, failed_conn_ratio) for a source, windowed."""
        now = time.time()
        a = self.attempts[src_ip]; f = self.failures[src_ip]
        self._prune(a, now); self._prune(f, now)
        n_attempts = len(a); n_failed = len(f)
        rate = n_attempts / RATE_WINDOW
        ratio = (n_failed / n_attempts) if n_attempts > 0 else 0.0
        return round(rate, 3), round(ratio, 3)


if __name__ == "__main__":
    # Self-test: simulate a scanner making many failed connections
    ct = ConnectionTracker()
    # attacker 10.0.0.1 sends 5 SYNs to different ports, no replies
    for port in range(1000, 1005):
        ct.observe("10.0.0.1", "10.0.0.3", port, 445, "TCP", SYN)
    # one retransmitted SYN (same 5-tuple) -- must NOT count as new attempt
    ct.observe("10.0.0.1", "10.0.0.3", 1000, 445, "TCP", SYN)
    print("Attempts recorded (should be 5, not 6):", len(ct.attempts["10.0.0.1"]))
    # one connection succeeds (SYN-ACK back on reverse tuple)
    ct.observe("10.0.0.3", "10.0.0.1", 445, 1001, "TCP", SYN | ACK)
    # force timeouts
    time.sleep(0.1)
    for k in ct.pending: ct.pending[k]["t"] -= 5   # age them past timeout
    ct.sweep()
    rate, ratio = ct.features_for("10.0.0.1")
    print(f"connection_rate={rate}  failed_conn_ratio={ratio}")
    print("(4 of 5 failed -> ratio ~0.8, since 1 succeeded)")
