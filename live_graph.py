#!/usr/bin/env python3
"""
live_graph.py -- Review 3: live reachability-graph analysis with path cutting.

The controller keeps a live reachability graph of the network (who can reach
whom). As an attack unfolds and the controller quarantines/restricts hosts,
this module:
  * updates the graph (removing edges that enforcement has cut),
  * computes, in real time, whether the attacker still has a PATH to a
    critical asset (the Server segment), and
  * reports when containment has SEVERED that path.

This runs ALONGSIDE the existing enforcement (observing + reporting) -- it does
not replace the proven quarantine/restrict logic.
"""
import networkx as nx

# Critical assets (Server segment, VLAN30) -- the targets we protect.
CRITICAL_ASSETS = ["10.0.0.3", "10.0.0.5"]   # FileServer, Database

ALL_HOSTS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
             "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]
NAME = {"10.0.0.1":"HR","10.0.0.2":"Finance","10.0.0.3":"FileServer",
        "10.0.0.4":"Guest","10.0.0.5":"Database","10.0.0.6":"IoT-1",
        "10.0.0.7":"IoT-2","10.0.0.8":"Admin"}


class LiveReachabilityGraph:
    def __init__(self, blocked_pairs):
        """Build the initial reachability graph from the static ACL policy."""
        self.G = nx.DiGraph()
        for h in ALL_HOSTS:
            self.G.add_node(h, name=NAME.get(h, h))
        for s in ALL_HOSTS:
            for d in ALL_HOSTS:
                if s != d and (s, d) not in blocked_pairs:
                    self.G.add_edge(s, d)
        self.quarantined = set()
        self.restricted = set()

    def cut_host(self, ip):
        """A host was quarantined -> remove ALL its edges (moved to Quarantine VLAN)."""
        if ip in self.G:
            self.G.remove_edges_from(list(self.G.in_edges(ip)) + list(self.G.out_edges(ip)))
        self.quarantined.add(ip)

    def cut_pair(self, src, dst):
        """A pair was restricted -> remove that single directed edge."""
        if self.G.has_edge(src, dst):
            self.G.remove_edge(src, dst)
        self.restricted.add((src, dst))

    def path_to_critical(self, attacker):
        """Return (asset, path) if the attacker can still reach ANY critical
        asset, else (None, None) -- meaning the path has been severed."""
        for asset in CRITICAL_ASSETS:
            if attacker in self.G and asset in self.G:
                try:
                    path = nx.shortest_path(self.G, attacker, asset)
                    return asset, path
                except nx.NetworkXNoPath:
                    continue
        return None, None

    def report(self, attacker):
        """Human-readable live status of the attacker's reachability."""
        asset, path = self.path_to_critical(attacker)
        if path is None:
            return (f"[live-graph] {NAME.get(attacker,attacker)} has NO PATH to any "
                    f"critical asset -- containment has SEVERED the attack path.")
        route = " -> ".join(NAME.get(h,h) for h in path)
        return (f"[live-graph] {NAME.get(attacker,attacker)} can still reach "
                f"{NAME.get(asset,asset)} via: {route} ({len(path)-1} hop(s)) "
                f"-- path still OPEN.")


if __name__ == "__main__":
    # Self-test: HR attacks, gets quarantined, path to Server is severed.
    blocked = set()
    GUEST = "10.0.0.4"
    for o in ALL_HOSTS:
        if o != GUEST:
            blocked.add((GUEST,o)); blocked.add((o,GUEST))
    g = LiveReachabilityGraph(blocked)
    print("Before attack:")
    print("  " + g.report("10.0.0.1"))
    print("HR quarantined...")
    g.cut_host("10.0.0.1")
    print("After quarantine:")
    print("  " + g.report("10.0.0.1"))
