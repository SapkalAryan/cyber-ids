"""
Extract the 10 schema features from live packets.
"""
import time
from collections import defaultdict

FIVE_SEC_WINDOW = 3.0  # seconds before a flow is considered "ready"


class FlowFeatureExtractor:
    def __init__(self, window_seconds=FIVE_SEC_WINDOW):
        self.window = window_seconds
        self.flows = defaultdict(lambda: {
            "start": None, "src": None, "dst": None,
            "fwd_packets": 0, "bwd_packets": 0,
            "fwd_bytes": 0, "bwd_bytes": 0,
            "lengths": [],
        })

    def _key(self, pkt):
        try:
            if not pkt.haslayer("IP"):
                return None
            ip = pkt["IP"]
            sport = dport = 0
            if pkt.haslayer("TCP"):
                sport, dport = pkt["TCP"].sport, pkt["TCP"].dport
            elif pkt.haslayer("UDP"):
                sport, dport = pkt["UDP"].sport, pkt["UDP"].dport
            return f"{ip.src}:{sport}->{ip.dst}:{dport}/{ip.proto}"
        except Exception:
            return None

    def update(self, pkt):
        key = self._key(pkt)
        if not key:
            return
        f = self.flows[key]
        now = time.time()
        if f["start"] is None:
            f["start"] = now
            f["src"] = pkt["IP"].src
            f["dst"] = pkt["IP"].dst
        ln = len(pkt)
        f["lengths"].append(ln)
        if pkt.haslayer("TCP") and (pkt["TCP"].flags & 0x02):
            f["fwd_packets"] += 1
            f["fwd_bytes"] += ln
        else:
            f["bwd_packets"] += 1
            f["bwd_bytes"] += ln

    def flush_ready(self):
        now = time.time()
        ready, expired = [], []
        for key, f in self.flows.items():
            if f["start"] is None:
                continue
            dur = now - f["start"]
            if dur < self.window:
                continue
            total_pkts = f["fwd_packets"] + f["bwd_packets"]
            total_bytes = f["fwd_bytes"] + f["bwd_bytes"]
            lengths = f["lengths"] or [0]
            mean_len = sum(lengths) / len(lengths)
            std_len = (sum((x - mean_len) ** 2 for x in lengths) / len(lengths)) ** 0.5
            ready.append({
                "Flow Duration": dur * 1_000_000,
                "Total Fwd Packets": f["fwd_packets"],
                "Total Backward Packets": f["bwd_packets"],
                "Total Length of Fwd Packets": f["fwd_bytes"],
                "Total Length of Bwd Packets": f["bwd_bytes"],
                "Flow Bytes/s": total_bytes / max(dur, 0.001),
                "Flow Packets/s": total_pkts / max(dur, 0.001),
                "Packet Length Mean": mean_len,
                "Packet Length Std": std_len,
                "Average Packet Size": total_bytes / max(total_pkts, 1),
                "_src": f["src"],
                "_dst": f["dst"],
            })
            expired.append(key)
        for k in expired:
            del self.flows[k]
        return ready