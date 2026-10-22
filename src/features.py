import time
import math
import hashlib
from collections import defaultdict

class BloomFilter:
    def __init__(self, expected_items, false_positive_rate):
        self.size = math.ceil((expected_items * math.log(false_positive_rate)) / math.log(1 / (2 ** math.log(2))))
        self.hash_count = math.ceil((self.size / expected_items) * math.log(2))
        self.bit_array = bytearray(self.size)
        
    def _hashes(self, item):
        item = item.encode('utf-8')
        hashes = []
        for i in range(self.hash_count):
            digest = hashlib.sha256(item + str(i).encode('utf-8')).hexdigest()
            hashes.append(int(digest, 16) % self.size)
        return hashes

    def add(self, item):
        for hash_val in self._hashes(item):
            self.bit_array[hash_val] = 1

    def check(self, item):
        for hash_val in self._hashes(item):
            if self.bit_array[hash_val] == 0:
                return False
        return True

class FlowFeatureExtractor:
    def __init__(self, window_seconds=3):
        self.window = window_seconds
        self.flows = defaultdict(lambda: {
            "start": None,
            "src": None,
            "dst": None,
            "proto": None,
            "dport": 0,
            "fwd_packets": 0,
            "bwd_packets": 0,
            "fwd_bytes": 0,
            "bwd_bytes": 0,
            "lengths": [],
        })

    def _key(self, pkt):
        try:
            if not pkt.haslayer("IP"):
                return None
            ip = pkt["IP"]
            proto = ip.proto
            sport = dport = 0
            if pkt.haslayer("TCP"):
                sport, dport = pkt["TCP"].sport, pkt["TCP"].dport
            elif pkt.haslayer("UDP"):
                sport, dport = pkt["UDP"].sport, pkt["UDP"].dport
            return f"{ip.src}:{sport}->{ip.dst}:{dport}/{proto}"
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
            f["proto"] = "TCP" if pkt.haslayer("TCP") else ("UDP" if pkt.haslayer("UDP") else "ICMP")
            f["dport"] = pkt["TCP"].dport if pkt.haslayer("TCP") else (pkt["UDP"].dport if pkt.haslayer("UDP") else 0)
            
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
                "_proto": f["proto"],
                "_dport": f["dport"]
            })
            expired.append(key)
        for k in expired:
            del self.flows[k]
        return ready