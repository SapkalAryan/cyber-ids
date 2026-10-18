import os
import sys
import time
import csv
import joblib
import pandas as pd
from scapy.all import sniff

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FlowFeatureExtractor
from schema import FEATURES

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE, "models", "ids_models.joblib")
ALERTS_CSV = os.path.join(BASE, "alerts.csv")

bundle = joblib.load(MODEL_PATH)
iso_model = bundle["iso_model"]
rf_model = bundle["rf_model"]
scaler = bundle["scaler"]
features = bundle["features"]

if not os.path.exists(ALERTS_CSV):
    with open(ALERTS_CSV, "w", newline="") as f:
        csv.writer(f).writerow(["timestamp", "src", "dst", "score", "verdict", "attack_type"])

extractor = FlowFeatureExtractor(window_seconds=3)
pkt_count = 0
alert_count = 0

def append_alert(row):
    with open(ALERTS_CSV, "a", newline="") as f:
        csv.writer(f).writerow(row)

def handle(pkt):
    global pkt_count, alert_count
    pkt_count += 1
    extractor.update(pkt)
    
    if pkt_count % 50 != 0:
        return
        
    ready = extractor.flush_ready()
    if not ready:
        return
        
    X = pd.DataFrame([[r[c] for c in features] for r in ready], columns=features)
    X = X.replace([float("inf"), float("-inf")], 0).fillna(0)
    X_scaled = scaler.transform(X.values)
    
    preds = iso_model.predict(X_scaled)
    scores = iso_model.decision_function(X_scaled)
    
    ts = time.strftime("%H:%M:%S")
    for r, p, s in zip(ready, preds, scores):
        
        # Calculate total packets in this flow
        total_pkts = r["Total Fwd Packets"] + r["Total Backward Packets"]
        
        # Print for debugging in terminal
        print(f"Flow: {r['_src']} -> {r['_dst']} | Total Packets: {total_pkts} | Pkt/s: {r['Flow Packets/s']:.2f}")
        
        is_anomaly = (p == -1) or (total_pkts > 10) or (r["Flow Packets/s"] > 10)
        
        if is_anomaly:
            alert_count += 1
            
            # Aggressive Heuristic Override
            if r["Flow Packets/s"] > 10 or total_pkts > 20:
                attack_type = "DDoS / Flood"
            elif total_pkts > 5 and r["Flow Duration"] < 500000:
                attack_type = "PortScan"
            else:
                attack_type = "Zero-Day / Unknown"
            
            append_alert([ts, r["_src"], r["_dst"], round(float(s), 4), "ANOMALY", attack_type])
            print(f"🚨 [ALERT] {r['_src']} -> {r['_dst']} | Type: {attack_type}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit('Usage: python src\\detect.py "<interface name>"')
    iface = sys.argv[1]
    print(f"Sniffing on '{iface}'...")
    try:
        sniff(iface=iface, prn=handle, store=False)
    except KeyboardInterrupt:
        print(f"\nStopped.")