import os
import sys
import time
import csv
import joblib
import pandas as pd
import numpy as np
import threading
from scapy.all import sniff
from supabase import create_client, Client
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FlowFeatureExtractor
from schema import FEATURES

SUPABASE_URL = "https://pdnfytydvpbdtgkbvycd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBkbmZ5dHlkdnBiZHRna2J2eWNkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTIzMzU4MjgsImV4cCI6MjEwNzkxMTgyOH0.xp068vgZEu2bIJFng8Bg9UDjgfjUPnuGcDn3RKDzSDM"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE, "models", "ids_iso.joblib")
ALERTS_CSV = os.path.join(BASE, "alerts.csv")

bundle = joblib.load(MODEL_PATH)
iso_model = bundle["iso_model"]
scaler = bundle["scaler"]
features = bundle["features"]

extractor = FlowFeatureExtractor(window_seconds=3)

def push_alert(ts, src, dst, score, attack_type):
    with open(ALERTS_CSV, "a", newline="") as f:
        csv.writer(f).writerow([ts, src, dst, score, "ANOMALY", attack_type])
    try:
        supabase.table("alerts").insert({
            "timestamp": ts, "src": src, "dst": dst, 
            "score": score, "verdict": "ANOMALY", "attack_type": attack_type
        }).execute()
    except Exception:
        pass

def process_flow(flow_dict):
    # 1. Convert to DataFrame
    X = pd.DataFrame([[flow_dict.get(c, 0.0) for c in features]], columns=features)
    X = X.replace([float("inf"), float("-inf")], 0).fillna(0)
    X_scaled = scaler.transform(X.values)
    
    # 2. ML Prediction
    pred = iso_model.predict(X_scaled)[0]
    score = iso_model.decision_function(X_scaled)[0]
    
    # 3. Log if it's an anomaly
    if pred == -1:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Label based on the math signature of the flow
        total_pkts = flow_dict.get("Total Fwd Packets", 0) + flow_dict.get("Total Backward Packets", 0)
        pkt_rate = flow_dict.get("Flow Packets/s", 0)
        
        if pkt_rate > 1000:
            attack_type = "DDoS / Flood"
        elif total_pkts < 5 and pkt_rate > 50:
            attack_type = "PortScan"
        else:
            attack_type = "Zero-Day / Unknown"
            
        src = flow_dict.get("_src", "Unknown")
        dst = flow_dict.get("_dst", "Unknown")
        
        print(f"🧠 [ML ANOMALY] {src} -> {dst} | Score: {score:.3f} | Type: {attack_type}")
        push_alert(ts, src, dst, round(float(score), 4), attack_type)

def handle_packet(pkt):
    extractor.update(pkt)
    # Only flush every 50 packets to save CPU
    ready = extractor.flush_ready()
    for r in ready:
        process_flow(r)

# --- BDA STREAMING SIMULATOR ---
# This simulates a continuous stream of attacks for your presentation
def simulate_attack(attack_type):
    print(f"\n🔥 INJECTING {attack_type} STREAM...")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for i in range(10): # Send 10 attack flows
        if attack_type == "PortScan":
            # Features matching a fast port scan (small packets, high rate)
            flow = {c: 0.0 for c in features}
            flow["Total Fwd Packets"] = 2
            flow["Flow Packets/s"] = 500.0
            flow["Flow Duration"] = 1000.0
            flow["_src"] = "10.98.205.143"
            flow["_dst"] = "10.98.205.229"
            push_alert(ts, flow["_src"], flow["_dst"], -0.99, "PortScan (Simulated)")
        else:
            # Features matching a DDoS flood
            flow = {c: 0.0 for c in features}
            flow["Total Fwd Packets"] = 5000
            flow["Flow Packets/s"] = 20000.0
            flow["Flow Duration"] = 2000000.0
            flow["_src"] = "10.98.205.143"
            flow["_dst"] = "10.98.205.229"
            push_alert(ts, flow["_src"], flow["_dst"], -0.99, "DDoS / Flood (Simulated)")
            
        time.sleep(0.5)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "simulate":
        simulate_attack("DDoS")
        sys.exit()
        
    iface = sys.argv[1] if len(sys.argv) > 1 else "Wi-Fi"
    print(f"Sniffing on '{iface}' using Pure ML Streaming...")
    sniff(iface=iface, prn=handle_packet, store=False)