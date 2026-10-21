import os
import sys
import time
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

bundle = joblib.load(MODEL_PATH)
iso_model = bundle["iso_model"]
scaler = bundle["scaler"]
features = bundle["features"]

extractor = FlowFeatureExtractor(window_seconds=3)

# --- BDA BATCHING LOGIC ---
alert_buffer = []
buffer_lock = threading.Lock()

def flush_buffer():
    global alert_buffer
    while True:
        time.sleep(5) # Wait 5 seconds to batch data
        with buffer_lock:
            if alert_buffer:
                try:
                    # Bulk Insert to Supabase
                    supabase.table("alerts").insert(alert_buffer).execute()
                    print(f"📦 [BATCH INSERTED] {len(alert_buffer)} alerts to Supabase.")
                    alert_buffer = []
                except Exception as e:
                    print(f"DB Error: {e}")

def push_alert(ts, src, dst, score, attack_type, proto="Unknown", dport=0):
    with buffer_lock:
        alert_buffer.append({
            "timestamp": ts, "src": src, "dst": dst, "score": score,
            "verdict": "ANOMALY", "attack_type": attack_type,
            "protocol": proto, "dst_port": dport
        })

def process_flow(flow_dict):
    X = pd.DataFrame([[flow_dict.get(c, 0.0) for c in features]], columns=features)
    X = X.replace([float("inf"), float("-inf")], 0).fillna(0)
    X_scaled = scaler.transform(X.values)
    
    pred = iso_model.predict(X_scaled)[0]
    score = iso_model.decision_function(X_scaled)[0]
    
    if pred == -1:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        proto = flow_dict.get("_proto", "Unknown")
        dport = flow_dict.get("_dport", 0)
        
        print(f"🧠 [ML ANOMALY] {src} -> {dst} | Type: {attack_type} | Proto: {proto}")
        push_alert(ts, src, dst, round(float(score), 4), attack_type, proto, dport)

def handle_packet(pkt):
    extractor.update(pkt)
    ready = extractor.flush_ready()
    for r in ready:
        process_flow(r)

def simulate_attack(attack_type):
    print(f"\n🔥 INJECTING {attack_type} STREAM...")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for i in range(10): 
        if attack_type == "PortScan":
            push_alert(ts, "10.98.205.143", "10.98.205.229", -0.99, "PortScan (Simulated)", "TCP", 80)
        else:
            push_alert(ts, "10.98.205.143", "10.98.205.229", -0.99, "DDoS / Flood (Simulated)", "UDP", 53)
        time.sleep(0.5)
    time.sleep(6) # Wait for the buffer to flush before exiting

if __name__ == "__main__":
    # Start the background batching thread
    threading.Thread(target=flush_buffer, daemon=True).start()

    if len(sys.argv) > 1 and sys.argv[1] == "simulate":
        simulate_attack("DDoS")
        sys.exit()
        
    iface = sys.argv[1] if len(sys.argv) > 1 else "Wi-Fi"
    print(f"Sniffing on '{iface}' using BDA Micro-Batching...")
    sniff(iface=iface, prn=handle_packet, store=False)