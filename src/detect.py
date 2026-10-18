import os
import sys
import time
import joblib
import pandas as pd
from scapy.all import sniff
from supabase import create_client, Client

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FlowFeatureExtractor
from schema import FEATURES

# --- SUPABASE CONFIG ---
SUPABASE_URL = "https://pdnfytydvpbdtgkbvycd.supabase.com"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBkbmZ5dHlkdnBiZHRna2J2eWNkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTIzMzU4MjgsImV4cCI6MjEwNzkxMTgyOH0.xp068vgZEu2bIJFng8Bg9UDjgfjUPnuGcDn3RKDzSDM"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE, "models", "ids_models.joblib")

bundle = joblib.load(MODEL_PATH)
iso_model = bundle["iso_model"]
rf_model = bundle["rf_model"]
scaler = bundle["scaler"]
features = bundle["features"]

extractor = FlowFeatureExtractor(window_seconds=3)
pkt_count = 0
alert_count = 0

def push_alert(ts, src, dst, score, attack_type):
    try:
        supabase.table("alerts").insert({
            "timestamp": ts, "src": src, "dst": dst, 
            "score": score, "verdict": "ANOMALY", "attack_type": attack_type
        }).execute()
    except Exception as e:
        print(f"Failed to send to cloud: {e}")

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
    rf_preds = rf_model.predict(X)
    
    ts = time.strftime("%H:%M:%S")
    for r, p, s, rf_p in zip(ready, preds, scores, rf_preds):
        total_pkts = r["Total Fwd Packets"] + r["Total Backward Packets"]
        is_anomaly = (p == -1) or (total_pkts > 10) or (r["Flow Packets/s"] > 10)
        
        if is_anomaly:
            alert_count += 1
            attack_type = rf_p if rf_p.upper() != "BENIGN" else "Zero-Day / Unknown"
            
            if attack_type == "Zero-Day / Unknown":
                if r["Flow Packets/s"] > 10 or total_pkts > 20:
                    attack_type = "DDoS / Flood"
                elif total_pkts > 5 and r["Flow Duration"] < 500000:
                    attack_type = "PortScan"
            
            push_alert(ts, r["_src"], r["_dst"], round(float(s), 4), attack_type)
            print(f"☁️ [SYNCED] {r['_src']} -> {r['_dst']} | Type: {attack_type}")

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "Wi-Fi"
    print(f"Sniffing on '{iface}' and syncing to Cloud...")
    sniff(iface=iface, prn=handle, store=False)