import os
import sys
import time
import csv
import joblib
import pandas as pd
import numpy as np
from collections import deque
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

extractor = FlowFeatureExtractor(window_seconds=2) # 2-second flow window
pkt_count = 0
alert_count = 0

# BDA Concept: Sliding Window for Streaming Analytics
# We keep a rolling history of the last 10 anomaly scores to detect a sustained attack
recent_scores = deque(maxlen=10)

def push_alert(ts, src, dst, score, attack_type):
    with open(ALERTS_CSV, "a", newline="") as f:
        csv.writer(f).writerow([ts, src, dst, score, "ANOMALY", attack_type])
    try:
        supabase.table("alerts").insert({
            "timestamp": ts, "src": src, "dst": dst, 
            "score": score, "verdict": "ANOMALY", "attack_type": attack_type
        }).execute()
    except Exception as e:
        pass # Silent fail for speed

def handle(pkt):
    global pkt_count, alert_count
    pkt_count += 1
    extractor.update(pkt)
    
    if pkt_count % 20 != 0:
        return
        
    ready = extractor.flush_ready()
    if not ready:
        return
        
    # Prepare data
    X = pd.DataFrame([[r[c] for c in features] for r in ready], columns=features)
    X = X.replace([float("inf"), float("-inf")], 0).fillna(0)
    X_scaled = scaler.transform(X.values)
    
    # ML Prediction
    preds = iso_model.predict(X_scaled)
    scores = iso_model.decision_function(X_scaled)
    
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    for r, p, s in zip(ready, preds, scores):
        # Update rolling window with the latest anomaly score
        recent_scores.append(s)
        
        # If the average score of the rolling window drops drastically, it's a sustained attack.
        # (Lower score in Isolation Forest means more anomalous)
        rolling_avg = np.mean(recent_scores) if recent_scores else 0
        
        # Only flag as DDoS if the rolling average is extremely low (meaning massive continuous anomaly)
        is_anomaly = p == -1 or rolling_avg < -0.30
        
        if is_anomaly:
            alert_count += 1
            attack_type = "DDoS / Anomaly" if rolling_avg < -0.30 else "Zero-Day / Unknown"
            push_alert(ts, r["_src"], r["_dst"], round(float(s), 4), attack_type)
            print(f"🧠 [ML ANOMALY] {r['_src']} -> {r['_dst']} | Score: {s:.3f} | Rolling Avg: {rolling_avg:.3f} | Type: {attack_type}")

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "Wi-Fi"
    print(f"Sniffing on '{iface}' using Pure ML Streaming...")
    sniff(iface=iface, prn=handle, store=False)