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
import socket

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FlowFeatureExtractor, BloomFilter
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

# --- BLOOM FILTER INITIALIZATION ---
visited_filter = BloomFilter(expected_items=10000, false_positive_rate=0.01)

popular_sites = [
    "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org", 
    "qq.com", "amazon.com", "tmall.com", "yahoo.com", "yahoo.co.jp", 
    "twitter.com", "instagram.com", "live.com", "vk.com", "sohu.com", 
    "netflix.com", "reddit.com", "linkedin.com", "microsoft.com", "github.com", 
    "apple.com", "office.com", "zoom.us", "whatsapp.com", "cloudflare.com", 
    "bing.com", "pinterest.com", "wordpress.com", "dropbox.com", "adobe.com", 
    "paypal.com", "ebay.com", "craigslist.org", "twitch.tv", "spotify.com", 
    "discord.com", "stackoverflow.com", "quora.com", "cnn.com", "bbc.co.uk", 
    "nytimes.com", "flipkart.com", "myntra.com", "swiggy.com", "zomato.com", 
    "irctc.co.in", "hdfcbank.com", "icicibank.com", "sbi.co.in", "coursera.org"
]
for site in popular_sites:
    visited_filter.add(site)

def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

# --- BDA BATCHING LOGIC ---
alert_buffer = []
buffer_lock = threading.Lock()

def flush_buffer():
    global alert_buffer
    while True:
        time.sleep(1) # CHANGED to 1 second for faster dashboard updates
        with buffer_lock:
            if alert_buffer:
                try:
                    supabase.table("alerts").insert(alert_buffer).execute()
                    print(f"📦 [BATCH INSERTED] {len(alert_buffer)} alerts to Supabase.")
                    alert_buffer = []
                except Exception as e:
                    print(f"DB Error: {e}")

def push_alert(ts, src, dst, score, attack_type, proto="Unknown", dport=0, domain="Unknown"):
    with buffer_lock:
        alert_buffer.append({
            "timestamp": ts, "src": src, "dst": dst, "score": score,
            "verdict": "ANOMALY", "attack_type": attack_type,
            "protocol": proto, "dst_port": dport, "domain": domain
        })

def process_flow(flow_dict):
    src_ip = flow_dict.get("_src", "Unknown")
    dst_ip = flow_dict.get("_dst", "Unknown")
    proto = flow_dict.get("_proto", "Unknown")
    dport = flow_dict.get("_dport", 0)
    
    # 1. Resolve Destination IP to Domain
    resolved_domain = get_domain(dst_ip)
    
    # --- CLEANUP FILTER FOR BETTER TERMINAL OUTPUT ---
    if "1e100.net" in resolved_domain or "googleusercontent.com" in resolved_domain:
        resolved_domain = "Google Services (YouTube/Search)"
    elif "DESKTOP-" in resolved_domain or resolved_domain == src_ip:
        resolved_domain = "Local Windows Background Traffic"
    elif "akamai" in resolved_domain or "cloudflare" in resolved_domain:
        resolved_domain = "CDN (Cloudflare/Akamai)"
    elif resolved_domain == dst_ip:
        resolved_domain = f"Unknown External Server ({dst_ip})"
    # --------------------------------------------------

    tracking_key = resolved_domain
    has_visited = visited_filter.check(tracking_key)
    
    # 3. ML Inference
    X = pd.DataFrame([[flow_dict.get(c, 0.0) for c in features]], columns=features)
    X = X.replace([float("inf"), float("-inf")], 0).fillna(0)
    X_scaled = scaler.transform(X.values)
    
    pred = iso_model.predict(X_scaled)[0]
    ml_score = iso_model.decision_function(X_scaled)[0]
    
    # 4. Apply Bloom Filter Logic
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not has_visited:
        attack_type = "NEW Domain"
        final_score = ml_score
        visited_filter.add(tracking_key)
        print(f"🆕 [NEW DOMAIN] {tracking_key} | Score: {final_score:.3f}")
    else:
        attack_type = "PREVIOUSLY VISITED"
        final_score = -0.05 
        print(f"✅ [VISITED] {tracking_key} | Assigned Low Score: {final_score}")

    # 5. ALWAYS PUSH TO CLOUD
    is_real_attack = (ml_score < -0.5)
    if is_real_attack:
        attack_type = "DDoS / Anomaly"
        final_score = ml_score
        
    push_alert(ts, src_ip, dst_ip, round(float(final_score), 4), attack_type, proto, dport, tracking_key)

def handle_packet(pkt):
    extractor.update(pkt)
    ready = extractor.flush_ready()
    for r in ready:
        process_flow(r)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "simulate":
        print("\n" + "="*50)
        print("🚨 [WARNING] INITIATING DDoS ATTACK SIMULATION 🚨")
        print("="*50)
        
        print('\a') 
        time.sleep(0.5)
        print('\a') 
        
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alerts_to_insert = []
        
        for i in range(10):
            alerts_to_insert.append({
                "timestamp": ts, "src": "10.98.205.143", "dst": "10.98.205.229", 
                "score": -0.99, "verdict": "ANOMALY", "attack_type": "DDoS / Flood", 
                "protocol": "UDP", "dst_port": 53, "domain": "Simulated_Attack"
            })
            print(f"  -> 🔥 Preparing simulated attack packet {i+1}/10...")
            time.sleep(0.1)
        
        print("\n🚀 Pushing directly to Supabase...")
        try:
            # Bypass the buffer and insert instantly for the demo
            supabase.table("alerts").insert(alerts_to_insert).execute()
            print("\n✅ [SUCCESS] 10 DDoS alerts inserted instantly! Check your Cloud Dashboard.")
        except Exception as e:
            print(f"\n❌ [ERROR] Failed to insert: {e}")
            
        sys.exit()
        
    threading.Thread(target=flush_buffer, daemon=True).start()
    
    iface = sys.argv[1] if len(sys.argv) > 1 else "Wi-Fi"
    print(f"Sniffing on '{iface}' with Bloom Filter Tracking...")
    sniff(iface=iface, prn=handle_packet, store=False)