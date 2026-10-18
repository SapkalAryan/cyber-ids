import os
import time
import socket
import threading
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime
from scapy.all import IP, TCP, ICMP, send

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_CSV = os.path.join(BASE, "alerts.csv")
GATEWAY_IP = "10.98.205.229" # YOUR ROUTER

st.set_page_config(page_title="SOC Threat Monitor", layout="wide")

def run_ping_flood():
    def flood():
        # Send 100 rapid ICMP packets to the router
        send(IP(dst=GATEWAY_IP)/ICMP(), count=100, verbose=False)
    threading.Thread(target=flood).start()

def run_port_scan():
    def scan():
        # Send 100 rapid TCP SYN packets to different ports on the router
        send(IP(dst=GATEWAY_IP)/TCP(dport=(1,100), flags="S"), verbose=False)
    threading.Thread(target=scan).start()

st.title("SOC Threat Monitor")
st.caption("Real-time Anomaly Detection & Attack Classification (CIC-IDS2017)")

with st.sidebar:
    st.header("Red Team Controls")
    st.write(f"Simulate a Ping Flood (DDoS) against router {GATEWAY_IP}.")
    if st.button("🚨 Launch DDoS Simulation"):
        run_ping_flood()
        st.success("DDoS launched! Watch the dashboard.")
        
    st.write(f"Simulate a TCP Port Scan against router {GATEWAY_IP}.")
    if st.button("🚨 Launch Port Scan"):
        run_port_scan()
        st.success("Scan launched!")

placeholder = st.empty()

def load_alerts():
    cols = ["timestamp", "src", "dst", "score", "verdict", "attack_type"]
    if not os.path.exists(ALERTS_CSV):
        return pd.DataFrame(columns=cols)
    try:
        return pd.read_csv(ALERTS_CSV)
    except Exception:
        return pd.DataFrame(columns=cols)

while True:
    alerts = load_alerts()
    with placeholder.container():
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Alerts", len(alerts))
        c2.metric("Unique Sources", alerts["src"].nunique() if len(alerts) else 0)
        c3.metric("Last Alert", str(alerts["timestamp"].iloc[-1]) if len(alerts) else "—")
        top_attack = alerts["attack_type"].mode()[0] if len(alerts) and not alerts["attack_type"].empty else "None"
        c4.metric("Top Threat", top_attack)

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Alerts per Minute")
            if len(alerts):
                alerts["datetime"] = pd.to_datetime(datetime.now().strftime("%Y-%m-%d ") + alerts["timestamp"].astype(str), errors="coerce")
                counts = alerts.groupby(alerts["datetime"].dt.floor("min")).size().reset_index(name="count")
                counts = counts.rename(columns={"datetime": "time"})
                fig = px.bar(counts, x="time", y="count", labels={"time": "Time", "count": "Alerts"})
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("Top Attacking IPs")
            if len(alerts):
                top_ips = alerts["src"].value_counts().head(5).reset_index()
                top_ips.columns = ["IP Address", "Count"]
                fig_pie = px.pie(top_ips, names="IP Address", values="Count", color_discrete_sequence=px.colors.sequential.Reds_r, hole=0.4)
                st.plotly_chart(fig_pie, use_container_width=True)

        st.subheader("Recent Threat Log")
        if len(alerts):
            display_df = alerts.drop(columns=["datetime"], errors="ignore")
            st.dataframe(display_df.tail(20).iloc[::-1], use_container_width=True)

    time.sleep(2)
    st.rerun()