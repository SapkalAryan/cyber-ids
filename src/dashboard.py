import time
import pandas as pd
import streamlit as st
import plotly.express as px
from supabase import create_client, Client

# --- SUPABASE CONFIG ---
SUPABASE_URL = "https://pdnfytydvpbdtgkbvycd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBkbmZ5dHlkdnBiZHRna2J2eWNkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTIzMzU4MjgsImV4cCI6MjEwNzkxMTgyOH0.xp068vgZEu2bIJFng8Bg9UDjgfjUPnuGcDn3RKDzSDM"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

st.set_page_config(page_title="SOC Threat Monitor", layout="wide")
st.title("SOC Threat Monitor (Cloud)")
st.caption("Live ML Anomaly Detection Synced from Local Wi-Fi Sniffer")

with st.sidebar:
    st.header("Red Team Controls")
    st.write("To simulate a massive DDoS attack, run this command in a **new** local terminal:")
    st.code('python -c "from scapy.all import *; send(IP(dst=\\"10.98.205.229\\")/UDP(dport=53), count=1000, inter=0.001)"')
    
    if st.button("Clear Cloud Database"):
        supabase.table("alerts").delete().neq("id", 0).execute()
        st.success("Database cleared!")

@st.fragment(run_every="2s")
def render_live_data():
    try:
        response = supabase.table("alerts").select("*").order("id", desc=True).limit(100).execute()
        alerts = pd.DataFrame(response.data)
    except Exception as e:
        st.error(f"Database error: {e}")
        return

    if not alerts.empty:
        alerts = alerts.iloc[::-1]
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Alerts", len(alerts))
        c2.metric("Unique Sources", alerts["src"].nunique())
        c3.metric("Last Alert", str(alerts["timestamp"].iloc[-1]))
        top_attack = alerts["attack_type"].mode()[0] if not alerts["attack_type"].empty else "None"
        c4.metric("Top Threat", top_attack)

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Alerts per Minute")
            # Parse the exact local timestamp sent by detect.py
            alerts["datetime"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
            counts = alerts.groupby(alerts["datetime"].dt.floor("min")).size().reset_index(name="count")
            fig = px.bar(counts, x="datetime", y="count", labels={"datetime": "Time", "count": "Alerts"})
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("Top Attacking IPs")
            top_ips = alerts["src"].value_counts().head(5).reset_index()
            top_ips.columns = ["IP Address", "Count"]
            fig_pie = px.pie(top_ips, names="IP Address", values="Count", hole=0.4)
            st.plotly_chart(fig_pie, use_container_width=True)

        st.subheader("Recent Threat Log")
        st.dataframe(alerts[["timestamp", "src", "dst", "score", "verdict", "attack_type"]].iloc[::-1], use_container_width=True)
    else:
        st.info("Waiting for local sniffer to send data to the cloud...")

render_live_data()