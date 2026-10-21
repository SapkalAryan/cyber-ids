import pandas as pd
import streamlit as st
import plotly.express as px
from supabase import create_client, Client
import re

# --- SUPABASE CONFIG ---
SUPABASE_URL = "https://pdnfytydvpbdtgkbvycd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBkbmZ5dHlkdnBiZHRna2J2eWNkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTIzMzU4MjgsImV4cCI6MjEwNzkxMTgyOH0.xp068vgZEu2bIJFng8Bg9UDjgfjUPnuGcDn3RKDzSDM"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

st.set_page_config(
    page_title="SOC Threat Monitor", 
    layout="wide",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': "BDA Cyber Threat Detection System"
    }
)

st.title("🛡️ Enterprise SOC & Threat Analytics")
st.caption("Live Network ML | Batch Ingestion | Unstructured Text & Email Analytics")

# Create two tabs
tab1, tab2 = st.tabs(["🌐 Live Network Traffic", "📄 File & Email Scanner"])

# ==========================================
# TAB 1: YOUR ORIGINAL DASHBOARD
# ==========================================
with tab1:
    with st.sidebar:
        st.header("Database Admin")
        st.write("Clear the current threat logs from the cloud database.")
        if st.button("Clear Cloud Database", use_container_width=True):
            supabase.table("alerts").delete().neq("id", 0).execute()
            st.success("Database cleared!")

    @st.fragment(run_every="2s")
    def render_live_data():
        try:
            response = supabase.table("alerts").select("*").order("id", desc=True).limit(500).execute()
            alerts = pd.DataFrame(response.data)
        except Exception as e:
            st.error(f"Database error: {e}")
            return

        if not alerts.empty:
            alerts = alerts.iloc[::-1]
            
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Alerts", len(alerts))
            c2.metric("Unique Sources", alerts["src"].nunique())
            
            top_port = alerts["dst_port"].mode()[0] if "dst_port" in alerts.columns and not alerts["dst_port"].empty else "N/A"
            c3.metric("Top Target Port", top_port)
            
            top_attack = alerts["attack_type"].mode()[0] if not alerts["attack_type"].empty else "None"
            c4.metric("Top Threat", top_attack)

            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Alerts per Minute")
                alerts["datetime"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
                counts = alerts.groupby(alerts["datetime"].dt.floor("min")).size().reset_index(name="count")
                fig = px.bar(counts, x="datetime", y="count", labels={"datetime": "Time", "count": "Alerts"})
                st.plotly_chart(fig, use_container_width=True)

            with col2:
                st.subheader("Protocol Distribution")
                if "protocol" in alerts.columns:
                    proto_counts = alerts["protocol"].value_counts().reset_index()
                    proto_counts.columns = ["Protocol", "Count"]
                    fig_pie = px.pie(proto_counts, names="Protocol", values="Count", hole=0.4)
                    st.plotly_chart(fig_pie, use_container_width=True)
                else:
                    st.info("Protocol data not yet available.")

            st.subheader("Recent Threat Log")
            display_cols = ["timestamp", "src", "dst", "attack_type", "protocol", "dst_port", "score"]
            available_cols = [c for c in display_cols if c in alerts.columns]
            st.dataframe(alerts[available_cols].iloc[::-1], use_container_width=True)
        else:
            st.info("Waiting for local sniffer to send data to the cloud...")

    render_live_data()

# ==========================================
# TAB 2: NEW FILE & EMAIL SCANNER
# ==========================================
with tab2:
    st.header("Upload Suspicious File or Email")
    st.write("Upload a `.txt` or `.eml` file. The system will scan it for malicious URLs, suspicious IPs, and phishing keywords.")
    
    uploaded_file = st.file_uploader("Choose a file", type=["txt", "eml"])
    
    if uploaded_file is not None:
        text_content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
        st.text_area("File Content Preview", text_content[:500] + "...", height=150)
        
        if st.button("🔍 Run Threat Analytics", use_container_width=True):
            with st.spinner("Analyzing text patterns..."):
                url_pattern = r'(https?://[^\s]+)'
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                phishing_keywords = ["urgent", "verify", "password", "bank", "account suspended", "click here", "login"]
                
                found_urls = re.findall(url_pattern, text_content)
                found_ips = re.findall(ip_pattern, text_content)
                found_keywords = [kw for kw in phishing_keywords if kw in text_content.lower()]
                
                risk_score = (len(found_urls) * 20) + (len(found_ips) * 30) + (len(found_keywords) * 15)
                risk_score = min(risk_score, 100)
                
                st.subheader("Analysis Results")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Risk Score", f"{risk_score}/100")
                m2.metric("URLs Found", len(found_urls))
                m3.metric("IPs Found", len(found_ips))
                m4.metric("Phishing Keywords", len(found_keywords))
                
                if risk_score > 50:
                    st.error("🚨 HIGH RISK: This file contains multiple indicators of a phishing attack or malware.")
                elif risk_score > 20:
                    st.warning("⚠️ MEDIUM RISK: Suspicious patterns detected. Proceed with caution.")
                else:
                    st.success("✅ LOW RISK: No obvious threats detected.")
                
                if found_urls or found_ips or found_keywords:
                    st.write("### Extracted Threats")
                    chart_data = pd.DataFrame({
                        "Threat Type": ["URLs", "IP Addresses", "Keywords"],
                        "Count": [len(found_urls), len(found_ips), len(found_keywords)]
                    })
                    fig = px.bar(chart_data, x="Threat Type", y="Count", color="Threat Type", title="Threat Composition")
                    st.plotly_chart(fig, use_container_width=True)

                    if found_urls:
                        st.write("**Malicious URLs:**")
                        for u in found_urls: st.code(u)
                    if found_ips:
                        st.write("**Suspicious IP Addresses:**")
                        for ip in found_ips: st.code(ip)