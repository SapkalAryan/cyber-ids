import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from supabase import create_client, Client
import re
import socket
from urllib.parse import urlparse

# --- SUPABASE CONFIG ---
SUPABASE_URL = "https://pdnfytydvpbdtgkbvycd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBkbmZ5dHlkdnBiZHRna2J2eWNkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTIzMzU4MjgsImV4cCI6MjEwNzkxMTgyOH0.xp068vgZEu2bIJFng8Bg9UDjgfjUPnuGcDn3RKDzSDM"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

st.set_page_config(page_title="SOC Threat Monitor", layout="wide", menu_items={'Get Help': None, 'Report a bug': None, 'About': "BDA Cyber Threat Detection System"})

# Determine current theme to style charts correctly
is_dark = st.context.theme.type == "dark"
text_color = "white" if is_dark else "black"

# Minimal, theme-aware CSS
st.markdown("""
    <style>
    h1, h2, h3 { font-family: 'Courier New', monospace; }
    [data-testid="stMetric"] { 
        background-color: rgba(128, 128, 128, 0.1); 
        padding: 15px; 
        border-radius: 10px; 
        border-left: 5px solid #00FFAA; 
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Enterprise SOC & Threat Analytics")
st.caption("Live Network ML | Batch Ingestion | Unstructured Text & Email Analytics")

# Helper function for Offline Reverse DNS & Organization mapping
@st.cache_data(ttl=3600)
def get_domain_name(ip):
    if re.match(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip) or re.match(r"^192\.168\.\d{1,3}\.\d{1,3}$", ip):
        return "Local Network"
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        if ip.startswith("142.") or ip.startswith("172.217.") or ip.startswith("74.125."): return "Google Services"
        elif ip.startswith("20.") or ip.startswith("52.") or ip.startswith("13.107."): return "Microsoft / Azure"
        elif ip.startswith("104.") or ip.startswith("185.") or ip.startswith("34.") or ip.startswith("18.66."): return "Cloudflare / Akamai / AWS"
        elif ip.startswith("140.82."): return "GitHub Services"
        else: return "Unknown External Server"

tab1, tab2, tab3 = st.tabs(["🌐 Live Network Traffic", "📄 File & Email Scanner", "🔗 URL Reputation Scanner"])

# ==========================================
# TAB 1: LIVE NETWORK TRAFFIC
# ==========================================
with tab1:
    dashboard_placeholder = st.empty()

    @st.fragment(run_every="2s")
    def render_live_data():
        try:
            response = supabase.table("alerts").select("*").order("id", desc=True).limit(500).execute()
            alerts = pd.DataFrame(response.data)
        except Exception as e:
            st.error(f"Database connection error: {e}")
            return

        with dashboard_placeholder.container():
            if not alerts.empty:
                alerts = alerts.iloc[::-1]
                
                with st.sidebar:
                    st.markdown("### 🟢 System Status: **ACTIVE**")
                    st.divider()
                    st.subheader("Live Metrics")
                    st.metric("Total Alerts", len(alerts))
                    st.metric("Unique Sources", alerts["src"].nunique())
                    
                    top_attack = alerts["attack_type"].mode()[0] if not alerts["attack_type"].dropna().empty else "None"
                    st.metric("Top Threat", top_attack)
                    
                    st.divider()
                    st.subheader("Database Admin")
                    if st.button("Clear Cloud Database", use_container_width=True):
                        supabase.table("alerts").delete().neq("id", 0).execute()
                        st.success("Database cleared!")
                        st.rerun()

                col1, col2 = st.columns((2, 1))
                
                with col1:
                    st.subheader("📊 Threat Velocity (Alerts per Minute)")
                    alerts["datetime"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
                    counts = alerts.groupby(alerts["datetime"].dt.floor("min")).size().reset_index(name="count")
                    
                    fig = go.Figure(data=[go.Scatter(
                        x=counts["datetime"], y=counts["count"],
                        mode='lines+markers',
                        line=dict(color='#00FFAA', width=3),
                        fill='tozeroy',
                        fillcolor='rgba(0, 255, 170, 0.1)'
                    )])
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                        font=dict(color=text_color), margin=dict(l=0, r=0, t=10, b=0),
                        xaxis=dict(showgrid=True, gridcolor='rgba(128,128,128,0.2)'), 
                        yaxis=dict(showgrid=True, gridcolor='rgba(128,128,128,0.2)')
                    )
                    st.plotly_chart(fig, use_container_width=True)

                with col2:
                    st.subheader("🥧 Attack Vectors")
                    if "protocol" in alerts.columns and not alerts["protocol"].dropna().empty:
                        proto_counts = alerts["protocol"].value_counts().reset_index()
                        proto_counts.columns = ["Protocol", "Count"]
                        fig_pie = px.pie(proto_counts, names="Protocol", values="Count", hole=0.6,
                                         color_discrete_sequence=px.colors.sequential.Teal)
                        fig_pie.update_layout(
                            plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                            font=dict(color=text_color), margin=dict(l=0, r=0, t=10, b=0)
                        )
                        st.plotly_chart(fig_pie, use_container_width=True)
                    else:
                        st.info("Waiting for protocol data...")

                st.subheader("📋 Recent Threat Log")
                display_cols = ["timestamp", "src", "dst", "domain", "attack_type", "protocol", "dst_port", "score"]
                available_cols = [c for c in display_cols if c in alerts.columns]
                
                display_df = alerts[available_cols].iloc[::-1].copy()
                if "dst" in display_df.columns:
                    display_df["dst_domain"] = display_df["dst"].apply(get_domain_name)
                    display_df = display_df[["timestamp", "src", "dst", "dst_domain", "attack_type", "protocol", "dst_port", "score"]]

                # Convert negative anomaly scores to positive 0-100 Threat Scores
                display_df["Threat Score"] = (display_df["score"].abs() * 100).round(1)

                st.dataframe(
                    display_df, 
                    use_container_width=True,
                    column_config={
                        "Threat Score": st.column_config.ProgressColumn(
                            "Threat Level (0-100)",
                            help="0 = Normal Traffic, 100 = Critical Anomaly",
                            format="%.1f",
                            min_value=0,
                            max_value=100,
                            color="#FF4B4B" # Bright red bar
                        ),
                        "score": None # Hide the raw negative score
                    }
                )
            else:
                st.info("Waiting for local sniffer to send data to the cloud...")

    render_live_data()

# ==========================================
# TAB 2: FILE & EMAIL SCANNER
# ==========================================
with tab2:
    st.header("📄 Upload Suspicious File or Email")
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
                
                if risk_score > 50: st.error("🚨 HIGH RISK: Phishing indicators found.")
                elif risk_score > 20: st.warning("⚠️ MEDIUM RISK: Suspicious patterns detected.")
                else: st.success("✅ LOW RISK: No obvious threats detected.")
                
                if found_urls or found_ips or found_keywords:
                    st.write("### Extracted Threats")
                    chart_data = pd.DataFrame({"Threat Type": ["URLs", "IPs", "Keywords"], "Count": [len(found_urls), len(found_ips), len(found_keywords)]})
                    chart_data = chart_data[chart_data["Count"] > 0]
                    fig = px.bar(chart_data, x="Threat Type", y="Count", color="Threat Type", color_discrete_sequence=px.colors.sequential.Reds_r)
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', 
                        font=dict(color=text_color)
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    if found_urls:
                        st.write("**Malicious URLs:**")
                        for u in found_urls: st.code(u)

# ==========================================
# TAB 3: OFFLINE URL REPUTATION SCANNER
# ==========================================
with tab3:
    st.header("🔗 URL Lexical Threat Scanner")
    st.write("Scan a URL locally using heuristic analysis to detect phishing, typosquatting, and malicious patterns without relying on external APIs.")
    
    url_to_scan = st.text_input("Enter a URL to scan (e.g., http://paypal-secure-login.com):")
    
    if st.button("🌐 Scan URL", use_container_width=True):
        if not url_to_scan:
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Running lexical analysis..."):
                if not url_to_scan.startswith("http"):
                    url_to_scan = "http://" + url_to_scan
                    
                parsed = urlparse(url_to_scan)
                domain = parsed.netloc.lower()
                path = parsed.path.lower()
                
                flags = []
                
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
                    flags.append("Uses a raw IP address (suspicious)")
                
                bad_tlds = [".xyz", ".top", ".club", ".work", ".click", ".link"]
                if any(domain.endswith(tld) for tld in bad_tlds):
                    flags.append("Uses a high-risk Top Level Domain (TLD)")
                
                if domain.count(".") > 3:
                    flags.append("Excessive subdomains (Typosquatting/Phishing)")
                
                keywords = ["login", "secure", "account", "update", "verify", "bank", "signin", "password"]
                found_kws = [kw for kw in keywords if kw in domain or kw in path]
                if found_kws:
                    flags.append(f"Contains sensitive keywords: {', '.join(found_kws)}")
                
                shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"]
                if domain in shorteners:
                    flags.append("Uses a URL shortener (Hides true destination)")
                
                if domain.count("-") > 2:
                    flags.append("Excessive hyphens in domain name")
                
                risk_score = len(flags) * 20
                risk_score = min(risk_score, 100)
                
                st.subheader("Scan Results")
                c1, c2 = st.columns(2)
                c1.metric("Target Domain", domain)
                c2.metric("Risk Score", f"{risk_score}/100")
                
                if risk_score >= 60:
                    st.error("🚨 HIGH RISK: This URL exhibits multiple characteristics of a phishing scam.")
                elif risk_score >= 20:
                    st.warning("⚠️ MEDIUM RISK: Suspicious patterns detected.")
                else:
                    st.success("✅ LOW RISK: No obvious lexical threats detected.")
                
                if flags:
                    st.write("### Detection Flags")
                    for flag in flags:
                        st.write(f"- ⚠️ {flag}")
                else:
                    st.write("No malicious patterns found in the URL string.")