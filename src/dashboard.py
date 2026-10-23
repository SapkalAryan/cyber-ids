import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
import plotly.express as px
import plotly.graph_objects as go
from supabase import create_client, Client
import re
import socket
from urllib.parse import urlparse
import time
import math
import hashlib

# --- SUPABASE CONFIG ---
SUPABASE_URL = "https://pdnfytydvpbdtgkbvycd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBkbmZ5dHlkdnBiZHRna2J2eWNkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTIzMzU4MjgsImV4cCI6MjEwNzkxMTgyOH0.xp068vgZEu2bIJFng8Bg9UDjgfjUPnuGcDn3RKDzSDM"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

st.set_page_config(page_title="SOC Threat Monitor", layout="wide", menu_items={'Get Help': None, 'Report a bug': None, 'About': "BDA Cyber Threat Detection System"})

is_dark = st.context.theme.type == "dark"
text_color = "white" if is_dark else "black"

# --- CUSTOM CSS FOR FLASHING WARNINGS ---
st.markdown("""
    <style>
    h1, h2, h3 { font-family: 'Courier New', monospace; }
    [data-testid="stMetric"] { background-color: rgba(128, 128, 128, 0.1); padding: 15px; border-radius: 10px; border-left: 5px solid #00FFAA; }
    .critical-warning { background-color: #ff4b4b; color: white; padding: 20px; border-radius: 10px; text-align: center; font-weight: bold; font-size: 24px; animation: flash 1s infinite; border: 3px solid red; }
    @keyframes flash { 0% { background-color: #ff4b4b; box-shadow: 0 0 20px red; } 50% { background-color: #880000; box-shadow: 0 0 5px red; } 100% { background-color: #ff4b4b; box-shadow: 0 0 20px red; } }
    </style>
""", unsafe_allow_html=True)

# --- UNIVERSAL AUDIO, NOTIFICATION & TAB FLASHING ALARM ---
def play_native_alarm():
    js = """
    <audio id="alarm-audio" src="https://actions.google.com/sounds/v1/alarms/alarm_clock.ogg" loop></audio>
    <script>
        // 1. Play Audio
        var audio = document.getElementById("alarm-audio");
        audio.play().catch(function(e) { console.log("Audio blocked:", e); });

        // 2. Trigger Desktop Notification (Shows even if on another tab)
        if (Notification.permission === "granted") {
            new Notification("🚨 CRITICAL WARNING", {
                body: "DDoS ATTACK DETECTED ON YOUR NETWORK!",
                icon: "https://cdn-icons-png.flaticon.com/512/564/564619.png"
            });
        } else if (Notification.permission !== "denied") {
            Notification.requestPermission().then(function (permission) {
                if (permission === "granted") {
                    new Notification("🚨 CRITICAL WARNING", {
                        body: "DDoS ATTACK DETECTED ON YOUR NETWORK!",
                        icon: "https://cdn-icons-png.flaticon.com/512/564/564619.png"
                    });
                }
            });
        }

        // 3. Flash the Tab Title
        var isOriginal = false;
        var interval = setInterval(function() {
            document.title = isOriginal ? "🚨 DDoS ATTACK DETECTED 🚨" : "🛡️ SOC Threat Monitor";
            isOriginal = !isOriginal;
        }, 1000);
        
        // Stop flashing after 30 seconds to avoid annoyance
        setTimeout(function() { clearInterval(interval); document.title = "🛡️ SOC Threat Monitor"; }, 30000);
    </script>
    """
    components.html(js, height=0)

# Helper function for Reverse DNS
@st.cache_data(ttl=3600)
def get_domain_name(ip):
    if re.match(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip) or re.match(r"^192\.168\.\d{1,3}\.\d{1,3}$", ip):
        return "Local Network"
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

# --- BLOOM FILTER LOGIC ---
class BloomFilter:
    def __init__(self, expected_items, false_positive_rate):
        self.size = math.ceil((expected_items * math.log(false_positive_rate)) / math.log(1 / (2 ** math.log(2))))
        self.hash_count = math.ceil((self.size / expected_items) * math.log(2))
        self.bit_array = bytearray(self.size)
    def _hashes(self, item):
        item = item.encode('utf-8'); hashes = []
        for i in range(self.hash_count):
            digest = hashlib.sha256(item + str(i).encode('utf-8')).hexdigest()
            hashes.append(int(digest, 16) % self.size)
        return hashes
    def add(self, item):
        for hash_val in self._hashes(item): self.bit_array[hash_val] = 1
    def check(self, item):
        for hash_val in self._hashes(item):
            if self.bit_array[hash_val] == 0: return False
        return True

if "visited_filter" not in st.session_state:
    st.session_state.visited_filter = BloomFilter(expected_items=10000, false_positive_rate=0.01)
    popular_sites = ["google.com", "youtube.com", "facebook.com", "amazon.com", "github.com", "flipkart.com"]
    for site in popular_sites: st.session_state.visited_filter.add(site)

visited_filter = st.session_state.visited_filter

# Create Tabs
tab1, tab2, tab3, tab4 = st.tabs(["🌐 Live Network Traffic", "🛡️ Link Interceptor", "📄 File Scanner", "🔗 URL Reputation"])

# ==========================================
# TAB 1: LIVE NETWORK TRAFFIC
# ==========================================
with tab1:
    dashboard_placeholder = st.empty()
    @st.fragment(run_every="1s")
    def render_live_data():
        try:
            response = supabase.table("alerts").select("*").order("id", desc=True).limit(500).execute()
            alerts = pd.DataFrame(response.data)
        except Exception as e:
            st.error(f"Database error: {e}")
            return

        with dashboard_placeholder.container():
            if not alerts.empty:
                alerts = alerts.iloc[::-1]
                recent_attacks = alerts.tail(10)
                ddos_detected = recent_attacks[recent_attacks["attack_type"].str.contains("DDoS", na=False)].shape[0] > 0

                with st.sidebar:
                    st.markdown("### 🟢 System Status: **ACTIVE**")
                    st.metric("Total Alerts", len(alerts))
                    st.metric("Unique Sources", alerts["src"].nunique())
                    top_attack = alerts["attack_type"].mode()[0] if not alerts["attack_type"].dropna().empty else "None"
                    st.metric("Top Threat", top_attack)
                    if st.button("Clear Cloud Database", use_container_width=True):
                        supabase.table("alerts").delete().neq("id", 0).execute()
                        st.session_state["ddos_alert_playing"] = False
                        st.rerun()

                # --- THE DDoS ALARM LOGIC ---
                if ddos_detected:
                    if not st.session_state.get("ddos_alert_playing", False):
                        st.session_state["ddos_alert_playing"] = True
                        
                        # 1. Play audio & Desktop Notification & Tab Flashing
                        play_native_alarm()
                        
                        # 2. Trigger a native browser popup box
                        components.html("<script>alert('🚨 CRITICAL WARNING: DDoS ATTACK DETECTED! 🚨');</script>", height=0)
                    
                    st.markdown('<div class="critical-warning">🚨 CRITICAL WARNING: DDoS ATTACK DETECTED 🚨</div>', unsafe_allow_html=True)
                    st.write("")
                    
                    if st.button("🛑 STOP ATTACK (Clear DB)", type="primary", use_container_width=True):
                        st.session_state["ddos_alert_playing"] = False
                        supabase.table("alerts").delete().neq("id", 0).execute()
                        st.rerun()
                else:
                    st.session_state["ddos_alert_playing"] = False

                col1, col2, col3 = st.columns((2, 1, 1))
                
                with col1:
                    st.subheader("📊 Threat Velocity")
                    alerts["datetime"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
                    counts = alerts.groupby(alerts["datetime"].dt.floor("min")).size().reset_index(name="count")
                    fig = go.Figure(data=[go.Scatter(x=counts["datetime"], y=counts["count"], mode='lines+markers', line=dict(color='#00FFAA', width=3), fill='tozeroy', fillcolor='rgba(0, 255, 170, 0.1)')])
                    fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font=dict(color=text_color))
                    st.plotly_chart(fig, use_container_width=True)

                with col2:
                    st.subheader("🧠 Bloom Memory")
                    bf_counts = alerts["attack_type"].value_counts().reset_index()
                    bf_counts.columns = ["Type", "Count"]
                    bf_counts = bf_counts[bf_counts["Type"].isin(["NEW Domain", "PREVIOUSLY VISITED"])]
                    
                    if not bf_counts.empty:
                        fig_bf = px.pie(bf_counts, names="Type", values="Count", hole=0.5, 
                                        color="Type",
                                        color_discrete_map={"NEW Domain": "#FF4B4B", "PREVIOUSLY VISITED": "#00FFAA"})
                        fig_bf.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font=dict(color=text_color), showlegend=False)
                        st.plotly_chart(fig_bf, use_container_width=True)
                    else:
                        st.info("No Bloom Filter data yet.")

                with col3:
                    st.subheader("🥧 Attack Vectors")
                    if "protocol" in alerts.columns and not alerts["protocol"].dropna().empty:
                        proto_counts = alerts["protocol"].value_counts().reset_index()
                        proto_counts.columns = ["Protocol", "Count"]
                        fig_pie = px.pie(proto_counts, names="Protocol", values="Count", hole=0.5, color_discrete_sequence=px.colors.sequential.Teal)
                        fig_pie.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font=dict(color=text_color))
                        st.plotly_chart(fig_pie, use_container_width=True)

                st.subheader("📋 Recent Threat Log")
                display_cols = ["timestamp", "src", "dst", "domain", "attack_type", "protocol", "dst_port", "score"]
                available_cols = [c for c in display_cols if c in alerts.columns]
                display_df = alerts[available_cols].iloc[::-1].copy()
                if "dst" in display_df.columns:
                    display_df["dst_domain"] = display_df["dst"].apply(get_domain_name)
                    display_df = display_df[["timestamp", "src", "dst", "dst_domain", "attack_type", "protocol", "dst_port", "score"]]
                display_df["Threat Score"] = (display_df["score"].abs() * 100).round(1)
                st.dataframe(display_df, use_container_width=True, column_config={"Threat Score": st.column_config.ProgressColumn("Threat Level", format="%.1f", min_value=0, max_value=100, color="#FF4B4B"), "score": None})
            else:
                st.info("Waiting for data...")
    render_live_data()

# ==========================================
# TAB 2: LINK INTERCEPTOR
# ==========================================
with tab2:
    st.header("🛡️ Secure Link Interceptor")
    st.write("Type a URL and press **Enter**. The system will scan it automatically.")
    
    target_url = st.text_input("Enter URL to visit (e.g., https://google.com or http://hack-site.xyz):")
    
    if target_url:
        if not target_url.startswith("http"):
            target_url = "http://" + target_url
            
        parsed = urlparse(target_url)
        domain = parsed.netloc.lower()
        
        with st.spinner("Analyzing link..."):
            time.sleep(0.5)
            
            is_known = visited_filter.check(domain)
            
            flags = []
            risk_score = 0
            
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain): 
                flags.append("Raw IP Address")
                risk_score += 50
                
            if any(domain.endswith(tld) for tld in [".xyz", ".top", ".club", ".click"]): 
                flags.append("High-Risk TLD")
                risk_score += 60
                
            if domain.count("-") > 2: 
                flags.append("Excessive Hyphens")
                risk_score += 30
            
            st.divider()
            st.subheader("Scan Results")
            
            # --- LOW RISK / KNOWN DOMAIN ---
            if is_known and risk_score == 0:
                st.success(f"✅ **SAFE:** `{domain}` is recognized as safe.")
                st.link_button(f"👉 Click here to open {domain}", target_url, use_container_width=True)
            
            # --- MEDIUM RISK / UNKNOWN DOMAIN ---
            elif not is_known and risk_score < 50:
                # PLAY AUDIO & POPUP
                play_native_alarm()
                components.html(f"<script>alert('WARNING: {domain} is not in your recent links.');</script>", height=0)
                
                st.warning(f"⚠️ **MEDIUM WARNING:** `{domain}` is **NOT** in your recent links.")
                st.write("**Detection Flags:**", ", ".join(flags) if flags else "None")
                
                session_key = f"proceed_{domain}"
                
                if not st.session_state.get(session_key, False):
                    if st.button("I Understand the Risk, Proceed", type="primary"):
                        st.session_state[session_key] = True
                        visited_filter.add(domain)
                        st.rerun()
                else:
                    st.link_button(f"👉 Take me to {domain}", target_url, use_container_width=True)
            
            # --- HIGH RISK / SUSPICIOUS URL ---
            else:
                # PLAY AUDIO & POPUP
                play_native_alarm()
                components.html("<script>alert('CRITICAL: MALICIOUS LINK DETECTED! ACCESS BLOCKED.');</script>", height=0)
                
                st.markdown(f'<div class="critical-warning">🚨 CRITICAL WARNING 🚨<br>This URL looks like a Phishing Attack!<br>Risk Score: {risk_score}/100</div>', unsafe_allow_html=True)
                st.write("")
                st.write("**Detection Flags:**", ", ".join(flags))
                st.error("🛑 ACCESS BLOCKED BY SOC SYSTEM 🛑")
                st.write("The system has prevented you from opening this malicious link.")
    else:
        st.info("Waiting for you to type a URL...")

# ==========================================
# TAB 3: FILE SCANNER
# ==========================================
with tab3:
    st.header("📄 Upload Suspicious File")
    uploaded_file = st.file_uploader("Choose a file", type=["txt", "eml"])
    if uploaded_file is not None:
        text_content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
        st.text_area("File Content Preview", text_content[:500] + "...", height=150)
        if st.button("🔍 Run Threat Analytics", use_container_width=True):
            url_pattern = r'(https?://[^\s]+)'
            found_urls = re.findall(url_pattern, text_content)
            phishing_keywords = ["urgent", "verify", "password", "bank", "click here", "login"]
            found_keywords = [kw for kw in phishing_keywords if kw in text_content.lower()]
            
            risk_score = (len(found_urls) * 20) + (len(found_keywords) * 15)
            risk_score = min(risk_score, 100)
            
            st.subheader("Analysis Results")
            m1, m2 = st.columns(2)
            m1.metric("Risk Score", f"{risk_score}/100")
            m2.metric("Phishing Keywords", len(found_keywords))
            
            if risk_score > 50: 
                play_native_alarm()
                components.html("<script>alert('WARNING: HIGH RISK FILE DETECTED!');</script>", height=0)
                st.error("🚨 HIGH RISK: Phishing indicators found.")
            elif risk_score > 20: st.warning("⚠️ MEDIUM RISK: Suspicious patterns detected.")
            else: st.success("✅ LOW RISK: No obvious threats detected.")
            
            if found_urls:
                st.write("**Malicious URLs:**")
                for u in found_urls: st.code(u)

# ==========================================
# TAB 4: OFFLINE URL SCANNER
# ==========================================
with tab4:
    st.header("🔗 URL Lexical Threat Scanner")
    url_to_scan = st.text_input("Enter a URL to scan (e.g., http://paypal-secure-login.com):")
    if st.button("🌐 Scan URL", use_container_width=True):
        if url_to_scan:
            if not url_to_scan.startswith("http"): url_to_scan = "http://" + url_to_scan
            parsed = urlparse(url_to_scan)
            domain = parsed.netloc.lower()
            
            flags = []
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain): flags.append("Uses a raw IP address")
            bad_tlds = [".xyz", ".top", ".club", ".work", ".click", ".link"]
            if any(domain.endswith(tld) for tld in bad_tlds): flags.append("High-risk TLD")
            if domain.count(".") > 3: flags.append("Excessive subdomains (Typosquatting)")
            keywords = ["login", "secure", "account", "update", "verify", "bank"]
            found_kws = [kw for kw in keywords if kw in domain]
            if found_kws: flags.append(f"Sensitive keywords: {', '.join(found_kws)}")
            if domain.count("-") > 2: flags.append("Excessive hyphens")
            
            risk_score = min(len(flags) * 20, 100)
            
            st.subheader("Scan Results")
            c1, c2 = st.columns(2)
            c1.metric("Target Domain", domain)
            c2.metric("Risk Score", f"{risk_score}/100")
            
            if risk_score >= 60:
                play_native_alarm()
                components.html("<script>alert('WARNING: PHISHING URL DETECTED!');</script>", height=0)
                st.error("🚨 HIGH RISK: Phishing scam characteristics detected.")
            elif risk_score >= 20: st.warning("⚠️ MEDIUM RISK: Suspicious patterns.")
            else: st.success("✅ LOW RISK: No obvious threats.")
            
            if flags:
                st.write("### Detection Flags")
                for flag in flags: st.write(f"- ⚠️ {flag}")