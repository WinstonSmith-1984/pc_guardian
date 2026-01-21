import streamlit as st
import pyshark
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import threading
import time
import requests
from collections import deque, Counter
from datetime import datetime

# --- SHARED STATE ---
class MonitorState:
    def __init__(self):
        self.risk_score = 0
        self.threat_log = deque(maxlen=15)
        self.live_feed = deque(maxlen=25) 
        self.pps_history = deque([0]*30, maxlen=30)
        self.proto_counts = Counter()
        self.geo_data = []
        self.seen_ips = set()
        self.packet_counter = 0
        self.sensitivity = 1.0
        self.last_heartbeat = "Initializing..."
        self.is_running = True
        self.current_interface = 'any'
        self.map_all_traffic = True

if 'monitor' not in st.session_state:
    st.session_state.monitor = MonitorState()

# --- UTILITIES ---
def get_geo_location(ip, state, proto):
    private_prefixes = ['127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.3', '169.254.', '0.0.0.0']
    if any(ip.startswith(p) for p in private_prefixes) or ip in state.seen_ips:
        return
    
    try:
        fields = "status,city,country,isp,org,as,lat,lon,proxy,hosting"
        r = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=2).json()
        if r.get('status') == 'success':
            entry = {
                'ip': ip, 'location': f"{r['city']}, {r['country']}",
                'country': r.get('country', 'Unknown'), 'isp': r.get('isp', 'Unknown'),
                'org': r.get('org', 'Unknown'), 'as': r.get('as', 'Unknown'), 
                'lat': r['lat'], 'lon': r['lon'], 'proto': proto,
                'is_proxy': r.get('proxy', False), 'is_hosting': r.get('hosting', False)
            }
            state.geo_data.append(entry)
            state.seen_ips.add(ip)
    except:
        pass

def process_packet(pkt, state):
    try:
        timestamp = datetime.now().strftime("%H:%M:%S")
        proto = pkt.highest_layer
        state.proto_counts[proto] += 1
        
        src = pkt.ip.src if hasattr(pkt, 'ip') else "Internal"
        dst = pkt.ip.dst if hasattr(pkt, 'ip') else "Internal"
        state.live_feed.append(f"{timestamp} | {proto} | {src} -> {dst}")
        
        if state.map_all_traffic and src != "Internal":
            threading.Thread(target=get_geo_location, args=(src, state, proto), daemon=True).start()

        mult = state.sensitivity
        if 'TCP' in pkt and hasattr(pkt.tcp, 'flags_reset') and pkt.tcp.flags_reset == '1':
            added_risk = 20 * mult
            state.risk_score = min(100, state.risk_score + added_risk)
            state.threat_log.appendleft(f"⚠️ TCP Reset: {src}")
    except:
        pass

# --- BACKGROUND SERVICES ---
def run_sniffer(state):
    while state.is_running:
        try:
            cap = pyshark.LiveCapture(interface=state.current_interface)
            for pkt in cap.sniff_continuously():
                state.packet_counter += 1
                state.last_heartbeat = datetime.now().strftime("%H:%M:%S")
                process_packet(pkt, state)
                if not state.is_running: break
        except Exception as e:
            state.last_heartbeat = f"Error: {e}"
            time.sleep(2)

def run_pps_calculator(state):
    while state.is_running:
        initial = state.packet_counter
        time.sleep(1)
        state.pps_history.append(state.packet_counter - initial)

# --- UI SETUP ---
st.set_page_config(page_title="Guardian HUD", layout="wide")

st.markdown("""
<style>
    .paypal-btn {
        display: inline-block;
        background: #0070ba;
        color: white !important;
        text-decoration: none;
        padding: 10px 20px;
        border-radius: 25px;
        font-weight: bold;
        font-size: 0.9rem;
        text-align: center;
        width: 100%;
        margin-top: 10px;
    }
    .paypal-btn:hover { background: #005ea6; }
    .footer-text {
        font-size: 0.7rem;
        color: #888;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 20px;
        font-weight: bold;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

if 'started' not in st.session_state:
    threading.Thread(target=run_sniffer, args=(st.session_state.monitor,), daemon=True).start()
    threading.Thread(target=run_pps_calculator, args=(st.session_state.monitor,), daemon=True).start()
    st.session_state['started'] = True

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛠️ Settings")
    st.session_state.monitor.current_interface = st.selectbox("Interface", ['any', 'enp1s0', 'lo'])
    st.session_state.monitor.map_all_traffic = st.toggle("Map All External IPs", value=True)
    st.session_state.monitor.sensitivity = st.slider("Sensitivity", 0.5, 2.0, 1.0)
    
    if st.button("Reset All Stats", width='stretch'):
        st.session_state.monitor.risk_score = 0
        st.session_state.monitor.proto_counts.clear()
        st.session_state.monitor.threat_log.clear()
        st.session_state.monitor.geo_data.clear()
        st.session_state.monitor.seen_ips.clear()
        st.rerun()
    
    st.metric("Status", "ACTIVE", delta=st.session_state.monitor.last_heartbeat)
    st.markdown("---")
    
    # PAYPAL DONATION SECTION & REVISED CREDIT
    st.markdown('<div class="footer-text">Support Development</div>', unsafe_allow_html=True)
    st.markdown('<a href="https://paypal.me/conlon1984" target="_blank" class="paypal-btn">💙 Donate via PayPal</a>', unsafe_allow_html=True)
    st.markdown('<div style="text-align:center; font-size:0.7rem; color:#666; margin-top:10px;">🛡️ System built by <b>WinstonSmith_1984</b></div>', unsafe_allow_html=True)

# --- LIVE DASHBOARD FRAGMENT ---
@st.fragment(run_every=5)
def live_dashboard():
    st.title("🛡️ Network Alert Status")
    
    col1, col2 = st.columns([1, 1.2])
    with col1:
        current_pps = st.session_state.monitor.pps_history[-1] if st.session_state.monitor.pps_history else 0
        fig_gauge = go.Figure()
        
        fig_gauge.add_trace(go.Indicator(
            mode="gauge+number", value=current_pps,
            domain={'x': [0, 1], 'y': [0.15, 1]},
            gauge={
                'axis': {'range': [0, max(500, current_pps * 1.2)], 'tickwidth': 1},
                'bar': {'color': "#2ecc71"},
                'steps': [
                    {'range': [0, 200], 'color': "rgba(46, 204, 113, 0.2)"}, 
                    {'range': [200, 400], 'color': "rgba(243, 156, 18, 0.2)"}, 
                    {'range': [400, 10000], 'color': "rgba(231, 76, 60, 0.2)"}
                ]
            }
        ))
        
        fig_gauge.add_annotation(
            text="Current Throughput (PPS)", xref="paper", yref="paper",
            x=0.5, y=0.08, showarrow=False, font=dict(size=18, color="gray")
        )
        fig_gauge.update_layout(height=400, margin=dict(t=20, b=20), paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_gauge, width='stretch')

    with col2:
        if st.session_state.monitor.proto_counts:
            df_proto = pd.DataFrame(st.session_state.monitor.proto_counts.items(), columns=['Protocol', 'Count'])
            fig_proto = px.pie(df_proto, values='Count', names='Protocol', hole=0.5,
                               color_discrete_sequence=px.colors.qualitative.Bold)
            
            fig_proto.update_layout(
                height=440, 
                margin=dict(t=20, b=40),
                legend=dict(font=dict(size=16)), 
                paper_bgcolor="rgba(0,0,0,0)"
            )
            fig_proto.add_annotation(
                text="Protocol Distribution", xref="paper", yref="paper",
                x=0.5, y=0.08, showarrow=False, font=dict(size=22, color="gray")
            )
            fig_proto.update_traces(textinfo='percent+label', textfont_size=14)
            st.plotly_chart(fig_proto, width='stretch')
        else:
            st.info("Gathering protocol data...")

    st.markdown("---")
    feed_col, map_col = st.columns([1, 1])
    
    with feed_col:
        st.subheader("📡 Live Activity Stream")
        with st.container(height=350):
            feed_text = "\n".join(list(st.session_state.monitor.live_feed))
            st.code(feed_text if feed_text else "Awaiting packets...", language="text")

    with map_col:
        st.subheader("🌍 Traffic Origin Map")
        if st.session_state.monitor.geo_data:
            df_geo = pd.DataFrame(st.session_state.monitor.geo_data)
            fig_map = px.scatter_geo(df_geo, lat='lat', lon='lon', hover_name='ip', projection="natural earth")
            fig_map.update_traces(marker=dict(size=14, color='#e74c3c', line=dict(width=1, color='white')))
            fig_map.update_layout(height=360, margin=dict(l=0, r=0, t=0, b=0), geo=dict(showland=True, landcolor="#1b2631", bgcolor="rgba(0,0,0,0)"))
            st.plotly_chart(fig_map, width='stretch')
        else:
            st.info("Awaiting external IP mapping...")

    st.markdown("---")
    st.subheader("🚨 Threat Detections")
    threat_snapshot = list(st.session_state.monitor.threat_log)
    if threat_snapshot:
        for entry in threat_snapshot:
            st.error(entry)
    else:
        st.success("No critical threats identified in current window.")

live_dashboard()
