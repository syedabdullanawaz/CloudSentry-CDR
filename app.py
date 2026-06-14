import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import boto3
from datetime import datetime
from database import fetch_incidents, remediate_incident, suppress_incident, get_setting, set_setting
from mock_generator import inject_mock_data
from engine import run_security_audit

# ----------------------------------------------------
# 1. PAGE CONFIGURATION & PREMIUM STYLING INJECTION
# ----------------------------------------------------
st.set_page_config(
    page_title="CloudSentry CDR — Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom premium CSS styling to override Streamlit defaults with a sleek DevSecOps dark theme
st.markdown("""
    <style>
    /* Dark glassmorphism card styling */
    .metric-card {
        background: rgba(17, 24, 39, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 24px;
        text-align: center;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.4);
        backdrop-filter: blur(5px);
        -webkit-backdrop-filter: blur(5px);
        margin-bottom: 16px;
        transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
    }
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 40px rgba(99, 102, 241, 0.2);
    }
    .metric-title {
        font-family: 'Inter', sans-serif;
        color: #9ca3af;
        font-size: 14px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-bottom: 8px;
    }
    .metric-value {
        font-family: 'Outfit', 'Google Sans', sans-serif;
        font-size: 38px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .value-critical {
        color: #ef4444;
        text-shadow: 0 0 12px rgba(239, 68, 68, 0.3);
    }
    .value-warning {
        color: #f59e0b;
        text-shadow: 0 0 12px rgba(245, 158, 11, 0.3);
    }
    .value-finops {
        color: #10b981;
        text-shadow: 0 0 12px rgba(16, 185, 129, 0.3);
    }
    .metric-sub {
        font-size: 12px;
        color: #6b7280;
    }
    
    /* Playbook header */
    .playbook-header {
        background: linear-gradient(90deg, #312e81 0%, #1e1b4b 100%);
        border-left: 5px solid #6366f1;
        border-radius: 4px;
        padding: 12px 20px;
        margin-bottom: 20px;
    }
    
    /* Center aligning metrics layout */
    .stMetric {
        background-color: transparent !important;
    }
    </style>
""", unsafe_allow_html=True)

# ----------------------------------------------------
# 2. STATE MANAGEMENT & BACKEND HELPERS
# ----------------------------------------------------
def get_db_connection():
    return sqlite3.connect("cloudsentry_siem.db")

# ----------------------------------------------------
# 3. SIDEBAR NAVIGATION & SYSTEM SETTINGS
# ----------------------------------------------------
st.sidebar.image("https://www.gstatic.com/lamda/images/gemini_sparkle_aurora_33f86dc0c0257da337c63.svg", width=50)
st.sidebar.title("🛡️ CloudSentry CDR")
st.sidebar.caption("Enterprise Cloud Detection & Response")
st.sidebar.markdown("---")

# Active Operations
st.sidebar.subheader("System Control Center")

if st.sidebar.button("🚀 Trigger Live Cloud Scan", use_container_width=True):
    with st.spinner("Executing Boto3 scanning modules across us-east-1 and us-west-2..."):
        try:
            run_security_audit()
            st.sidebar.success("✅ Audit completed! SIEM db updated.")
        except Exception as e:
            st.sidebar.error(f"Scan failed: {e}")

if st.sidebar.button("🧪 Seed Mock Threat Telemetry", use_container_width=True):
    inject_mock_data()
    st.sidebar.success("✅ Seeded mock threats database!")
    st.rerun()

st.sidebar.markdown("---")

# Settings Configuration
st.sidebar.subheader("Integrations Configuration")
webhook_db = get_setting("discord_webhook")
webhook_input = st.sidebar.text_input("Discord Webhook URL", value=webhook_db, type="password")
if webhook_input != webhook_db:
    set_setting("discord_webhook", webhook_input)
    st.sidebar.success("Webhook saved.")

remediation_mode_db = get_setting("remediation_mode") or "MANUAL"
remediation_mode = st.sidebar.selectbox("Response Policy", ["MANUAL", "AUTONOMOUS (Zero-Trust)"], index=0 if remediation_mode_db == "MANUAL" else 1)
if remediation_mode.split()[0] != remediation_mode_db:
    set_setting("remediation_mode", remediation_mode.split()[0])
    st.sidebar.success(f"Remediation policy updated to {remediation_mode.split()[0]}")

st.sidebar.markdown("---")
st.sidebar.caption("© 2026 CloudSentry. All rights reserved.")

# ----------------------------------------------------
# 4. MAIN DASHBOARD CONTENT
# ----------------------------------------------------
st.title("🛡️ CloudSentry CDR — Security Operations Center")
st.subheader("Autonomous Threat Hunting, FinOps Auditing, & Cloud Incident Response")
st.markdown("---")

# Load incidents data
incidents = fetch_incidents()
df = pd.DataFrame(incidents)

# Ensure df is populated and contains standard columns for display
if df.empty:
    # Set up empty DF structure to prevent code crashes
    df = pd.DataFrame(columns=[
        'id', 'timestamp', 'resource_type', 'resource_id', 'severity', 
        'description', 'status', 'compliance_rule', 'cost_leak', 
        'ip_address', 'country', 'playbook_history'
    ])

# ----------------------------------------------------
# 4.1 INTERACTIVE TOP METRICS (GLASSMORPHISM CARDS)
# ----------------------------------------------------
open_incidents = df[df['status'] == 'OPEN']
critical_count = len(open_incidents[open_incidents['severity'] == 'CRITICAL'])
warning_count = len(open_incidents[open_incidents['severity'].isin(['HIGH', 'MEDIUM'])])
monthly_leak = open_incidents['cost_leak'].sum()

m_col1, m_col2, m_col3 = st.columns(3)

with m_col1:
    st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Critical Compromises</div>
            <div class="metric-value value-critical">{critical_count}</div>
            <div class="metric-sub">Immediate response required</div>
        </div>
    """, unsafe_allow_html=True)

with m_col2:
    st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Active Threats / Compliance Alerts</div>
            <div class="metric-value value-warning">{warning_count + critical_count}</div>
            <div class="metric-sub">CIS Benchmark violations pending</div>
        </div>
    """, unsafe_allow_html=True)

with m_col3:
    st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Est. FinOps Budget Leak</div>
            <div class="metric-value value-finops">${monthly_leak:.2f} <span style="font-size: 16px; font-weight: normal; color: #6b7280;">/mo</span></div>
            <div class="metric-sub">Detached volumes & orphaned IPs</div>
        </div>
    """, unsafe_allow_html=True)

# ----------------------------------------------------
# 4.2 COMPONENT TABS
# ----------------------------------------------------
tab_dashboard, tab_map, tab_logs, tab_remediation = st.tabs([
    "📊 Threat Telemetry Analytics",
    "🌍 Interactive Geolocation Threat Map",
    "📝 SIEM Incident Stream",
    "⚡ SOC Containment & Remediation Playbooks"
])

# ----------------------------------------------------
# TAB 1: TELEMETRY & ANALYTICS CHARTS
# ----------------------------------------------------
with tab_dashboard:
    st.write("### Threat Intelligence & Cost Exposure Profile")
    
    if not open_incidents.empty:
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            # Chart A: Severity Distribution Pie Chart
            fig_sev = px.pie(
                open_incidents, 
                names='severity', 
                title='Active Incident Severity Distribution',
                color='severity',
                color_discrete_map={
                    'CRITICAL': '#ef4444',
                    'HIGH': '#f97316',
                    'MEDIUM': '#f59e0b',
                    'LOW': '#10b981'
                },
                hole=0.4
            )
            fig_sev.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color='#f3f4f6'
            )
            st.plotly_chart(fig_sev, use_container_width=True)
            
        with chart_col2:
            # Chart B: FinOps Cost Leakage Bar Chart
            finops_df = open_incidents[open_incidents['cost_leak'] > 0]
            if not finops_df.empty:
                cost_summary = finops_df.groupby('resource_type')['cost_leak'].sum().reset_index()
                fig_cost = px.bar(
                    cost_summary,
                    x='resource_type',
                    y='cost_leak',
                    title='Monthly Financial Exposure by Orphaned Resource Type',
                    color='resource_type',
                    color_discrete_sequence=px.colors.qualitative.Pastel,
                    labels={'cost_leak': 'Cost Leak ($ USD)', 'resource_type': 'Resource Type'}
                )
                fig_cost.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#f3f4f6',
                    showlegend=False
                )
                st.plotly_chart(fig_cost, use_container_width=True)
            else:
                st.info("No cost leakage detected. Great job! All cloud assets are correctly attached.")
                
        # CIS Compliance Metrics
        st.markdown("### CIS AWS Foundations Benchmark Compliance Matrix")
        comp_col1, comp_col2, comp_col3 = st.columns(3)
        
        # Calculate scores
        total_rules_audited = 4
        failed_rules = open_incidents['compliance_rule'].nunique()
        compliance_pct = max(0, int(((total_rules_audited - failed_rules) / total_rules_audited) * 100))
        
        with comp_col1:
            st.metric(label="CIS Compliance Score", value=f"{compliance_pct}%")
        with comp_col2:
            st.metric(label="Failed Compliance Frameworks", value=f"{failed_rules} Controls")
        with comp_col3:
            st.metric(label="MFA Compliance Deficit", value="Non-Compliant" if len(open_incidents[open_incidents['compliance_rule'].str.contains('MFA', na=False)]) > 0 else "Compliant")
            
    else:
        st.success("🎉 Outstanding! Your cloud environment is 100% compliant and fully optimized.")

# ----------------------------------------------------
# TAB 2: GEOLOCATION THREAT MAP
# ----------------------------------------------------
with tab_map:
    st.write("### Geolocated Attack Vectors (Brute-Force & Compromise Origins)")
    
    # Filter open incidents that contain geo coordinates
    geo_df = open_incidents[open_incidents['ip_address'].notna() & (open_incidents['ip_address'] != '')]
    
    # Ensure latitude and longitude columns are float
    geo_df = geo_df[geo_df['ip_address'].apply(lambda x: not (x.startswith("192.168.") or x.startswith("10.") or x == "127.0.0.1"))]
    
    # Let's verify we have latitude/longitude in the incidents
    # Fetch coordinates using sqlite connection directly
    conn = get_db_connection()
    geo_raw = pd.read_sql_query("""
        SELECT ip_address, country, severity, description, cost_leak 
        FROM incidents 
        WHERE status = 'OPEN' AND ip_address IS NOT NULL AND ip_address != ''
    """, conn)
    conn.close()
    
    # Since sqlite doesn't separate lat/lon if they are looked up dynamically, 
    # we can map them using threat_intel's enrich_ip for display:
    from threat_intel import enrich_ip
    
    geo_enriched = []
    for idx, row in geo_raw.iterrows():
        ip = row['ip_address']
        if ip.startswith("192.") or ip.startswith("10."):
            continue
        res = enrich_ip(ip)
        geo_enriched.append({
            "IP": ip,
            "Country": res['country'],
            "City": res['city'],
            "Latitude": res['latitude'],
            "Longitude": res['longitude'],
            "Severity": row['severity'],
            "Incident": row['description']
        })
        
    if geo_enriched:
        map_data = pd.DataFrame(geo_enriched)
        
        # Color mapping for map dots based on severity
        color_seq = map_data['Severity'].map({
            'CRITICAL': '#ef4444',
            'HIGH': '#f97316',
            'MEDIUM': '#f59e0b',
            'LOW': '#10b981'
        }).fillna('#6366f1')
        
        map_data['Color'] = color_seq
        
        # Plotly Scatter Mapbox (Beautiful & Premium)
        fig_map = px.scatter_mapbox(
            map_data,
            lat="Latitude",
            lon="Longitude",
            hover_name="IP",
            hover_data=["Country", "City", "Severity", "Incident"],
            color="Severity",
            color_discrete_map={
                'CRITICAL': '#ef4444',
                'HIGH': '#f97316',
                'MEDIUM': '#f59e0b',
                'LOW': '#10b981'
            },
            size_max=15,
            zoom=1,
            height=600,
            title="IP Attack Geolocation Map"
        )
        
        fig_map.update_layout(
            mapbox_style="carto-darkmatter",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#f3f4f6',
            margin={"r":0,"t":40,"l":0,"b":0}
        )
        
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("No external IP-based attacks logged. Your firewall is clean.")

# ----------------------------------------------------
# TAB 3: SIEM INCIDENT STREAM
# ----------------------------------------------------
with tab_logs:
    st.write("### SIEM Correlated Log Center")
    
    # Filter Options
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        status_filter = st.selectbox("Status Filter", ["ALL", "OPEN", "RESOLVED", "SUPPRESSED"])
    with col_f2:
        severity_filter = st.selectbox("Severity Filter", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col_f3:
        search_query = st.text_input("Search description/ID")
        
    # Apply filters to loaded DF
    filtered_df = df.copy()
    
    if not filtered_df.empty:
        if status_filter != "ALL":
            filtered_df = filtered_df[filtered_df['status'] == status_filter]
        if severity_filter != "ALL":
            filtered_df = filtered_df[filtered_df['severity'] == severity_filter]
        if search_query:
            filtered_df = filtered_df[
                filtered_df['description'].str.contains(search_query, case=False) |
                filtered_df['resource_id'].str.contains(search_query, case=False)
            ]
            
        # Display data
        st.dataframe(
            filtered_df[[
                'id', 'timestamp', 'resource_type', 'resource_id', 
                'severity', 'description', 'status', 'compliance_rule', 'cost_leak'
            ]], 
            use_container_width=True,
            column_config={
                "id": "Incident ID",
                "timestamp": "Timestamp",
                "resource_type": "Asset Type",
                "resource_id": "AWS Resource ID",
                "severity": "Severity",
                "description": "Details",
                "status": "State",
                "compliance_rule": "CIS Control",
                "cost_leak": st.column_config.NumberColumn(
                    "Monthly Leak ($)",
                    format="$%.2f"
                )
            }
        )
    else:
        st.info("No incidents logged in the database yet. Click 'Trigger Live Cloud Scan' in the sidebar.")

# ----------------------------------------------------
# TAB 4: SOC REMEDIATION PLAYBOOKS (ACTIVE RESPONSE)
# ----------------------------------------------------
with tab_remediation:
    st.markdown('<div class="playbook-header"><h3>⚡ SOC Incident Containment Center</h3><p>Trigger automated playbooks to eliminate active exposures and optimize cost leaks.</p></div>', unsafe_allow_html=True)
    
    open_incidents_only = df[df['status'] == 'OPEN']
    
    if not open_incidents_only.empty:
        # User selects incident to remediate
        options = [f"#{row['id']} - [{row['severity']}] {row['resource_type']}: {row['resource_id']}" for index, row in open_incidents_only.iterrows()]
        selected_option = st.selectbox("Select Active Threat Incident", options)
        
        selected_id = int(selected_option.split(' ')[0][1:])
        selected_row = open_incidents_only[open_incidents_only['id'] == selected_id].iloc[0]
        
        st.markdown("---")
        st.write(f"### Playbook Options for Incident #{selected_id}")
        st.info(f"**Description:** {selected_row['description']}\n\n**Framework Check:** {selected_row['compliance_rule'] or 'Manual Rule'}")
        
        # Display buttons depending on asset type
        res_type = selected_row['resource_type']
        res_id = selected_row['resource_id']
        
        col_act1, col_act2 = st.columns(2)
        
        with col_act1:
            if res_type == "IAM Access Key":
                st.write("#### 🛡️ Playbook: Contain IAM Exposure")
                st.write("Deactivates the access key in AWS IAM instantly, preventing any future API actions.")
                
                # Dry run flag for safety
                dry_run = st.checkbox("Dry Run (Simulate deactivation in DB only)", value=True)
                
                if st.button("🔴 Revoke IAM Access Key", use_container_width=True, type="primary"):
                    if dry_run:
                        action = "Simulated revocation of access key. DB status updated."
                        remediate_incident(selected_id, action)
                        st.success(f"✅ Dry Run: Access key {res_id} deactivated successfully.")
                        st.rerun()
                    else:
                        with st.spinner("Invoking boto3 IAM client..."):
                            try:
                                iam = boto3.client('iam')
                                # Fetch username from database description or parse username
                                # (In engine.py description is: "User {username} has a dormant key...")
                                username = "unknown"
                                if "User '" in selected_row['description']:
                                    username = selected_row['description'].split("User '")[1].split("'")[0]
                                    
                                if username != "unknown":
                                    iam.update_access_key(
                                        UserName=username,
                                        AccessKeyId=res_id,
                                        Status='Inactive'
                                    )
                                    action = f"Revoked Access Key {res_id} for user {username}."
                                    remediate_incident(selected_id, action)
                                    st.success(f"✅ IAM Access Key {res_id} successfully transitioned to INACTIVE.")
                                    st.rerun()
                                else:
                                    st.error("Could not parse username from description. Run in Dry Run mode.")
                            except Exception as e:
                                st.error(f"AWS Revocation Error: {e}. Ensure your local credentials have 'iam:UpdateAccessKey' policy permissions.")
                                
            elif res_type == "Elastic IP":
                st.write("#### 💸 Playbook: Release Unused IP")
                st.write("Releases the public IP back to AWS pool, immediately stopping hourly billing leaks.")
                dry_run = st.checkbox("Dry Run (Simulate release in DB only)", value=True)
                
                if st.button("🟢 Release Elastic IP Address", use_container_width=True):
                    if dry_run:
                        action = "Simulated release of Elastic IP. DB updated."
                        remediate_incident(selected_id, action)
                        st.success(f"✅ Dry Run: EIP {res_id} released successfully.")
                        st.rerun()
                    else:
                        with st.spinner("Invoking boto3 EC2 client..."):
                            try:
                                ec2 = boto3.client('ec2')
                                # Release requires allocation ID. For demo, we release by looking up allocation ID.
                                addrs = ec2.describe_addresses(PublicIps=[res_id]).get('Addresses', [])
                                if addrs:
                                    alloc_id = addrs[0].get('AllocationId')
                                    if alloc_id:
                                        ec2.release_address(AllocationId=alloc_id)
                                        action = f"Released Elastic IP {res_id}."
                                        remediate_incident(selected_id, action)
                                        st.success(f"✅ Elastic IP {res_id} released back to AWS pool.")
                                        st.rerun()
                                else:
                                    st.error("Allocation ID not found for this Elastic IP. IP may already be released.")
                            except Exception as e:
                                st.error(f"AWS EC2 Error: {e}. Check IAM policy permissions for 'ec2:ReleaseAddress'.")
                                
            elif res_type == "EBS Volume":
                st.write("#### 🛡️ Playbook: Quarantine Detached Storage")
                st.write("Takes a secure backup snapshot of the volume and deletes the idle disk to eliminate storage costs.")
                dry_run = st.checkbox("Dry Run (Simulate quarantine in DB only)", value=True)
                
                if st.button("🟡 Quarantine Volume & Release Storage", use_container_width=True):
                    if dry_run:
                        action = "Simulated volume backup & deletion. DB updated."
                        remediate_incident(selected_id, action)
                        st.success(f"✅ Dry Run: Volume {res_id} quarantined and deleted successfully.")
                        st.rerun()
                    else:
                        with st.spinner("Invoking boto3 EC2 client..."):
                            try:
                                ec2 = boto3.client('ec2')
                                # 1. Snapshot
                                snapshot = ec2.create_snapshot(
                                    VolumeId=res_id,
                                    Description=f"CloudSentry Quarantine backup for {res_id}"
                                )
                                # 2. Delete
                                ec2.delete_volume(VolumeId=res_id)
                                action = f"Quarantined EBS Volume {res_id}. Created snapshot {snapshot.get('SnapshotId')}."
                                remediate_incident(selected_id, action)
                                st.success(f"✅ EBS Volume {res_id} successfully deleted after creating snapshot {snapshot.get('SnapshotId')}.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"AWS EC2 Error: {e}. Check IAM policy permissions for 'ec2:CreateSnapshot' and 'ec2:DeleteVolume'.")
            else:
                st.write("#### 🛠️ Playbook: Manual Investigation")
                st.write("Log manual investigation notes or suppress this alert from showing up on the active dashboard.")
                
                investigation_notes = st.text_area("Investigation Notes", value="Investigated incident. Determined as safe / legacy config.")
                if st.button("Mark as Investigated & Resolved", use_container_width=True):
                    remediate_incident(selected_id, f"Resolved manually: {investigation_notes}")
                    st.success("Incident resolved.")
                    st.rerun()
                    
        with col_act2:
            st.write("#### 🔕 Playbook: Suppress Alert")
            st.write("If this alert is a known safe configuration or is approved by security compliance, suppress it. This hides the incident from metrics and dashboard views.")
            
            suppression_reason = st.text_input("Reason for Suppression", value="Approved legacy credentials/resources.")
            if st.button("Suppress Alert", use_container_width=True):
                suppress_incident(selected_id, reason=suppression_reason)
                st.success(f"Incident #{selected_id} successfully suppressed.")
                st.rerun()
                
    else:
        st.success("🎉 All clear! There are currently no active incidents pending remediation.")
