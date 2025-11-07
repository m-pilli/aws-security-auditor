"""Streamlit dashboard for AWS Security Auditor."""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db import db


# Page configuration
st.set_page_config(
    page_title="AWS Security Auditor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .big-font {
        font-size: 24px !important;
        font-weight: bold;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
    }
    .critical { color: #d32f2f; }
    .high { color: #f57c00; }
    .medium { color: #fbc02d; }
    .low { color: #1976d2; }
    </style>
""", unsafe_allow_html=True)


def load_data():
    """Load data from database."""
    stats = db.get_statistics()
    findings = db.get_findings(resolved=False)
    latest_scan = db.get_latest_scan()
    
    return stats, findings, latest_scan


def render_overview(stats, latest_scan):
    """Render overview section."""
    st.header("🔍 Security Overview")
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Findings",
            value=stats['total_findings'],
            delta=f"{stats['recent_findings']} this week"
        )
    
    with col2:
        critical_count = stats['severity_counts'].get('critical', 0)
        st.metric(
            label="🔴 Critical",
            value=critical_count,
            delta=None if critical_count == 0 else "Action Required",
            delta_color="inverse"
        )
    
    with col3:
        high_count = stats['severity_counts'].get('high', 0)
        st.metric(
            label="🟠 High",
            value=high_count
        )
    
    with col4:
        st.metric(
            label="Total Scans",
            value=stats['total_scans']
        )
    
    # Latest scan info
    if latest_scan:
        st.info(f"📅 Last scan: {latest_scan['start_time']} ({latest_scan['scan_type'].upper()})")


def render_severity_chart(stats):
    """Render severity distribution chart."""
    st.subheader("📊 Severity Distribution")
    
    severity_data = stats['severity_counts']
    
    if severity_data:
        df = pd.DataFrame({
            'Severity': list(severity_data.keys()),
            'Count': list(severity_data.values())
        })
        
        # Define colors
        color_map = {
            'critical': '#d32f2f',
            'high': '#f57c00',
            'medium': '#fbc02d',
            'low': '#1976d2'
        }
        
        fig = px.bar(
            df,
            x='Severity',
            y='Count',
            color='Severity',
            color_discrete_map=color_map,
            title="Findings by Severity"
        )
        
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("✅ No security issues found!")


def render_service_chart(stats):
    """Render service distribution chart."""
    st.subheader("🔧 Findings by Service")
    
    service_data = stats['service_counts']
    
    if service_data:
        df = pd.DataFrame({
            'Service': list(service_data.keys()),
            'Count': list(service_data.values())
        })
        
        fig = px.pie(
            df,
            values='Count',
            names='Service',
            title="Distribution by AWS Service"
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("✅ No security issues found!")


def render_findings_table(findings):
    """Render findings table."""
    st.subheader("🔎 Security Findings")
    
    if not findings:
        st.success("✅ No open security findings!")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(findings)
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        service_filter = st.multiselect(
            "Filter by Service",
            options=df['service'].unique(),
            default=df['service'].unique()
        )
    
    with col2:
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=df['severity'].unique(),
            default=df['severity'].unique()
        )
    
    with col3:
        min_risk = st.slider(
            "Minimum Risk Score",
            min_value=0,
            max_value=10,
            value=0
        )
    
    # Apply filters
    filtered_df = df[
        (df['service'].isin(service_filter)) &
        (df['severity'].isin(severity_filter)) &
        (df['risk_score'] >= min_risk)
    ]
    
    # Display count
    st.write(f"Showing {len(filtered_df)} of {len(df)} findings")
    
    # Display table
    display_df = filtered_df[[
        'severity', 'service', 'finding_type', 
        'resource_name', 'risk_score', 'description'
    ]].copy()
    
    display_df.columns = [
        'Severity', 'Service', 'Finding Type',
        'Resource', 'Risk Score', 'Description'
    ]
    
    # Sort by risk score
    display_df = display_df.sort_values('Risk Score', ascending=False)
    
    st.dataframe(
        display_df,
        use_container_width=True,
        height=400
    )
    
    # Detailed view
    if st.checkbox("Show detailed findings"):
        for idx, finding in filtered_df.iterrows():
            with st.expander(
                f"[{finding['severity'].upper()}] {finding['finding_type']} - {finding['resource_name']}"
            ):
                st.write(f"**Service:** {finding['service']}")
                st.write(f"**Resource ID:** {finding['resource_id']}")
                st.write(f"**Risk Score:** {finding['risk_score']}/10")
                st.write(f"**Description:** {finding['description']}")
                if finding.get('recommendation'):
                    st.write(f"**Recommendation:** {finding['recommendation']}")
                
                # Resolve button
                if st.button(f"Mark as Resolved", key=f"resolve_{finding['id']}"):
                    db.resolve_finding(finding['id'])
                    st.success("Finding marked as resolved!")
                    st.rerun()


def render_trends():
    """Render trends section."""
    st.subheader("📈 Trends")
    
    # Get scan history
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            DATE(start_time) as date,
            COUNT(*) as scan_count,
            SUM(findings_count) as total_findings,
            SUM(critical_count) as critical,
            SUM(high_count) as high
        FROM scans
        WHERE start_time >= datetime('now', '-30 days')
        GROUP BY DATE(start_time)
        ORDER BY date
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    if rows:
        df = pd.DataFrame(rows, columns=['Date', 'Scans', 'Findings', 'Critical', 'High'])
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=df['Date'],
            y=df['Critical'],
            mode='lines+markers',
            name='Critical',
            line=dict(color='#d32f2f', width=2)
        ))
        
        fig.add_trace(go.Scatter(
            x=df['Date'],
            y=df['High'],
            mode='lines+markers',
            name='High',
            line=dict(color='#f57c00', width=2)
        ))
        
        fig.update_layout(
            title="Critical and High Severity Findings Over Time",
            xaxis_title="Date",
            yaxis_title="Count",
            hovermode='x unified'
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No historical data available yet. Run more scans to see trends.")


def render_recommendations():
    """Render top recommendations."""
    st.subheader("💡 Top Recommendations")
    
    findings = db.get_findings(resolved=False)
    
    # Get critical and high findings
    priority_findings = [
        f for f in findings 
        if f['severity'] in ['critical', 'high'] and f.get('recommendation')
    ]
    
    # Sort by risk score
    priority_findings.sort(key=lambda x: x['risk_score'], reverse=True)
    
    if priority_findings:
        for i, finding in enumerate(priority_findings[:5], 1):
            severity_icon = '🔴' if finding['severity'] == 'critical' else '🟠'
            
            st.markdown(f"""
            **{i}. {severity_icon} {finding['finding_type']}**
            - Resource: `{finding['resource_name']}`
            - Issue: {finding['description']}
            - **Action:** {finding['recommendation']}
            """)
    else:
        st.success("✅ No critical recommendations at this time!")


def main():
    """Main dashboard function."""
    # Sidebar
    st.sidebar.title("🔒 AWS Security Auditor")
    st.sidebar.markdown("---")
    
    page = st.sidebar.radio(
        "Navigation",
        ["Overview", "Findings", "Trends", "Recommendations"]
    )
    
    st.sidebar.markdown("---")
    
    # Refresh button
    if st.sidebar.button("🔄 Refresh Data"):
        st.rerun()
    
    st.sidebar.markdown("---")
    st.sidebar.info("""
    **Quick Actions:**
    - Run scan: `python main.py --scan all`
    - View report: `python main.py --report`
    - API docs: http://localhost:8000/docs
    """)
    
    # Load data
    try:
        stats, findings, latest_scan = load_data()
    except Exception as e:
        st.error(f"Error loading data: {e}")
        st.info("Make sure the database is initialized. Run a scan first: `python main.py --scan all`")
        return
    
    # Title
    st.title("🔒 AWS Security Audit Dashboard")
    st.markdown("Monitor and manage AWS security findings")
    st.markdown("---")
    
    # Render selected page
    if page == "Overview":
        render_overview(stats, latest_scan)
        
        col1, col2 = st.columns(2)
        
        with col1:
            render_severity_chart(stats)
        
        with col2:
            render_service_chart(stats)
    
    elif page == "Findings":
        render_findings_table(findings)
    
    elif page == "Trends":
        render_trends()
    
    elif page == "Recommendations":
        render_recommendations()
    
    # Footer
    st.markdown("---")
    st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()

