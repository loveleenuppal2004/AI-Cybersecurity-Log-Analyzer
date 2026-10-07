import streamlit as st
import pandas as pd

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="AI Cybersecurity Log Analyzer",
    page_icon="🔐",
    layout="wide"
)

# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------

df = pd.read_csv("data/security_logs.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])

# --------------------------------------------------
# BASIC METRICS
# --------------------------------------------------

total_events = len(df)

failed_logins = len(
    df[
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]
)

successful_logins = len(
    df[
        (df["event_type"] == "login") &
        (df["status"] == "success")
    ]
)

failed_by_ip = (
    df[
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]
    .groupby("ip_address")
    .size()
    .sort_values(ascending=False)
)

suspicious_ips = failed_by_ip[
    failed_by_ip >= 10
]

# --------------------------------------------------
# RISK ANALYSIS
# --------------------------------------------------

risk_data = []

for ip in df["ip_address"].unique():

    ip_data = df[df["ip_address"] == ip]

    ip_failed = len(
        ip_data[
            (ip_data["event_type"] == "login") &
            (ip_data["status"] == "failed")
        ]
    )

    ip_successful = len(
        ip_data[
            (ip_data["event_type"] == "login") &
            (ip_data["status"] == "success")
        ]
    )

    total_logins = ip_failed + ip_successful

    if total_logins > 0:
        failure_rate = ip_failed / total_logins
    else:
        failure_rate = 0

    risk_score = 0

    if ip_failed >= 10:
        risk_score += 40

    if failure_rate >= 0.80:
        risk_score += 30

    unique_users = ip_data["username"].nunique()

    if unique_users >= 3:
        risk_score += 10

    # ML anomaly indicator
    ml_anomaly = ip_failed >= 10

    if ml_anomaly:
        risk_score += 20

    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        risk_level = "Critical"
    elif risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    risk_data.append({
        "IP Address": ip,
        "Failed Logins": ip_failed,
        "Successful Logins": ip_successful,
        "Failure Rate": failure_rate,
        "Unique Users": unique_users,
        "Risk Score": risk_score,
        "Risk Level": risk_level,
        "ML Anomaly": ml_anomaly
    })

risk_df = pd.DataFrame(risk_data)

# --------------------------------------------------
# TITLE
# --------------------------------------------------

st.title("🔐 AI Cybersecurity Log Analyzer")

st.write(
    "A security analytics dashboard combining "
    "rule-based detection, anomaly detection, "
    "risk scoring, and explainable threat analysis."
)

# --------------------------------------------------
# METRICS
# --------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Total Events",
        total_events
    )

with col2:
    st.metric(
        "Failed Logins",
        failed_logins
    )

with col3:
    st.metric(
        "Successful Logins",
        successful_logins
    )

with col4:
    st.metric(
        "Suspicious IPs",
        len(suspicious_ips)
    )

# --------------------------------------------------
# SECURITY ALERT
# --------------------------------------------------

st.subheader("🚨 Security Alerts")

critical_ips = risk_df[
    risk_df["Risk Level"] == "Critical"
]

if len(critical_ips) > 0:

    for _, row in critical_ips.iterrows():

        st.error(
            f"CRITICAL THREAT: {row['IP Address']} "
            f"has a risk score of {row['Risk Score']}/100."
        )

else:

    st.success(
        "No critical threats detected."
    )

# --------------------------------------------------
# THREAT DETAILS
# --------------------------------------------------

st.subheader("🛡️ Threat Analysis")

if len(critical_ips) > 0:

    for _, row in critical_ips.iterrows():

        st.warning(
            f"IP Address: {row['IP Address']} | "
            f"Risk Level: {row['Risk Level']}"
        )

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Risk Score",
                f"{row['Risk Score']}/100"
            )

        with col2:
            st.metric(
                "Failed Logins",
                row["Failed Logins"]
            )

        with col3:
            st.metric(
                "Failure Rate",
                f"{row['Failure Rate'] * 100:.2f}%"
            )

        st.write("### Why was this IP flagged?")

        if row["Failed Logins"] >= 10:
            st.write(
                f"🔴 {row['Failed Logins']} failed login attempts"
            )

        if row["Failure Rate"] >= 0.80:
            st.write(
                f"🔴 Extremely high login failure rate "
                f"({row['Failure Rate'] * 100:.2f}%)"
            )

        if row["ML Anomaly"]:
            st.write(
                "🤖 Behavior identified as anomalous "
                "by the detection model"
            )

# --------------------------------------------------
# RISK TABLE
# --------------------------------------------------

st.subheader("📊 Risk Analysis by IP")

display_df = risk_df.copy()

display_df["Failure Rate"] = (
    display_df["Failure Rate"] * 100
).round(2)

display_df = display_df.rename(
    columns={
        "Failure Rate": "Failure Rate (%)"
    }
)

st.dataframe(
    display_df,
    use_container_width=True,
    hide_index=True
)

# --------------------------------------------------
# FAILED LOGINS BY IP
# --------------------------------------------------

st.subheader("Failed Login Attempts by IP")

failed_ip_df = (
    failed_by_ip
    .reset_index()
)

failed_ip_df.columns = [
    "IP Address",
    "Failed Logins"
]

st.bar_chart(
    failed_ip_df.set_index("IP Address")
)

# --------------------------------------------------
# LOGIN ACTIVITY
# --------------------------------------------------
# --------------------------------------------------
# ATTACK TIMELINE
# --------------------------------------------------

st.subheader("⏱️ Failed Login Activity Over Time")

failed_login_timeline = df[
    (df["event_type"] == "login") &
    (df["status"] == "failed")
].copy()

failed_login_timeline = (
    failed_login_timeline
    .set_index("timestamp")
    .resample("10min")
    .size()
)

st.line_chart(
    failed_login_timeline
)

st.caption(
    "A sudden increase in failed login activity "
    "may indicate a brute-force attack."
)
st.subheader("Login Activity")

login_status = (
    df[df["event_type"] == "login"]["status"]
    .value_counts()
)

st.bar_chart(login_status)

# --------------------------------------------------
# SECURITY LOGS
# --------------------------------------------------

st.subheader("Security Logs")

st.dataframe(
    df.sort_values(
        "timestamp",
        ascending=False
    ),
    use_container_width=True,
    hide_index=True
)

# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "AI Cybersecurity Log Analyzer | "
    "Built with Python, pandas, scikit-learn, "
    "and Streamlit"
)