import pandas as pd
import streamlit as st
from pathlib import Path

from src.risk_scoring import calculate_risk_scores


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="AI Cybersecurity Log Analyzer",
    page_icon="🔐",
    layout="wide"
)


# --------------------------------------------------
# LOAD SECURITY LOGS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = PROJECT_ROOT / "data" / "security_logs.csv"

st.title("🔐 AI Cybersecurity Log Analyzer")

st.write(
    "An intelligent security analytics dashboard combining "
    "rule-based detection, Isolation Forest anomaly detection, "
    "risk scoring, and explainable threat analysis."
)

if not DATA_PATH.exists():
    st.error("Security log dataset not found.")
    st.stop()

df = pd.read_csv(DATA_PATH)

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)

df = df.dropna(subset=["timestamp"])


# --------------------------------------------------
# CALCULATE ACTUAL ML PREDICTIONS AND RISK SCORES
# --------------------------------------------------

ip_features = calculate_risk_scores(df)


# --------------------------------------------------
# KEY SECURITY METRICS
# --------------------------------------------------

total_events = len(df)

failed_logins = df[
    (df["event_type"] == "login") &
    (df["status"] == "failed")
]

successful_logins = df[
    (df["event_type"] == "login") &
    (df["status"] == "success")
]

suspicious_ips = ip_features[
    ip_features["anomaly_prediction"] == -1
]

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Events",
    total_events
)

col2.metric(
    "Failed Logins",
    len(failed_logins)
)

col3.metric(
    "Successful Logins",
    len(successful_logins)
)

col4.metric(
    "ML-Detected Anomalies",
    len(suspicious_ips)
)


# --------------------------------------------------
# CRITICAL THREAT ALERT
# --------------------------------------------------

st.divider()

st.header("🚨 Security Alerts")

critical_ips = ip_features[
    ip_features["risk_level"] == "Critical"
]

if not critical_ips.empty:

    for _, row in critical_ips.iterrows():

        st.error(
            f"CRITICAL THREAT: {row['ip_address']} "
            f"has a risk score of {row['risk_score']}/100."
        )

else:
    st.success("No critical-risk IP addresses detected.")


# --------------------------------------------------
# THREAT ANALYSIS
# --------------------------------------------------

st.header("🔍 Threat Analysis")

if not suspicious_ips.empty:

    for _, row in suspicious_ips.iterrows():

        with st.expander(
            f"Investigate {row['ip_address']} — "
            f"{row['classification']}",
            expanded=True
        ):

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Risk Score",
                f"{row['risk_score']}/100"
            )

            col2.metric(
                "Failed Logins",
                int(row["failed_logins"])
            )

            col3.metric(
                "Failure Rate",
                f"{row['failure_rate']:.2%}"
            )

            st.write(
                f"**Risk Level:** {row['risk_level']}"
            )

            st.write(
                f"**ML Classification:** {row['classification']}"
            )

            st.write(
                f"**Isolation Forest Prediction:** "
                f"{row['anomaly_prediction']}"
            )

            st.write(
                f"**Anomaly Score:** "
                f"{row['anomaly_score']:.4f}"
            )

            st.subheader("Why was this IP flagged?")

            reasons = []

            if row["failed_logins"] >= 10:
                reasons.append(
                    f"{int(row['failed_logins'])} failed login attempts"
                )

            if row["failure_rate"] >= 0.80:
                reasons.append(
                    f"Extremely high login failure rate "
                    f"({row['failure_rate']:.2%})"
                )

            if row["unique_users"] >= 3:
                reasons.append(
                    f"Access attempts involving "
                    f"{int(row['unique_users'])} different users"
                )

            if row["anomaly_prediction"] == -1:
                reasons.append(
                    "Isolation Forest identified unusual IP behavior"
                )

            if reasons:
                for reason in reasons:
                    st.write(f"- {reason}")
            else:
                st.write(
                    "The model identified unusual behavior "
                    "that requires further investigation."
                )

else:
    st.info("The model did not identify any anomalous IP addresses.")


# --------------------------------------------------
# RISK ANALYSIS TABLE
# --------------------------------------------------

st.divider()

st.header("📊 Risk Analysis by IP")

display_columns = [
    "ip_address",
    "failed_logins",
    "successful_logins",
    "failure_rate",
    "anomaly_score",
    "classification",
    "risk_score",
    "risk_level"
]

risk_table = ip_features[display_columns].copy()

risk_table["failure_rate"] = (
    risk_table["failure_rate"].map(
        lambda value: f"{value:.2%}"
    )
)

st.dataframe(
    risk_table.sort_values(
        "risk_score",
        ascending=False
    ),
    use_container_width=True,
    hide_index=True
)


# --------------------------------------------------
# FAILED LOGIN CHART
# --------------------------------------------------

st.divider()

st.header("📈 Failed Login Attempts by IP")

failed_by_ip = (
    failed_logins.groupby("ip_address")
    .size()
    .sort_values(ascending=False)
)

st.bar_chart(failed_by_ip)


# --------------------------------------------------
# LOGIN ACTIVITY CHART
# --------------------------------------------------

st.header("📊 Login Activity")

login_activity = (
    df[df["event_type"] == "login"]
    .groupby(["ip_address", "status"])
    .size()
    .unstack(fill_value=0)
)

st.bar_chart(login_activity)


# --------------------------------------------------
# ATTACK TIMELINE
# --------------------------------------------------

st.divider()

st.header("⏱️ Failed Login Activity Over Time")

failed_login_timeline = failed_logins.copy()

if not failed_login_timeline.empty:

    timeline = (
        failed_login_timeline
        .set_index("timestamp")
        .resample("10min")
        .size()
    )

    st.line_chart(timeline)

    st.caption(
        "A sudden increase in failed login activity "
        "may indicate a brute-force attack."
    )

else:
    st.info("No failed login activity was found.")


# --------------------------------------------------
# SECURITY LOGS
# --------------------------------------------------

st.divider()

st.header("📋 Security Logs")

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
    "Educational cybersecurity analytics project. "
    "Anomaly predictions indicate unusual behavior, "
    "not confirmed malicious activity."
)