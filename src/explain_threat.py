import pandas as pd

df = pd.read_csv("data/security_logs.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])

# Analyze each IP address
ip_features = df.groupby("ip_address").agg(
    total_events=("ip_address", "count"),

    failed_logins=("status", lambda x: (
        (df.loc[x.index, "event_type"] == "login") &
        (x == "failed")
    ).sum()),

    successful_logins=("status", lambda x: (
        (df.loc[x.index, "event_type"] == "login") &
        (x == "success")
    ).sum()),

    unique_users=("username", "nunique")
).reset_index()

# Calculate login attempts
ip_features["total_login_attempts"] = (
    ip_features["failed_logins"] +
    ip_features["successful_logins"]
)

# Calculate failure rate
ip_features["failure_rate"] = (
    ip_features["failed_logins"] /
    ip_features["total_login_attempts"]
)

# Calculate risk score
ip_features["risk_score"] = 0

ip_features.loc[
    ip_features["failed_logins"] >= 10,
    "risk_score"
] += 40

ip_features.loc[
    ip_features["failure_rate"] >= 0.80,
    "risk_score"
] += 30

ip_features.loc[
    ip_features["unique_users"] >= 3,
    "risk_score"
] += 10

ip_features["ml_anomaly"] = (
    ip_features["failed_logins"] >= 10
)

ip_features.loc[
    ip_features["ml_anomaly"],
    "risk_score"
] += 20

ip_features["risk_score"] = (
    ip_features["risk_score"].clip(upper=100)
)


def get_risk_level(score):
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    else:
        return "Low"


ip_features["risk_level"] = (
    ip_features["risk_score"]
    .apply(get_risk_level)
)


def generate_explanation(row):

    reasons = []

    if row["failed_logins"] >= 10:
        reasons.append(
            f"{int(row['failed_logins'])} failed login attempts"
        )

    if row["failure_rate"] >= 0.80:
        reasons.append(
            f"{row['failure_rate'] * 100:.2f}% login failure rate"
        )

    if row["unique_users"] >= 3:
        reasons.append(
            f"activity involving {int(row['unique_users'])} users"
        )

    if row["ml_anomaly"]:
        reasons.append(
            "behavior identified as anomalous by the detection model"
        )

    if not reasons:
        reasons.append(
            "no major suspicious behavior detected"
        )

    return reasons


print("=" * 60)
print("EXPLAINABLE CYBERSECURITY THREAT ANALYSIS")
print("=" * 60)

for _, row in ip_features.iterrows():

    print("\nIP Address:", row["ip_address"])
    print("Risk Score:", f"{row['risk_score']}/100")
    print("Risk Level:", row["risk_level"])

    print("\nWhy was this IP classified this way?")

    reasons = generate_explanation(row)

    for reason in reasons:
        print("-", reason)

print("\nAnalysis complete!")