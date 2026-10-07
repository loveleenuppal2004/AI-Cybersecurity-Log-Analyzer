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

# Calculate total login attempts
ip_features["total_login_attempts"] = (
    ip_features["failed_logins"] +
    ip_features["successful_logins"]
)

# Calculate failure rate
ip_features["failure_rate"] = (
    ip_features["failed_logins"] /
    ip_features["total_login_attempts"]
)

# Create risk score
ip_features["risk_score"] = 0

# Rule 1: Many failed logins
ip_features.loc[
    ip_features["failed_logins"] >= 10,
    "risk_score"
] += 40

# Rule 2: Very high failure rate
ip_features.loc[
    ip_features["failure_rate"] >= 0.80,
    "risk_score"
] += 30

# Rule 3: Multiple users
ip_features.loc[
    ip_features["unique_users"] >= 3,
    "risk_score"
] += 10

# ML-style anomaly indicator
ip_features["ml_anomaly"] = (
    ip_features["failed_logins"] >= 10
)

ip_features.loc[
    ip_features["ml_anomaly"],
    "risk_score"
] += 20

# Make sure score never exceeds 100
ip_features["risk_score"] = (
    ip_features["risk_score"].clip(upper=100)
)

# Convert score into a risk level
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

print("=" * 60)
print("CYBERSECURITY RISK SCORING")
print("=" * 60)

print("\nRisk Analysis:\n")

print(
    ip_features[
        [
            "ip_address",
            "failed_logins",
            "failure_rate",
            "unique_users",
            "risk_score",
            "risk_level"
        ]
    ].to_string(index=False)
)

print("\n" + "=" * 60)
print("HIGH-RISK IP ADDRESSES")
print("=" * 60)

high_risk = ip_features[
    ip_features["risk_score"] >= 60
]

print(
    high_risk[
        [
            "ip_address",
            "risk_score",
            "risk_level"
        ]
    ].to_string(index=False)
)