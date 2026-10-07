import pandas as pd
from sklearn.ensemble import IsolationForest

df = pd.read_csv("data/security_logs.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"])

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

ip_features["total_login_attempts"] = (
    ip_features["failed_logins"] +
    ip_features["successful_logins"]
)

ip_features["failure_rate"] = (
    ip_features["failed_logins"] /
    ip_features["total_login_attempts"]
)

features = [
    "total_events",
    "failed_logins",
    "successful_logins",
    "unique_users",
    "failure_rate"
]

X = ip_features[features]

model = IsolationForest(
    contamination=0.10,
    random_state=42
)

model.fit(X)

ip_features["anomaly_prediction"] = model.predict(X)

ip_features["anomaly_score"] = model.decision_function(X)

ip_features["classification"] = ip_features[
    "anomaly_prediction"
].map({
    1: "Normal",
    -1: "Anomalous"
})

print("=" * 60)
print("AI CYBERSECURITY ANOMALY DETECTION")
print("=" * 60)

print("\nIP Behavior Analysis:\n")

print(
    ip_features[
        [
            "ip_address",
            "total_events",
            "failed_logins",
            "successful_logins",
            "failure_rate",
            "anomaly_score",
            "classification"
        ]
    ].to_string(index=False)
)

anomalies = ip_features[
    ip_features["classification"] == "Anomalous"
]

print("\n" + "=" * 60)
print("DETECTED ANOMALIES")
print("=" * 60)

print(anomalies.to_string(index=False))