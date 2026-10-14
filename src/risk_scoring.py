import pandas as pd
from src.anomaly_detection import detect_anomalies


def calculate_risk_scores(df):
    """
    Calculate IP risk scores using security rules
    and actual Isolation Forest predictions.
    """

    ip_features = detect_anomalies(df)

    ip_features["risk_score"] = 0

    # Rule 1: Many failed login attempts.
    ip_features.loc[
        ip_features["failed_logins"] >= 10,
        "risk_score"
    ] += 40

    # Rule 2: Very high login failure rate.
    ip_features.loc[
        ip_features["failure_rate"] >= 0.80,
        "risk_score"
    ] += 30

    # Rule 3: An IP accessed multiple user accounts.
    ip_features.loc[
        ip_features["unique_users"] >= 3,
        "risk_score"
    ] += 10

    # Rule 4: Use the actual Isolation Forest prediction.
    ip_features.loc[
        ip_features["anomaly_prediction"] == -1,
        "risk_score"
    ] += 20

    # Keep the score within 0–100.
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
        ip_features["risk_score"].apply(get_risk_level)
    )

    return ip_features


if __name__ == "__main__":

    df = pd.read_csv("data/security_logs.csv")

    results = calculate_risk_scores(df)

    print("=" * 60)
    print("CYBERSECURITY RISK SCORING")
    print("=" * 60)

    print(
        results[
            [
                "ip_address",
                "failed_logins",
                "failure_rate",
                "anomaly_prediction",
                "classification",
                "risk_score",
                "risk_level"
            ]
        ].to_string(index=False)
    )

    print("\nHIGH-RISK IP ADDRESSES")

    high_risk = results[
        results["risk_score"] >= 60
    ]

    print(
        high_risk[
            ["ip_address", "risk_score", "risk_level"]
        ].to_string(index=False)
    )
