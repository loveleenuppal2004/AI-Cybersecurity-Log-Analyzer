import pandas as pd

from src.anomaly_detection import detect_anomalies
from src.risk_scoring import calculate_risk_scores


def load_logs():
    return pd.read_csv("data/security_logs.csv")


def test_suspicious_ip():
    df = load_logs()

    failed_logins = df[
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]

    failed_by_ip = failed_logins.groupby("ip_address").size()

    suspicious_ips = failed_by_ip[failed_by_ip >= 10]

    assert "192.168.1.250" in suspicious_ips.index


def test_attack_has_30_failed_logins():
    df = load_logs()

    suspicious_ip = df[
        (df["ip_address"] == "192.168.1.250") &
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]

    assert len(suspicious_ip) == 30


def test_isolation_forest_detects_attack():
    df = load_logs()
    results = detect_anomalies(df)

    attack = results[
        results["ip_address"] == "192.168.1.250"
    ]

    assert len(attack) == 1
    assert attack.iloc[0]["anomaly_prediction"] == -1
    assert attack.iloc[0]["classification"] == "Anomalous"


def test_attack_receives_critical_risk_score():
    df = load_logs()
    results = calculate_risk_scores(df)

    attack = results[
        results["ip_address"] == "192.168.1.250"
    ]

    assert len(attack) == 1
    assert attack.iloc[0]["risk_score"] == 90
    assert attack.iloc[0]["risk_level"] == "Critical"


def test_risk_scores_are_between_zero_and_100():
    df = load_logs()
    results = calculate_risk_scores(df)

    assert results["risk_score"].between(0, 100).all()