import pandas as pd


def test_suspicious_ip():

    df = pd.read_csv("data/security_logs.csv")

    failed_logins = df[
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]

    failed_by_ip = (
        failed_logins
        .groupby("ip_address")
        .size()
    )

    suspicious_ips = failed_by_ip[
        failed_by_ip >= 10
    ]

    assert "192.168.1.250" in suspicious_ips.index


def test_attack_has_30_failed_logins():

    df = pd.read_csv("data/security_logs.csv")

    suspicious_ip = df[
        (df["ip_address"] == "192.168.1.250") &
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]

    assert len(suspicious_ip) == 30