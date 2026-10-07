import pandas as pd

# Load the cybersecurity logs
df = pd.read_csv("data/security_logs.csv")

# Convert timestamp to datetime
df["timestamp"] = pd.to_datetime(df["timestamp"])

print("=" * 50)
print("CYBERSECURITY LOG ANALYZER")
print("=" * 50)

# 1. Total events
print("\nTotal security events:")
print(len(df))

# 2. Event types
print("\nEvent types:")
print(df["event_type"].value_counts())

# 3. Login status
print("\nLogin status:")
print(df[df["event_type"] == "login"]["status"].value_counts())

# 4. Failed login attempts
failed_logins = df[
    (df["event_type"] == "login") &
    (df["status"] == "failed")
]

print("\nTotal failed login attempts:")
print(len(failed_logins))

# 5. Failed logins by IP
failed_by_ip = (
    failed_logins
    .groupby("ip_address")
    .size()
    .sort_values(ascending=False)
)

print("\nFailed login attempts by IP:")
print(failed_by_ip)

# 6. Failed logins by username
failed_by_user = (
    failed_logins
    .groupby("username")
    .size()
    .sort_values(ascending=False)
)

print("\nFailed login attempts by username:")
print(failed_by_user)

# 7. Find suspicious IP addresses
suspicious_ips = failed_by_ip[
    failed_by_ip >= 10
]

print("\nPotentially suspicious IP addresses:")
print(suspicious_ips)

print("\nAnalysis complete!")