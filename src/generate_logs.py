import pandas as pd
import random
from datetime import datetime, timedelta

# Make the results reproducible
random.seed(42)

# Sample users and IP addresses
users = [
    "alice",
    "bob",
    "charlie",
    "david",
    "emma"
]

normal_ips = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.13",
    "192.168.1.14"
]

suspicious_ip = "192.168.1.250"

event_types = [
    "login",
    "logout",
    "password_change"
]

statuses = [
    "success",
    "failed"
]

# Starting time for our logs
start_time = datetime(2026, 10, 1, 8, 0, 0)

logs = []

# -----------------------------------
# Generate normal activity
# -----------------------------------

for i in range(300):

    timestamp = start_time + timedelta(
        minutes=random.randint(0, 24 * 60)
    )

    user = random.choice(users)
    ip = random.choice(normal_ips)

    event_type = random.choice(event_types)

    if event_type == "login":
        status = random.choices(
            ["success", "failed"],
            weights=[90, 10]
        )[0]
    else:
        status = "success"

    logs.append({
        "timestamp": timestamp,
        "ip_address": ip,
        "username": user,
        "event_type": event_type,
        "status": status
    })


# -----------------------------------
# Generate suspicious brute-force activity
# -----------------------------------

attack_start = start_time + timedelta(hours=10)

for i in range(30):

    timestamp = attack_start + timedelta(
        seconds=i * 20
    )

    logs.append({
        "timestamp": timestamp,
        "ip_address": suspicious_ip,
        "username": "admin",
        "event_type": "login",
        "status": "failed"
    })


# -----------------------------------
# Successful login after attack
# -----------------------------------

logs.append({
    "timestamp": attack_start + timedelta(
        seconds=30 * 20
    ),
    "ip_address": suspicious_ip,
    "username": "admin",
    "event_type": "login",
    "status": "success"
})


# -----------------------------------
# Create DataFrame
# -----------------------------------

df = pd.DataFrame(logs)

# Sort by timestamp
df = df.sort_values("timestamp")

# Save dataset
df.to_csv(
    "data/security_logs.csv",
    index=False
)

print("Security log dataset created successfully!")
print()
print(f"Total events: {len(df)}")
print()
print(df.head(10))