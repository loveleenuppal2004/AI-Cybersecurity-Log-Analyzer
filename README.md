# 🔐 AI Cybersecurity Log Analyzer

A cybersecurity log analysis application that combines **rule-based threat detection, machine learning anomaly detection, risk scoring, and explainable security analysis**.

The project analyzes security logs and identifies suspicious behavior such as repeated failed login attempts and potential brute-force attacks.

---

## 🚀 Project Overview

Cybersecurity teams need to analyze large amounts of authentication and system activity logs to identify suspicious behavior.

This project demonstrates how Python and machine learning can be used to:

* Analyze cybersecurity logs
* Detect suspicious login activity
* Identify anomalous IP addresses
* Calculate security risk scores
* Explain why an IP address was flagged
* Visualize security activity through an interactive dashboard
* Automatically test threat detection logic

The project uses a **synthetic cybersecurity dataset** created for educational and demonstration purposes.

---

## 🧠 Key Features

### 1. Security Log Analysis

The system analyzes:

* IP addresses
* Usernames
* Event types
* Login status
* Timestamps

The current dataset contains **331 security events**.

---

### 2. Rule-Based Threat Detection

The system identifies IP addresses with excessive failed login attempts.

For example:

```text
IP Address: 192.168.1.250
Failed Login Attempts: 30
```

An IP address with at least 10 failed login attempts is considered suspicious by the rule-based detection system.

---

### 3. Machine Learning Anomaly Detection

The project uses the **Isolation Forest** algorithm from scikit-learn.

The model analyzes IP behavior using features such as:

* Total events
* Failed logins
* Successful logins
* Unique users
* Login failure rate

The simulated attack IP was successfully classified as **Anomalous**.

---

### 4. Risk Scoring

Each IP address receives a risk score from **0–100**.

| Score  | Risk Level |
| ------ | ---------- |
| 0–29   | Low        |
| 30–59  | Medium     |
| 60–79  | High       |
| 80–100 | Critical   |

The simulated suspicious IP received:

```text
Risk Score: 90/100
Risk Level: Critical
```

---

### 5. Explainable Threat Detection

The system explains why an IP address was flagged.

Example:

```text
192.168.1.250

30 failed login attempts
96.77% login failure rate
Behavior identified as anomalous by the detection model
```

This makes the security analysis easier to understand.

---

### 6. Interactive Streamlit Dashboard

The project includes a web dashboard displaying:

* Total security events
* Failed logins
* Successful logins
* Suspicious IPs
* Critical security alerts
* Risk scores
* Threat explanations
* Failed login charts
* Attack timeline
* Security logs

---

### 7. Automated Testing

The project includes automated tests using **pytest**.

The tests verify that:

* The suspicious IP is correctly detected.
* The simulated attack contains the expected number of failed login attempts.

Current test result:

```text
2 passed
```

---

## 🏗️ Project Architecture

```text
Security Logs
      │
      ▼
Data Generation
      │
      ▼
Log Analysis
      │
      ├───────────────┐
      ▼               ▼
Rule-Based       ML Anomaly
Detection        Detection
      │               │
      └───────┬───────┘
              ▼
        Risk Scoring
              │
              ▼
     Threat Explanation
              │
              ▼
    Streamlit Dashboard
```

---

## 📁 Project Structure

```text
AI-Cybersecurity-Log-Analyzer/
│
├── app/
│   └── dashboard.py
│
├── data/
│   └── security_logs.csv
│
├── models/
│
├── src/
│   ├── generate_logs.py
│   ├── analyze_logs.py
│   ├── anomaly_detection.py
│   ├── risk_scoring.py
│   └── explain_threat.py
│
├── tests/
│   └── test_detection.py
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## 🛠️ Technologies Used

* **Python**
* **pandas**
* **NumPy**
* **scikit-learn**
* **Isolation Forest**
* **Streamlit**
* **pytest**
* **Git**
* **GitHub Codespaces**

---

## ▶️ How to Run

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/AI-Cybersecurity-Log-Analyzer.git
```

### 2. Navigate into the project

```bash
cd AI-Cybersecurity-Log-Analyzer
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the environment

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows:

```bash
.venv\Scripts\activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Generate the security logs

```bash
python src/generate_logs.py
```

### 7. Run log analysis

```bash
python src/analyze_logs.py
```

### 8. Run anomaly detection

```bash
python src/anomaly_detection.py
```

### 9. Run risk scoring

```bash
python src/risk_scoring.py
```

### 10. Run the Streamlit dashboard

```bash
python -m streamlit run app/dashboard.py
```

---

## 🧪 Running Tests

Run:

```bash
pytest
```

Expected result:

```text
2 passed
```

---

## 🔎 Example Detection

The system successfully detected the simulated suspicious IP:

```text
IP Address: 192.168.1.250

Failed Logins: 30
Failure Rate: 96.77%
Risk Score: 90/100
Risk Level: Critical
ML Classification: Anomalous
```

This activity represents a simulated brute-force login attack.

---

## ⚠️ Disclaimer

This project uses synthetic cybersecurity data for educational and portfolio purposes.

It is a demonstration of security analytics concepts and should not be treated as a production security monitoring system.

---

## 🔮 Future Improvements

Potential future improvements include:

* Real-time log ingestion
* Support for Windows and Apache logs
* More advanced anomaly detection
* Time-window-based behavioral analysis
* Automated security recommendations
* Email and dashboard alerts
* Database integration
* REST API integration
* Cloud deployment
* More comprehensive cybersecurity datasets

---

## 💻 Skills Demonstrated

This project demonstrates experience with:

* Python programming
* Data analysis
* Machine learning
* Anomaly detection
* Cybersecurity analytics
* Feature engineering
* Risk scoring
* Explainable AI
* Data visualization
* Streamlit application development
* Automated testing
* Git and GitHub
