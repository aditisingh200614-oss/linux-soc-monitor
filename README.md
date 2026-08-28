# Linux SOC Security Monitor

A Python-based Linux security monitoring tool that detects suspicious authentication activity, processes, and network connections.

The project demonstrates basic Security Operations Center (SOC) concepts such as log monitoring, behavioral detection, baseline comparison, risk scoring, alert generation, and duplicate alert prevention.

---

## Why I Built This

This project was built as a hands-on cybersecurity project to understand how a basic SOC monitoring system works.

The goal was to learn how security events can be collected from a Linux system, analyzed for suspicious behavior, assigned a risk score, and converted into actionable alerts.

---

## Features

### 1. Authentication Monitoring

Monitors Linux authentication logs for failed authentication attempts.

The authentication monitor:

- Detects failed authentication attempts
- Tracks repeated failures within a time window
- Identifies possible brute-force activity
- Generates authentication alerts
- Stores alerts in `alerts.log`

---

### 2. Process Monitoring

Monitors currently running Linux processes and compares them against a known process baseline.

The detector checks:

- New processes
- Executable paths
- Command-line arguments
- Processes running as root
- High CPU usage
- Suspicious paths such as `/tmp` and `/dev/shm`

Each indicator contributes to a risk score.

When the risk score reaches the configured threshold, a process alert is generated.

---

### 3. Network Monitoring

Monitors active network connections using `psutil`.

The network detector checks:

- Established network connections
- Remote IP addresses
- Remote ports
- Processes associated with connections
- Selected suspicious remote ports

Suspicious connections generate network alerts.

---

### 4. Risk Scoring

Instead of treating every unusual event as an attack, the project uses multiple indicators to calculate a risk score.

Current process detection scoring:

| Indicator | Score |
|---|---:|
| New process | +1 |
| Executable from `/tmp` | +3 |
| Executable from `/dev/shm` | +3 |
| Suspicious command line | +3 |
| Running as root | +1 |
| High CPU usage | +1 |

An alert is generated when the configured risk threshold is reached.

This approach helps reduce unnecessary alerts by requiring suspicious behavior to reach a defined risk level.

---

### 5. Duplicate Alert Prevention

The process monitor keeps track of processes that have already generated alerts.

This prevents the same suspicious process from generating repeated alerts during every monitoring scan.

If the suspicious process disappears and later starts again with a new process ID, it can generate a new alert.

---

## Architecture

```text
                         Linux System
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
       Authentication      Processes        Network
            Logs            Monitor         Monitor
              |               |               |
              +---------------+---------------+
                              |
                              v
                        Detection Logic
                              |
                              v
                         Risk Scoring
                              |
                              v
                       Alert Threshold
                              |
                       +------+------+
                       |             |
                      No            Yes
                       |             |
                       v             v
                    Ignore       🚨 Alert
                                     |
                                     v
                                alerts.log
Detection Logic
Authentication Detection
Authentication Logs
        |
        v
Failed Attempts
        |
        v
Time-based Analysis
        |
        v
Repeated Failures
        |
        v
Possible Brute Force
        |
        v
      Alert

Process Detection
Running Processes
        |
        v
Compare with Baseline
        |
        v
Analyze Process Behavior
        |
        +----------------------+
        |          |           |
        v          v           v
    Executable  Command      User
      Path       Line
        |          |           |
        +----------+-----------+
                   |
                   v
              Risk Score
                   |
                   v
            Threshold Reached?
              /          \
            No            Yes
            |              |
          Ignore        🚨 Alert

Network Detection
Active Connections
        |
        v
Established Connections
        |
        v
Remote IP + Port + Process
        |
        v
Suspicious Indicators
        |
        v
Risk Score
        |
        v
      Alert

Project Structure
linux-soc-monitor/
│
├── monitor.py
├── process_detector.py
├── network_monitor.py
├── soc_monitor.py
├── process_baseline.json
├── .gitignore
└── README.md

File Description
File	                      Purpose
monitor.py	        Authentication and brute-force monitoring
process_detector.py	Process behavior monitoring and risk scoring
network_monitor.py	Network connection monitoring
soc_monitor.py	        Central script that runs the monitoring modules
process_baseline.json	Stores the known process baseline
.gitignore	        Prevents runtime/generated files from being committed
README.md	        Project documentation

Technologies Used
Python 3
Linux / WSL
psutil
JSON
Git
GitHub

How to Run

Make sure you are inside the project directory:

cd linux-soc-monitor
Run the complete SOC monitor
python3 soc_monitor.py
Run individual monitors

Authentication monitoring:

python3 monitor.py

Process monitoring:

python3 process_detector.py

Network monitoring:

python3 network_monitor.py
Viewing Alerts

Security alerts are stored locally in:

alerts.log

View the alerts using:

cat alerts.log

You can also monitor the file continuously using:

tail -f alerts.log

Press:

Ctrl + C

to stop tail.

Example Process Alert

The following is an example of an alert generated during testing:

🚨 PROCESS ALERT

Process: python3
PID: 594
User: aditi
Command: python3 /tmp/test_process.py
Risk Score: 3

Reasons:
- Command line references suspicious path: /tmp

This demonstrates how the monitor can identify suspicious behavior even when the executable itself is a normal program.

Example Detection Scenario

A test process was created inside /tmp:

echo 'import time; time.sleep(300)' > /tmp/test_process.py

The process was then started:

python3 /tmp/test_process.py &

The process detector identified the suspicious /tmp reference in the command line and generated a process alert.

This demonstrates the difference between looking only at the executable and analyzing the complete command line.

Security Approach

The project follows a basic SOC detection workflow:

Collect
   |
   v
Analyze
   |
   v
Compare with Baseline
   |
   v
Calculate Risk
   |
   v
Apply Threshold
   |
   v
Generate Alert
   |
   v
Log Event

The goal is not to classify every unusual event as malicious.

Instead, multiple indicators are combined to determine whether an event is suspicious enough to generate an alert.

Limitations

This is an educational SOC monitoring project and is not intended to replace a production SIEM or Endpoint Detection and Response (EDR) platform.

Current limitations include:

Basic detection rules
Limited behavioral analysis
Network monitoring currently focuses on selected suspicious ports
Alerts are stored locally
No centralized SIEM integration
No web-based SOC dashboard
Limited historical analysis
No advanced threat intelligence integration
Future Improvements

Possible future improvements include:

Real-time authentication log monitoring
More advanced process behavior detection
More advanced network behavior analysis
IP reputation checking
File integrity monitoring
Malware and suspicious file analysis
Alert severity classification
Email or messaging notifications
Web-based SOC dashboard
SIEM integration
Improved behavioral baselines
Historical security event analysis
