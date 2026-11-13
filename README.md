
# Network Intrusion Detection & Real-Time Traffic Monitoring System (NID-TMS)

A Python-based cybersecurity project that monitors network traffic, detects suspicious network behaviour, generates security alerts, and displays network activity through a real-time web dashboard.

## Project Overview

The Network Intrusion Detection & Real-Time Traffic Monitoring System (NID-TMS) is designed to help identify potentially suspicious network activity through packet monitoring and rule-based intrusion detection.

The system captures network packets, analyzes traffic patterns, detects suspicious behaviour, stores alerts and traffic records in an SQLite database, and presents security information through a web dashboard.

It also generates text and PDF security reports.

## Objectives

- Capture and monitor network traffic.
- Analyze TCP, UDP, ICMP, IPv4 and IPv6 packets.
- Detect suspicious activities such as port scans and abnormal SYN traffic.
- Monitor unusual IP behaviour.
- Generate security alerts with severity levels and risk scores.
- Store network traffic and alerts in an SQLite database.
- Display monitoring results through a web dashboard.
- Generate downloadable text and PDF security reports.
- Test important detection and reporting functionality using automated tests.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Scapy | Network packet capture and analysis |
| FastAPI | Backend API |
| Uvicorn | ASGI server |
| SQLite | Database |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Dashboard functionality |
| ReportLab | PDF report generation |
| pypdf | PDF content verification in tests |
| pytest | Automated testing |
| Git & GitHub | Version control |

## Features

### 1. Network Packet Capture
- Captures network packets using Scapy.
- Extracts source and destination IP addresses.
- Identifies network protocols.
- Records source and destination ports when available.
- Records packet sizes and timestamps.

### 2. Intrusion Detection
- Port scan detection.
- Suspicious SYN traffic detection.
- ICMP traffic monitoring.
- IP behaviour monitoring.
- Detection of unusual packet rates.
- Rule-based suspicious activity identification.

### 3. Security Alert Management
- Generates security alerts.
- Supports LOW, MEDIUM, HIGH and CRITICAL severity levels.
- Calculates risk scores.
- Stores alerts in SQLite.
- Tracks alert categories and timestamps.

### 4. Traffic Monitoring
- Displays TCP, UDP and ICMP packet statistics.
- Tracks IPv4 and IPv6 traffic.
- Displays total packets and bytes.
- Maintains session and lifetime traffic statistics.

### 5. Security Dashboard
- Real-time network monitoring interface.
- Security overview cards.
- Traffic statistics.
- Security alert table.
- Alert search and filtering.
- CSV alert export.
- Automatic dashboard refresh.

### 6. Security Reports
- Generates text-based security reports.
- Generates PDF security reports.
- Includes alert summaries and risk scores.
- Includes session and lifetime traffic statistics.
- Displays recent security alerts.

### 7. Automated Testing
- Tests intrusion detection functionality.
- Tests port scan detection.
- Tests SYN alert handling.
- Tests IP behaviour detection.
- Tests traffic statistics.
- Tests PDF report generation.

## Project Structure

```text
NID-TMS/
│
├── alerts/
│   └── alert_manager.py
│
├── analyzer/
│   ├── intrusion_detector.py
│   ├── risk_scoring.py
│   ├── traffic_analyzer.py
│   └── traffic_stats.py
│
├── capture/
│   └── packet_capture.py
│
├── config/
│   └── settings.py
│
├── dashboard/
│   ├── app.py
│   └── index.html
│
├── database/
│   └── database_manager.py
│
├── reports/
│   ├── report_generator.py
│   ├── pdf_report_generator.py
│   ├── nid_tms_security_report.txt
│   └── nid_tms_security_report.pdf
│
├── tests/
│   ├── test_detection_time_windows.py
│   ├── test_ip_behavior.py
│   ├── test_pdf_report_generator.py
│   ├── test_persistence_manual.py
│   ├── test_port_scan_detection.py
│   ├── test_syn_alert_guard.py
│   ├── test_system.py
│   └── test_traffic_stats.py
│
├── main.py
├── requirements.txt
├── requirements-dev.txt
├── .gitignore
└── README.md
```

*Note: The text and PDF report files are generated outputs. They may not exist until the report generators are run.*

## Requirements

- Python 3.10 or later.
- Windows or Linux.
- Git.
- Npcap on Windows when required for Scapy packet capture.
- Administrator privileges may be required for live packet capture.

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/Mulinticharan2007/NID-TMS.git
```

### 2. Open the project directory

```bash
cd NID-TMS
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the virtual environment

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 5. Install project dependencies

```bash
pip install -r requirements.txt
```

### 6. Install development and testing dependencies

```bash
pip install -r requirements-dev.txt
```

## Running the Application

Start the FastAPI application using:

```bash
python -m uvicorn main:app --reload
```

Open the dashboard in your browser:

```text
http://127.0.0.1:8000
```

The API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

## Generating Security Reports

### Generate a text report

```bash
python .\reports\report_generator.py
```

### Generate a PDF report

```bash
python .\reports\pdf_report_generator.py
```

Generated reports are saved in the `reports/` directory.

## Running Automated Tests

Run the complete test suite:

```bash
python -m pytest -q
```

Run tests with detailed output:

```bash
python -m pytest -v
```

Run only PDF report tests:

```bash
python -m pytest .\tests\test_pdf_report_generator.py -v
```

**Latest verified test result:** 25 tests passed.

## Security and Responsible Use

- Use this project only on networks and devices you own or have permission to monitor.
- Packet capture may require administrator privileges.
- Do not use this project to monitor networks without authorization.
- Detection results are rule-based indicators and do not prove that an attack has occurred.
- Investigate alerts before treating an IP address or activity as malicious.
- Avoid sharing captured traffic containing sensitive information.

## Current Project Status

The following components have been implemented:

- Network packet capture.
- Traffic analysis and statistics.
- Rule-based intrusion detection.
- Security alert generation.
- Risk scoring.
- SQLite database storage.
- FastAPI backend.
- Web-based security dashboard.
- Session and lifetime traffic monitoring.
- Text security report generation.
- PDF security report generation.
- Automated test suite.

The project has passed **25 automated tests** in the latest verified test run.

## Future Improvements

- Machine learning-based anomaly detection.
- Advanced threat intelligence integration.
- Improved detection accuracy.
- User authentication and role-based access.
- More detailed security analytics.
- Advanced report customization.
- Email notifications for high-severity alerts.

## Author

**Charan Mulinti**

GitHub: https://github.com/Mulinticharan2007

## Disclaimer

This project is developed for educational and cybersecurity learning purposes. It is not a replacement for professional enterprise-grade intrusion detection systems or security monitoring solutions.
