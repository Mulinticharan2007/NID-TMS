\# NID-TMS



\## Network Intrusion Detection \& Real-Time Traffic Monitoring System



NID-TMS is a Python-based cybersecurity project designed to monitor network traffic, analyze packets, identify suspicious activity, and generate security alerts through a web-based dashboard.



The project demonstrates fundamental network security monitoring and intrusion detection concepts in a practical environment.



\## Objectives



\* Capture and analyze network packets.

\* Monitor TCP, UDP, and ICMP traffic.

\* Detect suspicious network behavior.

\* Identify potential port scanning and SYN-related anomalies.

\* Generate and manage security alerts.

\* Display traffic statistics and alerts through a web dashboard.

\* Generate security reports for analysis.



\## Technologies Used



| Technology            | Purpose                                |

| --------------------- | -------------------------------------- |

| Python                | Core application and detection logic   |

| Scapy                 | Network packet capture and analysis    |

| FastAPI               | Web API and dashboard backend          |

| Uvicorn               | ASGI server                            |

| SQLite                | Persistent storage for security alerts |

| HTML, CSS, JavaScript | Interactive dashboard                  |

| Git and GitHub        | Version control and project hosting    |



\## Features



\* \*\*Packet Capture:\*\* Capture network packets using Scapy.

\* \*\*Traffic Monitoring:\*\* Track packet counts and traffic volume.

\* \*\*Protocol Analysis:\*\* Monitor TCP, UDP, and ICMP traffic.

\* \*\*Intrusion Detection:\*\* Identify potential port scans and suspicious SYN activity.

\* \*\*Security Alerts:\*\* Record and manage detected events.

\* \*\*Web Dashboard:\*\* View network statistics and security alerts.

\* \*\*Report Generation:\*\* Generate a text-based security report.

\* \*\*Automated Refresh:\*\* Refresh dashboard information periodically.

\* \*\*Unit Testing:\*\* Test traffic-statistics calculations using simulated packets.



\## Project Structure



```text

NID-TMS/

├── alerts/

│   └── alert\_manager.py

├── analyzer/

│   ├── intrusion\_detector.py

│   ├── traffic\_analyzer.py

│   └── traffic\_stats.py

├── capture/

│   └── packet\_capture.py

├── config/

│   └── settings.py

├── dashboard/

│   ├── app.py

│   └── index.html

├── database/

│   └── database\_manager.py

├── reports/

│   └── report\_generator.py

├── tests/

│   ├── test\_system.py

│   └── test\_traffic\_stats.py

├── main.py

├── requirements.txt

├── .gitignore

└── README.md

```



\*Note: This is the intended core structure. Some local files may differ depending on your current project version.\*



\## Requirements



\* Python 3.10 or later

\* Windows, Linux, or another compatible Python environment

\* Npcap on Windows when required for live packet capture with Scapy

\* Required Python packages listed in `requirements.txt`



\## Installation and Setup



\### 1. Clone the repository



```bash

git clone https://github.com/Mulinticharan2007/NID-TMS.git

cd NID-TMS

```



\### 2. Create a virtual environment



Windows PowerShell:



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

```



\### 3. Install dependencies



```powershell

python -m pip install -r requirements.txt

```



\### 4. Run the application



Start the application using the entry point appropriate for your current version:



```powershell

python main.py

```



If your dashboard is started separately, use the documented FastAPI/Uvicorn entry point for your project. For example, if the FastAPI application object is named `app` in `dashboard/app.py`:



```powershell

python -m uvicorn dashboard.app:app --reload

```



Open the local URL printed by Uvicorn in your browser. The usual development address is `http://127.0.0.1:8000`, but use the address and port shown in your terminal.



\## Testing



Run the traffic-statistics unit tests:



```powershell

python -m unittest tests.test\_traffic\_stats -v

```



The tests cover TCP, UDP, and ICMP packet counting, total byte calculations, and processing multiple packets.



Run the system checks using the test script:



```powershell

python tests/test\_system.py

```



\## Security and Responsible Use



\* Use live packet capture only on systems and networks you own or have explicit permission to monitor.

\* Run with the required privileges for your operating system and capture configuration.

\* Treat detection results as indicators for investigation, not definitive proof of an attack.

\* Avoid publishing sensitive packet captures, credentials, personal data, or private network information.



\## Current Project Status



The initial project setup, packet-analysis components, dashboard, alert-management components, report generator, and traffic-statistics tests have been developed.



The traffic-statistics test suite has passed five tests in the current development environment. Features and system-wide behavior should continue to be tested as the project evolves.



\## Future Improvements



\* Add additional intrusion-detection rules.

\* Improve alert severity scoring and filtering.

\* Add historical traffic charts.

\* Improve report export and filtering.

\* Expand automated tests and detection accuracy.

\* Add clear setup instructions and dashboard screenshots.



\## Author



\*\*Charan Mulinti\*\*



GitHub: \[@Mulinticharan2007](https://github.com/Mulinticharan2007)



\## Disclaimer



NID-TMS is an educational cybersecurity project intended for authorized network monitoring and defensive security learning. It is not a replacement for a production-grade intrusion detection system.



