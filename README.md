# Real-Time-Cybersecurity-Dashboard
A Python-based monitoring tool that provides live security insights and system performance metrics.

## Features
Network Monitoring: Tracks active connections and flags suspicious IPs/ports

###  Process Scanning: Detects high-CPU processes and known malicious executables

System Metrics: Real-time CPU, memory, disk, and network monitoring

Alert System: Categorizes threats by severity (High/Medium/Low)

Web Dashboard: Interactive dark-mode interface with live updates

REST API: JSON endpoint for integration with other tools

#### Technologies Used
Python 3

Flask (Web framework)

psutil (System monitoring)

HTML/CSS/JS (Dashboard UI)

##### Installation
bash
git clone [repo-url]
cd cybersecurity-dashboard
pip install -r requirements.txt
python app.py
Then open http://localhost:5000 in your browser

Use Cases
Home lab security monitoring

Educational tool for cybersecurity concepts

Lightweight alternative to commercial monitoring solutions
