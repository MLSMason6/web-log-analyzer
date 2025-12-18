# 🔍 Web Log Analyzer (Security-Focused)

## Overview

The **Web Log Analyzer** is a security-focused web application that analyzes Apache/Nginx access logs to identify traffic patterns, suspicious behavior, and potential web attacks. Instead of relying on database-driven CRUD operations, this project focuses on **raw log parsing, pattern detection, and data analysis**, closely mirroring real-world SOC and cybersecurity analyst workflows.

This project was built to demonstrate skills in **log analysis, threat detection, backend processing, and data visualization**.

---

## Key Features

* 📂 Upload Apache or Nginx access log files
* 🔎 Parse raw log entries using regex
* 🚨 Detect common web attack patterns
* 📊 Visualize traffic and status codes with charts
* 🕒 Analyze request volume over time
* 🌐 Identify top IP addresses by request volume
* 📄 Export flagged (suspicious) requests to CSV

---

## Detected Threat Types

The analyzer scans requests and user agents for common attack signatures, including:

* **SQL Injection** (e.g., `UNION SELECT`, `OR 1=1`)
* **Directory Traversal** (e.g., `../` attempts)
* **Cross-Site Scripting (XSS)** (e.g., `<script>` payloads)
* **Command Injection** (`;`, `||`, `&&`)
* **Suspicious User Agents** (e.g., `sqlmap`, `nikto`, `curl`, `wget`)

Flagged requests are highlighted in the results table and included in CSV exports.

---

## Dashboard Analytics

### Status Code Breakdown

Displays a pie chart showing HTTP response codes (200, 401, 403, 404, 500, etc.), helping identify errors, failed logins, and blocked requests.

### Request Volume Over Time

A timeline chart that groups requests by hour, making it easy to:

* Spot traffic spikes
* Identify brute-force or scanning bursts
* Visualize usage patterns

### Top IP Addresses

Lists the IPs generating the most requests, useful for identifying noisy or potentially malicious sources.

---

## CSV Export

Flagged requests can be exported to a CSV file containing:

* IP address
* Timestamp
* Request string
* HTTP status code
* Detected threat types

This mirrors real-world analyst workflows where suspicious activity is exported for reporting or further investigation.

---

## Project Structure

```
web-log-analyzer/
│
├── index.php              # Log upload page
├── analyze.php            # Parsing, detection, and visualization
├── export_csv.php         # CSV export of flagged logs
│
├── includes/
│   └── log_parser.php     # Regex parsing and threat detection logic
│
├── assets/
│   └── chart.min.js       # Chart.js library
│
├── uploads/               # Temporary uploaded log files
└── README.md
```

---

## Technologies Used

* **PHP** – backend processing and log parsing
* **Regular Expressions (Regex)** – extracting log fields and detecting threats
* **JavaScript** – chart rendering
* **Chart.js** – data visualization
* **HTML/CSS** – UI and layout

---

## What This Project Demonstrates

* Understanding of web server access logs
* Ability to parse unstructured data
* Applied cybersecurity analysis
* Detection of common web attack techniques
* Data aggregation and visualization
* Building analyst-focused tooling (not CRUD-based admin panels)

---

## Future Enhancements (Optional)

* Brute-force detection thresholds
* IP geolocation lookup
* User-agent anomaly scoring
* Dark-mode UI
* Log file format auto-detection

---

## How to Use

1. Place the project in a local PHP environment (XAMPP, MAMP, etc.)
2. Open `index.php` in your browser
3. Upload an Apache/Nginx access log file
4. Review charts, flagged requests, and analytics
5. Export suspicious activity to CSV if needed

---

## Author

**Mason Schrader**
Computer Information Systems
Cybersecurity & Software Projects

---

> This project was created as a portfolio piece to demonstrate real-world cybersecurity analysis and log interpretation skills.
