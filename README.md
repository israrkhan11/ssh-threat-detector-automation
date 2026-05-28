# SSH Threat Detection System

A Python-based cybersecurity monitoring tool that detects SSH brute-force attacks from Linux authentication logs.

## Features

* Real-time SSH log monitoring
* Failed login detection
* Brute-force attack detection
* Alert generation
* Incident report creation
* SOC-style monitoring workflow

## Technologies Used

* Python
* Linux
* Regex
* File Handling
* Cybersecurity Monitoring

## Project Structure

```text
ssh-threat-detector/
│
├── monitor.py
├── analyzer.py
├── config.py
├── README.md
```

## How It Works

1. `monitor.py` reads Linux authentication logs.
2. `analyzer.py` analyzes failed SSH login attempts.
3. Suspicious IP addresses are detected after threshold limits.
4. Alerts and incident reports are generated automatically.

## Example Detection

```text
[ALERT] Threat detected!
IP: 192.168.1.100 | Failed Attempts: 5
```

## MITRE ATT&CK Mapping

* T1110 — Brute Force

## Future Improvements

* Email alerts
* Real-time dashboard
* GeoIP attacker tracking
* SIEM integration

## Author

Israr Khan
