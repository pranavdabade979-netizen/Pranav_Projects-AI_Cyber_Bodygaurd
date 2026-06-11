# 🛡️ AI Cyber Bodyguard

A comprehensive security monitoring system that uses machine learning and real-time threat detection to protect your system from cyber threats.

## Features

### 🔍 Real-Time Monitoring
- **System Metrics**: CPU, memory, disk usage, and process count monitoring
- **Anomaly Detection**: ML-based detection of unusual login times using Isolation Forest
- **Process Guard**: Detects suspicious processes based on keyword matching
- **USB Monitor**: Tracks and alerts on new USB device connections
- **File Guard**: Monitors critical files for unauthorized modifications using MD5 hashing
- **Network Guard**: Detects unknown and suspicious network connections
- **WiFi Security**: Analyzes WiFi configuration for vulnerabilities (WPS detection)

### 🚨 Threat Response
- **Multi-Level Severity**: SAFE, MEDIUM, HIGH, CRITICAL threat levels
- **Smart Alerting**: Weighted threat analysis based on threat count and type
- **System Notifications**: Windows system alerts for detected threats
- **MongoDB Logging**: Persistent threat logging for auditing and analysis

### 📊 Dashboard & Visualization
- **Web Dashboard**: Real-time threat visualization and monitoring
- **CLI Viewer**: Command-line interface for viewing alerts
- **Auto-Refresh**: Live updates every 5 seconds
- **Historical Data**: Complete audit trail of all detected threats

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Main Loop (every 10s)                │
├─────────────────────────────────────────────────────────┤
│  Monitor      → ML Detect  → Threat Analysis  → Response │
│  - System     → Anomalies  → Severity Score  → Alert    │
│  - Processes  → Hour          Threat Count    → Log      │
│  - Network    │  Pattern   → Weights                    │
│  - Files      │                                         │
│  - USB        │                                         │
│  - WiFi       │                                         │
└─────────────────────────────────────────────────────────┘
                            ↓
                    MongoDB Database
                  (threat_logs collection)
```

## Installation

### Prerequisites
- Python 3.8+
- MongoDB running on localhost:27017
- Windows OS (for system notifications)

### Setup

1. **Clone/Extract the project**
   ```bash
   cd AI-Cyber-Bodygaurd
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   # Copy example config
   copy .env.example .env
   
   # Edit .env with your settings
   # Update MONGO_URI if needed
   ```

4. **Prepare data**
   - Ensure `data/baseline.csv` exists with historical login time data
   - Format: CSV with 'time' column (YYYY-MM-DD HH:MM:SS)
   - Add critical files to `important_files/` folder for monitoring

## Usage

### Start the Security Monitor
```bash
python main.py
```

The system will:
1. Load/train the ML model
2. Start continuous monitoring
3. Display alerts in real-time
4. Log all events to MongoDB

**Output:**
```
🛡️  AI CYBER BODYGUARD STARTING
============================================================
Loading ML model for anomaly detection...
ML model loaded successfully
Starting continuous monitoring (Check interval: 10s)
Press Ctrl+C to stop
```

### View Alerts - Option 1: Web Dashboard
```bash
python dashboard.py
```
Then open: **http://localhost:5000** in your browser

Features:
- Real-time threat statistics
- Detailed threat breakdown
- Color-coded severity levels
- Auto-refresh every 5 seconds
- Manual refresh button

### View Alerts - Option 2: CLI Viewer
```bash
python cli_viewer.py
```

Menu:
1. View all alerts (latest 20)
2. View critical alerts only
3. View summary statistics

## Configuration

Edit `.env` file to customize settings:

```ini
# MongoDB
MONGO_URI=mongodb://admin:admin123@localhost:27017/
MONGO_DB=cyber_bodyguard

# Monitoring
CHECK_INTERVAL=10                    # Seconds between checks
CPU_THRESHOLD=85                     # % threshold
MEMORY_THRESHOLD=90                  # % threshold
DISK_THRESHOLD=80                    # % threshold

# ML Model
MODEL_PATH=data/model.pkl            # Trained model location
BASELINE_DATA=data/baseline.csv      # Training data

# Logging
LOG_LEVEL=INFO                       # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE=logs/bodyguard.log

# Suspicious Keywords (comma-separated)
SUSPICIOUS_KEYWORDS=keylogger,miner,trojan,hack,malware,ransomware

# Feature Flags
ENABLE_WIFI_MONITORING=true
ENABLE_USB_MONITORING=true
ENABLE_FILE_GUARD=true
ENABLE_NETWORK_GUARD=true
```

## Threat Severity Levels

| Level | Threats | Action |
|-------|---------|--------|
| 🟢 **SAFE** | 0 | No action |
| 🟡 **MEDIUM** | 1-2 | Warning alert |
| 🟠 **HIGH** | 3-4 | Risk alert |
| 🔴 **CRITICAL** | 5+ | Critical alert |

## Threat Types Detected

1. **Login Time Anomaly** - Unusual login hours detected by ML model
2. **High CPU Usage** - Exceeds configured threshold
3. **High Memory Usage** - Exceeds configured threshold
4. **Suspicious Processes** - Matches malware keyword patterns
5. **New USB Devices** - Unauthorized device connections
6. **File Modifications** - Critical files have changed
7. **Unknown Network IPs** - External network connections
8. **WiFi Vulnerabilities** - WPS enabled or weak encryption

## Logs

All events are logged to:
- **Console**: Real-time output during execution
- **File**: `logs/bodyguard.log` - Persistent log file
- **Database**: MongoDB `threat_logs` collection

View logs:
```bash
# Console (while running)
tail -f logs/bodyguard.log

# Query database
python -c "from database.mongo_db import *; 
logs = list(db['threat_logs'].find()); 
[print(l) for l in logs]"
```

## Directory Structure

```
AI-Cyber-Bodygaurd/
├── config.py              # Configuration management
├── logger.py              # Logging setup
├── main.py                # Main application
├── dashboard.py           # Web dashboard server
├── cli_viewer.py          # CLI alert viewer
├── test_suite.py          # Unit tests
├── core/                  # Core monitoring modules
│   ├── monitor.py         # System metrics collection
│   ├── ml_engine.py       # ML anomaly detection
│   ├── process_guard.py   # Process monitoring
│   ├── wifi_analyzer.py   # WiFi security
│   ├── usb_monitor.py     # USB detection
│   ├── file_guard.py      # File integrity
│   ├── network_guard.py   # Network monitoring
│   ├── threat_engine.py   # Threat analysis
│   ├── response_engine.py # Response actions
│   └── notifier.py        # User notifications
├── database/              # Database modules
│   └── mongo_db.py        # MongoDB operations
├── data/                  # Data files
│   ├── baseline.csv       # ML training data
│   └── model.pkl          # Trained ML model
├── templates/             # Web templates
│   └── dashboard.html     # Dashboard UI
├── logs/                  # Log files
│   └── bodyguard.log      # Application logs
├── important_files/       # Files to monitor
└── .env                   # Environment configuration
```

## Database Schema

### threat_logs Collection
```json
{
  "_id": ObjectId,
  "iteration": 123,
  "severity": "HIGH",
  "threats": [
    "Suspicious process detected: malware.exe",
    "High CPU usage: 92%"
  ],
  "data": {
    "time": "2026-02-21 14:30:45",
    "cpu": 92,
    "memory": 78,
    "disk": 65,
    "processes": 245
  }
}
```

## Performance Optimization

✅ **Model Caching** - ML model is saved and reused (50% faster startup)
✅ **Efficient Monitoring** - Parallel data collection
✅ **Error Recovery** - Graceful error handling with logging
✅ **Configurable Intervals** - Adjust monitoring frequency as needed

## Troubleshooting

### MongoDB Connection Error
```
Error: [Errno 10061] No connection could be made
```
**Solution:** Ensure MongoDB is running
```bash
mongod  # Start MongoDB service
```

### Flask Not Found
```
ModuleNotFoundError: No module named 'flask'
```
**Solution:** Install Flask
```bash
pip install flask
```

### Permission Denied (File Guard)
**Solution:** Use `important_files/` folder for monitoring or run as admin

### No Baseline Data
```
FileNotFoundError: baseline.csv not found
```
**Solution:** Create `data/baseline.csv` with time column

## Testing

Run unit tests:
```bash
python test_suite.py
```

Tests cover:
- ML model training and prediction
- Threat analysis and severity calculation
- Error handling and exceptions
- Configuration loading
- Database operations

## Advanced Features

### Custom Threat Rules
Modify `threat_engine.py` to add custom threat rules:
```python
if specific_condition:
    threats.append("Custom threat: description")
```

### Email Alerts
Extend `notifier.py` to send email alerts:
```python
import smtplib
# Add email sending logic
```

### Slack Integration
Add Slack webhook for instant notifications:
```python
import requests
requests.post(webhook_url, json={"text": message})
```

### Custom Suspicious Keywords
Update `.env`:
```ini
SUSPICIOUS_KEYWORDS=custom1,custom2,custom3
```

## License

This project is for educational and defensive security purposes.

## Support

For issues or questions:
1. Check `logs/bodyguard.log` for detailed error messages
2. Review MongoDB logs for database issues
3. Ensure all prerequisites are installed
4. Validate `.env` configuration

## Future Improvements

- [ ] Real-time threat intelligence integration
- [ ] Machine learning model improvement
- [ ] Automated remediation actions
- [ ] Multi-user dashboard with roles
- [ ] Email and SMS alerting
- [ ] API for third-party integration
- [ ] Docker containerization
- [ ] Cloud deployment support

---

**Stay secure! 🛡️**
