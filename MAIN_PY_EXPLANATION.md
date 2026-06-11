# Main.py - Step-by-Step Code Explanation

## 📋 Overview
`main.py` is the **orchestrator/conductor** - it coordinates all the security modules to continuously monitor the system.

---

## 🔧 Part 1: Imports and Setup

```python
"""
AI Cyber Bodyguard - Main Application
Continuous security monitoring with ML-based anomaly detection
"""
```
**Lines 1-3:** Module docstring explaining the purpose.

```python
import time
import sys
```
**Lines 4-5:**
- `time`: Provides `sleep()` function to pause between checks
- `sys`: Provides `sys.exit()` to terminate application

```python
from core.monitor import collect_system_data
from core.ml_engine import train, detect
from core.login_monitor import detect_login_anomalies
from core.wifi_analyzer import analyze_wifi
from core.process_guard import detect_suspicious_process
from core.usb_monitor import detect_usb
from core.file_guard import check_integrity
from core.network_guard import check_network
from core.threat_engine import analyze
from core.response_engine import take_action
from core.web_guard import start_clipboard_monitoring
from database.mongo_db import log_event
from config import CHECK_INTERVAL
from logger import get_logger
```
**Lines 7-20:** Import all security modules

| Import | Purpose |
|--------|---------|
| `collect_system_data` | Get CPU, memory, disk metrics |
| `train, detect` | ML model training and anomaly detection |
| `detect_login_anomalies` | Check for suspicious login patterns |
| `analyze_wifi` | WiFi security analysis |
| `detect_suspicious_process` | Find malicious processes |
| `detect_usb` | Detect USB device connections |
| `check_integrity` | Monitor file tampering |
| `check_network` | Check network connections |
| `analyze` | Threat engine - combines all data |
| `take_action` | Response engine - trigger alerts |
| `start_clipboard_monitoring` | Monitor clipboard for malicious URLs |
| `log_event` | Save events to database |
| `CHECK_INTERVAL` | Delay between monitoring cycles |
| `get_logger` | Logging function |

```python
log = get_logger("main")
```
**Line 22:** Create a logger instance named "main" to log events from this file.

---

## 🎯 Part 2: Main Function Definition

```python
def main():
    """
    Main application loop.
    Continuously monitors system for threats and takes action when detected.
    """
```
**Lines 25-28:** Function definition with docstring.

```python
    try:
        log.info("=" * 60)
        log.info("🛡️  AI CYBER BODYGUARD STARTING")
        log.info("=" * 60)
```
**Lines 29-32:** 
- Start try block for error handling
- Print banner showing app is starting
- `"=" * 60` creates 60 equal signs

**Console Output:**
```
============================================================
🛡️  AI CYBER BODYGUARD STARTING
============================================================
```

---

## 🤖 Part 3: ML Model Training/Loading

```python
        # Train/Load ML model
        log.info("Loading ML model for anomaly detection...")
        model = train()
        log.info("ML model loaded successfully")
```
**Lines 35-38:**
- Log that we're loading the ML model
- Call `train()` function from `ml_engine.py`
  - If model file exists (`data/model.pkl`): **Load it** (fast)
  - If model doesn't exist: **Train new model** from baseline data
- Store trained model in `model` variable for later use
- Log success

**What train() does:**
```
First run:
  Load baseline.csv 
  → Extract login hours
  → Train IsolationForest 
  → Save to data/model.pkl

Subsequent runs:
  Load data/model.pkl 
  → Use immediately (no retraining)
```

---

## 🔗 Part 4: Start Background Monitoring

```python
        # Start web guard clipboard monitoring in the background
        start_clipboard_monitoring()
```
**Lines 40-41:**
- Launch clipboard monitoring in a separate thread
- This runs **continuously in background** while main loop executes
- Monitors if user copies malicious URLs
- Non-blocking (doesn't wait for completion)

**What it does:**
```
Background Thread:
  Every 1 second:
    Read clipboard contents
    If clipboard changed:
      Check if it's a URL
      Send to VirusTotal API
      Log result to database
      Alert if malicious
```

---

## ⏱️ Part 5: Configuration Display

```python
        log.info(f"Starting continuous monitoring (Check interval: {CHECK_INTERVAL}s)")
        log.info("Press Ctrl+C to stop\n")
```
**Lines 43-44:**
- Log the monitoring interval (default: 10 seconds from config)
- Inform user they can press Ctrl+C to stop

**Example Output:**
```
Starting continuous monitoring (Check interval: 10s)
Press Ctrl+C to stop
```

---

## 🔄 Part 6: The Main Monitoring Loop

```python
        iteration = 0
        while True:
```
**Lines 46-47:**
- Initialize iteration counter (tracks loop cycles)
- `while True`: **Infinite loop** - runs continuously until user presses Ctrl+C

```python
            iteration += 1
            try:
```
**Lines 48-49:**
- Increment iteration counter (1, 2, 3, ... N)
- Start try block to catch errors in this iteration

---

## 📊 Part 7: Data Collection Phase

```python
                # Collect all monitoring data
                data = collect_system_data()
                wifi = analyze_wifi()
                processes = detect_suspicious_process()
                usb = detect_usb()
                files = check_integrity()
                network = check_network()
                login_anomaly = detect_login_anomalies()
```
**Lines 51-57:** Call all detection modules **in parallel**

### 📈 Data Collected:

| Variable | What It Contains | Source |
|----------|------------------|--------|
| `data` | `{time, cpu%, memory%, disk%, process_count}` | `monitor.py` |
| `wifi` | `{encryption, wps_enabled, signal_strength}` | `wifi_analyzer.py` |
| `processes` | `["malware.exe", "keylogger.exe"]` | `process_guard.py` |
| `usb` | `["D:", "E:"]` (new USB drives) | `usb_monitor.py` |
| `files` | `["file_tampering_alert"]` | `file_guard.py` |
| `network` | `["192.168.1.100", "10.0.0.5"]` | `network_guard.py` |
| `login_anomaly` | `{anomaly: bool, details: []}` | `login_monitor.py` |

**Example values after one iteration:**
```python
data = {
    "time": "2024-01-15 14:30:45.123456",
    "cpu": 25.5,
    "memory": 60.2,
    "disk": 45.0,
    "processes": 142
}

wifi = {
    "encryption": "WPA2",
    "wps_enabled": True,
    "signal_strength": "Good"
}

processes = []  # No suspicious processes
usb = ["E:"]    # One new USB device detected
files = []      # No file tampering
network = []    # No suspicious connections
login_anomaly = {
    "anomaly": False,
    "details": [],
    "login_count": 2,
    "failed_logins": 0
}
```

---

## 🧠 Part 8: ML Anomaly Detection

```python
                # ML anomaly detection
                hour = int(data["time"][11:13])
                anomaly = detect(model, hour)
```
**Lines 59-60:**

### Breaking down line 59:
```python
hour = int(data["time"][11:13])
```
- `data["time"]` = `"2024-01-15 14:30:45.123456"`
- String indexing `[11:13]` = Extract characters 11-12 → `"14"`
- `int()` = Convert to integer → `14`
- **Result:** `hour = 14` (2 PM)

### Line 60:
```python
anomaly = detect(model, hour)
```
- Call ML model with the login hour
- Model returns either:
  - `1` = Normal hour (expected)
  - `-1` = Anomaly detected (suspicious)

**Example:**
```
If hour = 14 (2 PM):
  Normal working hours → anomaly = 1

If hour = 3 (3 AM):
  Outside working hours → anomaly = -1 (ALERT!)
```

---

## 🎯 Part 9: Threat Analysis (The Brain)

```python
                # Comprehensive threat analysis
                severity, threats = analyze(data, anomaly, wifi, processes, usb, files, network, login_anomaly)
```
**Lines 62-63:**
- Call `threat_engine.analyze()` with ALL collected data
- This function **combines everything** to calculate overall threat level
- Returns two values:

```python
severity, threats = analyze(...)
```

| Return Value | Example |
|--------------|---------|
| `severity` | `"CRITICAL"` or `"HIGH"` or `"MEDIUM"` or `"SAFE"` |
| `threats` | `["Suspicious process detected", "High CPU usage"]` |

**How severity is calculated:**
```
Count all threats:
  - ML anomaly detected?        +1
  - Login anomaly?              +1
  - Suspicious process?         +1
  - USB device detected?        +1
  - File tampering?             +1
  - Unknown network IP?         +1

Then:
  0 threats   → SAFE
  1-2 threats → MEDIUM
  3-4 threats → HIGH
  5+ threats  → CRITICAL
```

**Example threat analysis:**
```python
# Input
data = {cpu: 95, memory: 88}           # Both high
processes = ["trojan.exe"]             # Malware found
usb = ["E:"]                           # USB plugged in
anomaly = -1                           # Unusual login time

# Processing
threats = [
    "High CPU usage: 95%",
    "High memory usage: 88%",
    "Suspicious processes detected: trojan.exe",
    "Unauthorized USB device(s): E:",
    "ML-based time anomaly detected"
]
severity = "CRITICAL"  # 5 threats ≥ 5 threshold
```

---

## 💾 Part 10: Event Logging to Database

```python
                # Log event to MongoDB
                log_event({
                    "iteration": iteration,
                    "severity": severity,
                    "threats": threats,
                    "data": data
                })
```
**Lines 65-70:**
- Create event object with all threat information
- Save to MongoDB (or JSON fallback)
- Fields logged:
  - `iteration`: Which monitoring cycle (1, 2, 3...)
  - `severity`: Calculated threat level
  - `threats`: List of detected threat descriptions
  - `data`: System metrics (CPU, memory, etc.)

**Database record example:**
```json
{
  "iteration": 42,
  "severity": "HIGH",
  "threats": [
    "Suspicious process detected: malware.exe",
    "High CPU usage: 92%"
  ],
  "data": {
    "time": "2024-01-15 14:30:45",
    "cpu": 92.0,
    "memory": 75.5,
    "disk": 50.0,
    "processes": 156
  }
}
```

**Purpose:** Creates **audit trail** for investigation later!

---

## 🚨 Part 11: Response to Threats

```python
                # Take action if threats detected
                if severity != "SAFE":
                    take_action(severity, threats)
```
**Lines 72-74:**
- Check if system is safe
- If **NOT safe** (MEDIUM/HIGH/CRITICAL): Trigger response
- Call `response_engine.take_action()`

**What take_action() does:**
```python
if severity == "CRITICAL":
    Send loud popup alert to user
    Log to database
    
elif severity == "HIGH" or "MEDIUM":
    Log to database only
    No popup (avoid user spam)

elif severity == "SAFE":
    Do nothing
```

**Example responses:**
```
CRITICAL → "🚨 CRITICAL THREAT DETECTED" popup
HIGH     → Silently logged
MEDIUM   → Silently logged
SAFE     → No action
```

---

## ⏳ Part 12: Wait Before Next Check

```python
                # Wait before next check
                time.sleep(CHECK_INTERVAL)
```
**Lines 76-77:**
- Pause execution for `CHECK_INTERVAL` seconds (default: 10)
- Prevents system from being overwhelmed with checks
- Allows time for new events to occur

**Timeline:**
```
Iteration 1: Collect data, analyze, log → sleep 10s
Iteration 2: Collect data, analyze, log → sleep 10s
Iteration 3: Collect data, analyze, log → sleep 10s
...
```

---

## 🛑 Part 13: Error Handling in Loop

```python
            except KeyboardInterrupt:
                log.info("Keyboard interrupt received")
                break
```
**Lines 79-81:**
- If user presses Ctrl+C during monitoring loop
- Log that we received interrupt
- `break`: Exit the while loop (stop monitoring)

```python
            except Exception as e:
                log.error(f"Error in monitoring loop (iteration {iteration}): {str(e)}", exc_info=True)
                # Continue monitoring even if there's an error
                time.sleep(CHECK_INTERVAL)
```
**Lines 82-85:**
- If ANY error occurs in monitoring iteration:
  - Log the error with full details (`exc_info=True`)
  - **Don't crash!** Continue monitoring
  - Sleep before next iteration

**Example:**
```
Iteration 42: ERROR reading process list
  → Log error
  → Sleep 10s
  → Continue to iteration 43
```

---

## 🔴 Part 14: Outer Error Handling

```python
    except KeyboardInterrupt:
        log.info("Shutting down...")
```
**Lines 87-88:**
- If Ctrl+C pressed at any point
- Log shutdown message

```python
    except Exception as e:
        log.critical(f"Fatal error in main application: {str(e)}", exc_info=True)
        sys.exit(1)
```
**Lines 89-90:**
- If FATAL error occurs (can't recover)
- Log critical error
- Exit application with code 1 (error)

```python
    finally:
        log.info("=" * 60)
        log.info("🛡️  AI CYBER BODYGUARD STOPPED")
        log.info("=" * 60)
```
**Lines 91-94:**
- `finally`: Always executes (whether error or normal exit)
- Print shutdown banner

**Console Output on Exit:**
```
============================================================
🛡️  AI CYBER BODYGUARD STOPPED
============================================================
```

---

## 📌 Part 15: Application Entry Point

```python
if __name__ == "__main__":
    main()
```
**Lines 97-98:**
- Python idiom: Only run if this file is executed directly
- Not run if this file is imported as a module
- Calls the `main()` function to start everything

---

## 📊 Complete Execution Flow Diagram

```
START
  │
  ├─→ Load ML Model (train/detect anomalies)
  │
  ├─→ Start Clipboard Monitoring (background thread)
  │
  └─→ LOOP (Every 10 seconds):
      │
      ├─→ Collect Data
      │   ├─ CPU, Memory, Disk
      │   ├─ WiFi settings
      │   ├─ Running processes
      │   ├─ USB devices
      │   ├─ File hashes
      │   ├─ Network connections
      │   └─ Login patterns
      │
      ├─→ ML Anomaly Detection
      │   ├─ Extract login hour
      │   └─ Model predicts: Normal (1) or Anomaly (-1)
      │
      ├─→ Threat Analysis Engine
      │   ├─ Count all threats
      │   └─ Calculate severity: SAFE → MEDIUM → HIGH → CRITICAL
      │
      ├─→ Log to Database
      │   └─ Save event for dashboard/audit
      │
      ├─→ Response Engine
      │   ├─ If CRITICAL: Popup alert
      │   └─ If HIGH/MEDIUM: Silent log
      │
      ├─→ Sleep 10 seconds
      │
      └─→ REPEAT or EXIT (on Ctrl+C)

STOP
```

---

## 🎓 Key Concepts for Your Teacher

### 1. **Orchestration Pattern**
Main.py is a **conductor** that:
- Calls multiple independent modules
- Combines their outputs
- Makes decisions based on combined data

### 2. **Infinite Loop with Safe Exit**
```python
while True:
    try:
        # Monitor
    except KeyboardInterrupt:
        break  # Safe exit on Ctrl+C
```

### 3. **Layered Error Handling**
- Inner try-except: Handle individual iteration errors
- Outer try-except: Handle fatal errors
- Finally block: Always cleanup

### 4. **Real-time Monitoring**
- Continuous monitoring every `CHECK_INTERVAL` seconds
- Non-blocking (sleeps don't freeze detection)
- Background threads for parallel tasks

### 5. **Data Pipeline**
```
Collection → Processing → Analysis → Action → Logging
```

### 6. **Threat Scoring**
Multiple independent detections contribute to one severity level.

### 7. **Responsiveness**
Checks every 10 seconds = Quick threat detection while not overwhelming system.

---

## 🧪 Example: One Complete Iteration

```
ITERATION 5:

1. iteration = 5

2. Collect data:
   data = {cpu: 45%, memory: 60%, ...}
   processes = ["notepad.exe"]  (not suspicious)
   usb = []  (no new USB)
   files = []  (no tampering)
   network = []  (no unknown IPs)
   login_anomaly = {anomaly: False}

3. ML Detection:
   hour = 14 (2 PM)
   anomaly = 1  (normal)

4. Threat Analysis:
   threats = []  (no threats detected)
   severity = "SAFE"

5. Database Log:
   {
     "iteration": 5,
     "severity": "SAFE",
     "threats": [],
     "data": {...}
   }

6. Response:
   severity == "SAFE" → No action

7. Sleep 10 seconds

ITERATION 6:
...
```

This repeats continuously until you press Ctrl+C!

