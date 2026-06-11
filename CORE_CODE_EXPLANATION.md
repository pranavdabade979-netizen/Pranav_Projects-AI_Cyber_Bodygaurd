# AI Cyber Bodyguard - Core Module Detailed Explanation

## 📋 Overview
The core folder contains 11 specialized modules that work together to provide comprehensive system security monitoring. Each module handles a specific security aspect.

---

## 1️⃣ monitor.py - System Data Collection

### Purpose
Gathers real-time system metrics (CPU, memory, disk usage, process count) for threat analysis.

### Line-by-Line Explanation

```python
"""
System monitoring module
Collects real-time system metrics (CPU, memory, disk, processes)
"""
```
**Lines 1-3:** Module docstring describing what this file does.

```python
import psutil
import datetime
from logger import get_logger
```
**Lines 5-7:** 
- `psutil`: Library for accessing system information (CPU, memory, disk, processes)
- `datetime`: For recording timestamps
- `get_logger`: Custom logging function to log events

```python
log = get_logger("monitor")
```
**Line 9:** Creates a logger instance named "monitor" to track this module's activities.

```python
def collect_system_data():
    """
    Collect current system metrics.
    
    Returns:
        dict: System metrics including time, CPU, memory, disk usage, and process count
    """
```
**Lines 12-18:** Function definition with docstring explaining it collects system metrics.

```python
    try:
        return {
            "time": str(datetime.datetime.now()),
            "cpu": psutil.cpu_percent(interval=1),
            "memory": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent,
            "processes": len(psutil.pids())
        }
```
**Lines 19-26:** 
- **Line 19:** Try block to handle errors gracefully
- **Line 20-25:** Returns a dictionary containing:
  - `time`: Current timestamp as string
  - `cpu`: CPU usage percentage (interval=1 means it measures over 1 second)
  - `memory`: Total memory usage percentage
  - `disk`: Disk usage percentage (checking root '/' directory)
  - `processes`: Total number of running processes

```python
    except Exception as e:
        log.error(f"Error collecting system data: {str(e)}")
        return {
            "time": str(datetime.datetime.now()),
            "cpu": 0,
            "memory": 0,
            "disk": 0,
            "processes": 0
        }
```
**Lines 27-35:** Error handling - if collection fails, logs the error and returns zeros for all metrics (safe default).

---

## 2️⃣ ml_engine.py - Machine Learning Anomaly Detection

### Purpose
Uses Isolation Forest ML algorithm to detect unusual login times that deviate from normal patterns.

### Line-by-Line Explanation

```python
"""
ML Engine for anomaly detection using Isolation Forest
Trains on login hour patterns and detects anomalies
"""
import pandas as pd
import pickle
import os
from sklearn.ensemble import IsolationForest
from config import MODEL_PATH, BASELINE_DATA
from logger import get_logger
```
**Lines 1-11:**
- Imports pandas for data handling, pickle for saving models, sklearn for ML algorithm
- `IsolationForest`: ML algorithm that detects outliers/anomalies
- Loads configuration paths and logger

```python
log = get_logger("ml_engine")
```
**Line 13:** Create logger for ML engine events

```python
def train():
    """
    Train ML model on baseline data or load pre-trained model.
    
    Returns:
        model: Trained IsolationForest model for anomaly detection
    """
```
**Lines 16-22:** Function that trains or loads the ML model.

```python
    try:
        # Try to load existing model
        if os.path.exists(MODEL_PATH):
            log.info(f"Loading pre-trained model from {MODEL_PATH}")
            with open(MODEL_PATH, 'rb') as f:
                model = pickle.load(f)
            return model
```
**Lines 23-29:**
- **Line 25:** Checks if model file already exists
- **Line 26:** Logs that we're loading existing model
- **Line 27:** Opens the pickle file in binary read mode ('rb')
- **Line 28:** Deserializes the model from file
- **Line 29:** Returns the loaded model (skips retraining)

```python
        # Train new model if doesn't exist
        log.info(f"Training new model from baseline data: {BASELINE_DATA}")
        if not os.path.exists(BASELINE_DATA):
            log.error(f"Baseline data not found at {BASELINE_DATA}")
            raise FileNotFoundError(f"Baseline data not found at {BASELINE_DATA}")
```
**Lines 31-35:**
- If model doesn't exist, log that we'll train a new one
- Check if baseline data file exists
- If not, raise error (can't train without data)

```python
        df = pd.read_csv(BASELINE_DATA)
        df['hour'] = pd.to_datetime(df['time']).dt.hour
```
**Lines 37-38:**
- **Line 37:** Load baseline.csv into pandas DataFrame
- **Line 38:** Extract hour from 'time' column (converts "2024-01-15 14:30:00" → 14)

```python
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(df[['hour']])
```
**Lines 40-41:**
- **Line 40:** Create IsolationForest model
  - `contamination=0.1`: Expect 10% of data to be anomalies
  - `random_state=42`: For reproducible results
- **Line 41:** Train model on the hour values

```python
        # Save model for future use
        os.makedirs(os.path.dirname(MODEL_PATH) or ".", exist_ok=True)
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(model, f)
        log.info(f"Model trained and saved to {MODEL_PATH}")
        
        return model
```
**Lines 43-49:**
- Create data directory if needed
- Save trained model using pickle serialization
- Log success and return the model

```python
def detect(model, hour):
    """
    Detect if the given hour is anomalous based on trained model.
    
    Args:
        model: Trained IsolationForest model
        hour: Hour of the day (0-23)
    
    Returns:
        int: -1 if anomaly detected, 1 if normal
    """
```
**Lines 54-64:** Function to check if a login hour is suspicious.

```python
    try:
        if not isinstance(hour, int) or hour < 0 or hour > 23:
            log.warning(f"Invalid hour value: {hour}")
            return 1  # Return normal if invalid
```
**Lines 65-68:**
- Validate hour is integer between 0-23
- If invalid, log warning and return 1 (normal/safe)

```python
        df = pd.DataFrame([[hour]], columns=["hour"])
        prediction = model.predict(df)[0]
        
        if prediction == -1:
            log.warning(f"Anomaly detected at hour {hour}")
        
        return prediction
```
**Lines 70-74:**
- Convert hour into DataFrame for prediction
- Get model's prediction (-1 for anomaly, 1 for normal)
- Log if anomaly detected
- Return prediction

---

## 3️⃣ process_guard.py - Suspicious Process Detection

### Purpose
Monitors all running processes and identifies those with suspicious keywords/names.

### Line-by-Line Explanation

```python
"""
Process Guard module
Monitors running processes for suspicious activity and known malware signatures
"""
import psutil
from config import SUSPICIOUS_KEYWORDS
from logger import get_logger
```
**Lines 1-7:**
- Import psutil for process monitoring
- Import SUSPICIOUS_KEYWORDS list from config (keywords to watch for)
- Import logger

```python
log = get_logger("process_guard")
```
**Line 10:** Create logger for process guard

```python
def detect_suspicious_process():
    """
    Scan all running processes for suspicious names.
    
    Returns:
        list: List of process names that match suspicious keywords
    """
```
**Lines 13-19:** Function to find malware/suspicious processes.

```python
    try:
        found = []
        suspicious_procs = []
```
**Lines 20-22:**
- Start try block for error handling
- `found`: Simple list of process names
- `suspicious_procs`: Detailed list with PID and matching keyword

```python
        for p in psutil.process_iter(['name', 'pid']):
```
**Line 24:** Loop through all running processes, getting their name and PID.

```python
            try:
                proc_name = p.info['name'].lower()
                for keyword in SUSPICIOUS_KEYWORDS:
                    if keyword.lower() in proc_name:
                        found.append(p.info['name'])
                        suspicious_procs.append({
                            'name': p.info['name'],
                            'pid': p.info['pid'],
                            'keyword': keyword
                        })
                        break
```
**Lines 25-34:**
- **Line 27:** Convert process name to lowercase for case-insensitive matching
- **Line 28:** Loop through each suspicious keyword
- **Line 29:** Check if keyword is in process name
- **Line 30:** Add to found list
- **Lines 31-35:** Add detailed info (name, PID, matching keyword)
- **Line 36:** Break after first match (don't match same process twice)

```python
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
```
**Lines 37-38:** Skip processes that disappear or are protected from access.

```python
        if suspicious_procs:
            log.warning(f"Detected {len(suspicious_procs)} suspicious process(es)")
            for proc in suspicious_procs:
                log.warning(f"  - {proc['name']} (PID: {proc['pid']}) matched keyword: {proc['keyword']}")
```
**Lines 40-43:** If suspicious processes found, log details about each.

```python
        return found
    except Exception as e:
        log.error(f"Error detecting suspicious processes: {str(e)}")
        return []
```
**Lines 45-47:** Return found list, or empty list if error occurs.

---

## 4️⃣ file_guard.py - File Integrity Monitoring

### Purpose
Monitors critical files in 'important_files' folder for unauthorized changes using MD5 hashing.

### Line-by-Line Explanation

```python
"""
File Guard Module
Monitors critical files for unauthorized modifications
"""
import hashlib
import os
import json
from logger import get_logger
```
**Lines 1-8:** Imports for file hashing, file operations, JSON storage, and logging.

```python
log = get_logger("file_guard")

WATCH_FOLDER = "important_files"
HASH_FILE = "data/file_hashes.json"
hash_map = {}
```
**Lines 10-14:**
- Create logger
- Define folder to monitor (important_files)
- Define where to store hashes (data/file_hashes.json)
- Global dict to store filename → hash mappings

```python
def load_hashes():
    """
    Load previously stored file hashes from disk.
    """
    global hash_map
```
**Lines 17-21:** Function to load saved hashes from previous runs.

```python
    try:
        if os.path.exists(HASH_FILE):
            with open(HASH_FILE, 'r') as f:
                hash_map = json.load(f)
            log.info(f"Loaded {len(hash_map)} file hashes from {HASH_FILE}")
        else:
            hash_map = {}
            log.info("No existing hash file found - starting fresh")
```
**Lines 22-29:**
- If hash file exists, load it
- Count and log how many hashes loaded
- If not exists, start with empty dict

```python
def save_hashes():
    """
    Save current file hashes to disk.
    """
    try:
        os.makedirs(os.path.dirname(HASH_FILE) or ".", exist_ok=True)
        with open(HASH_FILE, 'w') as f:
            json.dump(hash_map, f, indent=2)
        log.debug(f"Saved {len(hash_map)} file hashes to {HASH_FILE}")
```
**Lines 36-42:**
- Create data directory if needed
- Save hash_map as formatted JSON
- Log the save

```python
def get_hash(path):
    """
    Calculate MD5 hash of a file.
    
    Args:
        path (str): File path
    
    Returns:
        str: MD5 hash of file contents
    """
    try:
        with open(path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
```
**Lines 45-58:**
- Open file in binary read mode
- Read entire file contents
- Calculate MD5 hash
- Return hexadecimal representation

```python
def check_integrity():
    """
    Check integrity of files in watch folder.
    Detects modifications by comparing MD5 hashes.
    
    Returns:
        list: Alert messages for modified files
    """
```
**Lines 61-68:** Main function to check if any files changed.

```python
    try:
        alerts = []
        
        # Always load existing hashes to ensure we have the latest
        load_hashes()
```
**Lines 69-73:**
- Load saved hashes from disk
- Create empty alerts list

```python
        # Create watch folder if it doesn't exist
        if not os.path.exists(WATCH_FOLDER):
            os.makedirs(WATCH_FOLDER)
            log.info(f"Created watch folder: {WATCH_FOLDER}")
            return alerts
```
**Lines 75-79:**
- Create watch folder if missing
- Return empty alerts (first run)

```python
        log.debug(f"Checking {len(os.listdir(WATCH_FOLDER))} files in {WATCH_FOLDER}")
        
        for f in os.listdir(WATCH_FOLDER):
            path = os.path.join(WATCH_FOLDER, f)
            
            # Skip directories
            if not os.path.isfile(path):
                continue
```
**Lines 81-87:**
- Log how many files to check
- Loop through each file/folder in watch folder
- Get full file path
- Skip if it's a directory

```python
            h = get_hash(path)
            if h is None:
                continue

            if f in hash_map and hash_map[f] != h:
                alert_msg = f"File integrity violation: {f} has been modified or tampered with"
                alerts.append(alert_msg)
                log.critical(alert_msg)
                # Update hash to new value (acknowledge the change)
                hash_map[f] = h
```
**Lines 89-98:**
- Calculate current file hash
- Skip if hash calculation failed
- If file was seen before and hash changed: **THIS IS TAMPERING!**
- Add alert message
- Log critical security event
- Update hash to acknowledge the change

```python
            elif f not in hash_map:
                # New file - add to baseline
                hash_map[f] = h
                log.info(f"Added new file to baseline: {f}")

        # Save updated hashes
        save_hashes()
        
        return alerts
```
**Lines 99-105:**
- If file is new (first time seen), add it to hash map
- Save updated hashes to disk
- Return all detected tampering alerts

---

## 5️⃣ login_monitor.py - Login Anomaly Detection

### Purpose
Detects suspicious login patterns: unusual login hours, brute force attempts, and new users.

### Line-by-Line Explanation

```python
"""
Login Anomaly Detection Module
Monitors Windows login events and detects suspicious login patterns
"""
import datetime
from logger import get_logger
from collections import defaultdict
import json
import os
import subprocess
import random
```
**Lines 1-12:** Imports for datetime handling, logging, Windows event interaction.

```python
# Try to import Windows event log utilities
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    HAS_WIN32EVT = True
except ImportError:
    HAS_WIN32EVT = False
    get_logger("login_monitor").warning("pywin32 not available, using fallback login detection")
```
**Lines 14-22:**
- Try to import Windows event log tools (optional)
- If available, set flag to True (can read Windows logs directly)
- If not available, use fallback method

```python
log = get_logger("login_monitor")
LOGIN_HISTORY_FILE = "data/login_history.json"
os.makedirs(os.path.dirname(LOGIN_HISTORY_FILE), exist_ok=True)
```
**Lines 24-26:** Setup logger and create data directory.

```python
def get_login_history():
    """Load login history from file."""
    if os.path.exists(LOGIN_HISTORY_FILE):
        try:
            with open(LOGIN_HISTORY_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            log.error(f"Error loading login history: {str(e)}")
            return {}
    return {}
```
**Lines 29-38:**
- Load previously saved login history
- If file exists, read JSON
- If error occurs, return empty dict
- Allows tracking login patterns over time

```python
def detect_login_anomalies():
    """
    Detect suspicious login patterns.
    
    Returns:
        dict: Anomaly detection results with severity and details
    """
```
**Lines 169-175:** Main function to identify suspicious login behavior.

```python
    try:
        recent_logins = get_recent_logins(hours=24)
        login_history = get_login_history()
        anomalies = []
```
**Lines 176-179:**
- Get all logins from last 24 hours
- Load previous login history
- Create empty list for detected anomalies

```python
        if not recent_logins:
            log.debug("No recent logins detected")
            return {"anomaly": False, "details": []}
```
**Lines 181-183:** If no logins, return no anomalies.

```python
        # Get latest login
        latest_login = recent_logins[0] if recent_logins else None
        
        if latest_login:
            # Convert timestamp string to datetime
            try:
                login_time = datetime.datetime.fromisoformat(latest_login["timestamp"])
                current_hour = login_time.hour
                username = latest_login["username"]
```
**Lines 185-192:**
- Get most recent login
- Parse the timestamp
- Extract hour and username

```python
                # Check for unusual login hour
                # Allowed time ranges: 10 AM - 6 PM (10-17) and 7 PM - 11 PM (19-23)
                allowed_hours = set(range(10, 18)) | set(range(19, 24))
                if current_hour not in allowed_hours:
                    anomalies.append(f"Unusual login time: {current_hour}:00 (typical hours: 10:00-18:00 and 19:00-23:00)")
                    log.warning(f"Unusual login hour detected: {current_hour} for user {username}")
```
**Lines 194-199:**
- Define normal working hours (10-17 and 19-23)
- If login outside these hours: **ANOMALY!**
- Add to anomalies list with details

```python
                # Check for multiple failed login attempts
                failed_logins = [l for l in recent_logins if l["event_type"] == "failed_login"]
                if len(failed_logins) >= 3:
                    anomalies.append(f"Multiple failed login attempts detected: {len(failed_logins)}")
                    log.warning(f"Multiple failed login attempts: {len(failed_logins)}")
```
**Lines 201-205:**
- Count failed login attempts
- If 3+ failures: **POSSIBLE BRUTE FORCE!**
- Add alert

```python
                # Check for rapid consecutive logins (possible brute force)
                if len(recent_logins) >= 5:
                    time_diffs = []
                    for i in range(len(recent_logins) - 1):
                        try:
                            t1 = datetime.datetime.fromisoformat(recent_logins[i]["timestamp"])
                            t2 = datetime.datetime.fromisoformat(recent_logins[i + 1]["timestamp"])
                            time_diff = abs((t1 - t2).total_seconds())
                            time_diffs.append(time_diff)
                        except:
                            continue
                    
                    # If average time between logins is < 30 seconds, suspicious
                    if time_diffs and sum(time_diffs) / len(time_diffs) < 30:
                        anomalies.append("Rapid login attempts detected - possible brute force")
                        log.warning("Rapid successive login attempts detected")
```
**Lines 207-221:**
- Calculate time between consecutive logins
- If average time < 30 seconds: **BRUTE FORCE DETECTED!**
- Attacker rapidly trying passwords

```python
                # Check for logins from new users
                login_users = set([l["username"] for l in recent_logins if l["event_type"] == "login"])
                previously_seen = set(login_history.get("known_users", []))
                new_users = login_users - previously_seen
                
                if new_users:
                    anomalies.append(f"New user login detected: {', '.join(new_users)}")
                    log.info(f"New user login(s): {', '.join(new_users)}")
```
**Lines 223-229:**
- Get all unique users in recent logins
- Get users seen in history
- Find new users (not seen before)
- If new users: log this (might be legitimate, might be suspicious)

```python
                # Update login history
                login_history["known_users"] = list(login_users.union(previously_seen))
                login_history["last_updated"] = datetime.datetime.now().isoformat()
                save_login_history(login_history)
```
**Lines 231-234:**
- Combine new users with previously known users
- Update timestamp
- Save updated history

```python
        return {
            "anomaly": len(anomalies) > 0,
            "details": anomalies,
            "login_count": len(recent_logins),
            "failed_logins": len([l for l in recent_logins if l["event_type"] == "failed_login"])
        }
```
**Lines 244-248:**
- Return comprehensive anomaly report:
  - Boolean if any anomalies found
  - List of detailed anomaly descriptions
  - Total login count
  - Failed login count

---

## 6️⃣ network_guard.py - Network Connection Monitoring

### Purpose
Monitors network connections and alerts on suspicious external IPs and ports.

### Line-by-Line Explanation

```python
"""
Network Guard Module
Monitors network connections for unauthorized or suspicious activity
"""
import psutil
from logger import get_logger
```
**Lines 1-6:** Import process/network library and logger.

```python
log = get_logger("network_guard")

# Trusted IP ranges and known safe IPs (customize as needed)
TRUSTED_RANGES = [
    "192.168.",     # Private network
    "127.",         # Localhost
    "10.",          # Private network
    # ... more ranges
]
```
**Lines 8-26:**
- Create logger
- Define IP ranges that are safe (private networks, localhost)
- These IPs won't trigger alarms

```python
# Known safe IPs (DNS, CDNs, etc.)
KNOWN_SAFE_IPS = {
    "8.8.8.8",      # Google DNS
    "8.8.4.4",      # Google DNS
    # ... more IPs
}
```
**Lines 28-42:** Whitelist of known safe public IPs (DNS servers, CDNs).

```python
# Suspicious ports commonly used by malware
SUSPICIOUS_PORTS = {
    21,    # FTP
    23,    # Telnet
    25,    # SMTP
    # ... more ports
}
```
**Lines 44-67:**
- Dictionary of ports associated with malware/exploits
- If connection uses these ports → suspicious

```python
def check_network():
    """
    Check network connections for unknown/suspicious IPs.
    
    Returns:
        list: List of suspicious external IP addresses
    """
```
**Lines 70-76:** Function to scan network connections.

```python
    try:
        conns = psutil.net_connections()
        suspicious = []

        for c in conns:
            if not c.raddr:
                continue
```
**Lines 77-83:**
- Get all active network connections
- Create empty suspicious list
- Skip connections without remote address

```python
            ip = str(c.raddr.ip)
            
            # Check if IP is in trusted ranges or known safe
            is_trusted = any(ip.startswith(trusted) for trusted in TRUSTED_RANGES) or ip in KNOWN_SAFE_IPS
            
            # Only flag as suspicious if not trusted AND using suspicious port
            if not is_trusted and c.raddr.port in SUSPICIOUS_PORTS and ip not in suspicious:
                suspicious.append(ip)
                log.warning(f"Suspicious network connection detected: {ip}:{c.raddr.port} (suspicious port)")
```
**Lines 85-92:**
- Extract IP address
- Check if IP is trusted (private range or whitelisted)
- If NOT trusted AND using suspicious port → **FLAG IT!**
- Log warning and add to suspicious list

```python
        return suspicious
    except Exception as e:
        log.error(f"Error checking network: {str(e)}")
        return []
```
**Lines 94-97:** Return suspicious IPs or empty list if error.

---

## 7️⃣ usb_monitor.py - USB Device Detection

### Purpose
Detects when new USB devices are plugged in (potential malware vector).

### Line-by-Line Explanation

```python
"""
USB Monitor Module
Detects new or unauthorized USB device connections
"""
import os
import platform
import psutil
from logger import get_logger
```
**Lines 1-8:** Import OS, platform detection, and system monitoring.

```python
log = get_logger("usb_monitor")

# Track previously seen USB devices
prev = set()

# Windows drive type constants
DRIVE_REMOVABLE = 2
```
**Lines 10-16:**
- Create logger
- `prev`: Set to store previously detected USB devices
- `DRIVE_REMOVABLE`: Windows constant for removable drives

```python
def _is_windows_removable(drive):
    """Return True if a drive is removable on Windows."""
    if platform.system() != "Windows":
        return False
```
**Lines 19-21:** Check if OS is Windows, return False if not.

```python
    try:
        from ctypes import windll, create_unicode_buffer

        drive_letter = os.path.splitdrive(drive)[0] + "\\"
        if not drive_letter:
            return False
        return windll.kernel32.GetDriveTypeW(drive_letter) == DRIVE_REMOVABLE
```
**Lines 22-28:**
- Use Windows DLL to check drive type
- Extract drive letter (C:, D:, etc.)
- Compare drive type with DRIVE_REMOVABLE constant
- Return True if it's a removable drive

```python
def detect_usb():
    """
    Detect newly connected USB devices.

    Returns:
        list: List of new USB device paths detected since last check
    """
```
**Lines 32-38:** Main function to find new USB devices.

```python
    global prev
    try:
        current = set()

        for p in psutil.disk_partitions(all=False):
            # Exclude main system drive and any non-removable fixed drives
            if p.device.upper().startswith("C:") or p.mountpoint.upper().startswith("C:"):
                continue
```
**Lines 40-47:**
- Use global prev set
- Get all disk partitions
- Skip C: drive (system drive)

```python
            is_removable = 'removable' in p.opts.lower() if p.opts else False
            if platform.system() == "Windows":
                # Check explicit drive type on Windows
                is_removable = is_removable or _is_windows_removable(p.device)

            if is_removable:
                current.add(p.device)
```
**Lines 49-54:**
- Check partition options for 'removable' flag
- On Windows, also use explicit drive type check
- Add removable drives to current set

```python
        new = current - prev

        if new:
            log.warning(f"New USB device(s) detected: {', '.join(new)}")

        prev = current
        return list(new)
```
**Lines 56-61:**
- Calculate new USB devices (current - prev)
- If any new devices, log warning
- Update prev for next check
- Return list of new devices

---

## 8️⃣ threat_engine.py - Threat Analysis & Severity Calculation

### Purpose
Analyzes all threat indicators and calculates overall system threat level.

### Line-by-Line Explanation

```python
"""
Threat Analysis Engine
Analyzes multiple threat indicators and calculates overall severity level
"""
from config import CPU_THRESHOLD, MEMORY_THRESHOLD
from logger import get_logger
```
**Lines 1-6:** Import configuration and logger.

```python
log = get_logger("threat_engine")

# Severity levels based on threat count
THREAT_THRESHOLDS = {
    "CRITICAL": 5,  # 5+ threats
    "HIGH": 3,      # 3-4 threats
    "MEDIUM": 1,    # 1-2 threats
    "SAFE": 0       # 0 threats
}
```
**Lines 8-15:**
- Create logger
- Define threat counting rules:
  - 0 threats = SAFE
  - 1-2 threats = MEDIUM
  - 3-4 threats = HIGH
  - 5+ threats = CRITICAL

```python
def analyze(data, anomaly, wifi, processes, usb, files, network, login_anomaly=None):
    """
    Analyze all threat indicators and determine overall severity.
    
    Args:
        data (dict): System metrics (cpu, memory, etc.)
        anomaly (int): ML anomaly detection result (-1 or 1)
        wifi (dict): WiFi security status
        processes (list): Suspicious processes found
        usb (list): USB devices detected
        files (list): File integrity violations
        network (list): Unknown network connections
        login_anomaly (dict): Login anomaly detection results
    
    Returns:
        tuple: (severity_level, threat_list)
```
**Lines 18-32:** Function signature with all threat types it analyzes.

```python
    try:
        threats = []

        if anomaly == -1:
            threats.append("ML-based time anomaly detected")
```
**Lines 33-37:**
- Create empty threats list
- If ML detected anomaly (-1), add to list

```python
        # Add login anomalies
        if login_anomaly and login_anomaly.get("anomaly"):
            for detail in login_anomaly.get("details", []):
                threats.append(f"Login anomaly: {detail}")
```
**Lines 39-42:** Add all login anomalies to threats.

```python
        if data.get("cpu", 0) > CPU_THRESHOLD:
            threats.append(f"High CPU usage: {data['cpu']}%")

        if data.get("memory", 0) > MEMORY_THRESHOLD:
            threats.append(f"High memory usage: {data['memory']}%")
```
**Lines 44-47:** Add CPU/memory threats if over thresholds.

```python
        if wifi.get("wps_enabled", False):
            threats.append("WPS enabled - router vulnerable to brute force attacks")

        if processes:
            threats.append(f"Suspicious processes detected: {', '.join(processes)}")

        if usb:
            threats.append(f"Unauthorized USB device(s): {', '.join(usb)}")

        if files:
            threats.extend(files)

        if network:
            threats.append(f"Unknown network connections: {', '.join(network)}")
```
**Lines 49-59:** Collect all other threat types into threats list.

```python
        # Determine severity based on threat count
        severity = "SAFE"
        if len(threats) >= THREAT_THRESHOLDS["CRITICAL"]:
            severity = "CRITICAL"
        elif len(threats) >= THREAT_THRESHOLDS["HIGH"]:
            severity = "HIGH"
        elif len(threats) >= THREAT_THRESHOLDS["MEDIUM"]:
            severity = "MEDIUM"
```
**Lines 61-68:** Calculate severity based on threat count using thresholds.

```python
        if severity != "SAFE":
            log.warning(f"Threats detected - Severity: {severity} ({len(threats)} threats)")
        else:
            log.info("System check completed - No threats detected")

        return severity, threats
```
**Lines 70-74:** Log findings and return severity + threat list.

---

## 9️⃣ notifier.py - User Alerts

### Purpose
Sends desktop notifications to alert the user about threats.

### Line-by-Line Explanation

```python
"""
Notifier Module
Sends system alerts and notifications to the user
"""
from plyer import notification
from logger import get_logger
```
**Lines 1-6:** Import notification library and logger.

```python
log = get_logger("notifier")

MAX_LENGTH = 240  # Windows notification character limit
```
**Lines 8-10:**
- Create logger
- Windows notifications have 240 character limit

```python
def alert(title, message):
    """
    Send a notification alert to the user.
    
    Args:
        title (str): Alert title (appears in bold)
        message (str): Alert message body
    """
```
**Lines 13-21:** Function to send desktop notification.

```python
    try:
        # Truncate message if too long for Windows notifications
        if len(message) > MAX_LENGTH:
            message = message[:MAX_LENGTH] + "..."

        notification.notify(
            title=title,
            message=message,
            timeout=5
        )
        log.info(f"Alert sent: {title}")
```
**Lines 22-31:**
- If message too long, truncate to 240 characters
- Send notification with title and message
- Display for 5 seconds
- Log that alert was sent

---

## 🔟 response_engine.py - Threat Response Actions

### Purpose
Executes appropriate actions (alerts, logging) based on threat severity.

### Line-by-Line Explanation

```python
"""
Response Engine
Takes appropriate action based on threat severity level
"""
from core.notifier import alert
from config import ENABLE_NOTIFICATIONS
from logger import get_logger
```
**Lines 1-7:** Import notification function, config, and logger.

```python
log = get_logger("response_engine")
```
**Line 10:** Create logger.

```python
def take_action(severity, threats):
    """
    Execute response actions based on threat severity.
    
    Args:
        severity (str): Threat level (SAFE, MEDIUM, HIGH, CRITICAL)
        threats (list): List of detected threats
    """
```
**Lines 13-21:** Function to respond to threats.

```python
    try:
        if not threats or severity == "SAFE":
            log.debug("No action needed - system is safe")
            return

        message = "\n".join(threats)
        log.info(f"Taking action for {severity} threat: {len(threats)} threat(s) detected")
```
**Lines 22-28:**
- If no threats, do nothing
- Combine threats into multi-line message
- Log the action

```python
        if severity == "CRITICAL":
            log.critical("CRITICAL THREAT DETECTED - Triggering alert")
            if ENABLE_NOTIFICATIONS:
                alert("🚨 CRITICAL THREAT DETECTED", message)

        elif severity == "HIGH":
            log.warning("HIGH RISK - Logging only (no popup)")
            # No alert for HIGH

        elif severity == "MEDIUM":
            log.warning("MEDIUM SEVERITY - Logging only (no popup)")
            # No alert for MEDIUM
```
**Lines 30-42:**
- For CRITICAL: Send loud popup alert
- For HIGH/MEDIUM: Just log (no popup to avoid user spam)

---

## 1️⃣1️⃣ wifi_analyzer.py - WiFi Security Scanning

### Purpose
Checks WiFi network security configuration for vulnerabilities.

### Line-by-Line Explanation

```python
"""
WiFi Security Analyzer
Monitors WiFi network security settings and vulnerabilities
"""
from logger import get_logger

log = get_logger("wifi_analyzer")
```
**Lines 1-7:** Import logger.

```python
def analyze_wifi(): 
    """
    Analyze current WiFi network security configuration.
    
    Returns:
        dict: WiFi security status including encryption and WPS settings
    """
```
**Lines 10-16:** Function to check WiFi security.

```python
    try:
        # Note: This is a placeholder. In production, integrate with:
        # - WiFi scanning libraries (scapy, pywifi)
        # - Network manager APIs for real WiFi data
        
        result = {
            "encryption": "WPA2",  
            "wps_enabled": True,
            "signal_strength": "Good"
        }
        
        if result["wps_enabled"]:
            log.warning("WiFi WPS is enabled - vulnerable to brute force attacks")
        
        return result
```
**Lines 17-30:**
- Currently returns hardcoded data (placeholder)
- In real implementation: scan actual WiFi
- WPS (WiFi Protected Setup) is vulnerable to brute force
- Returns dict with security info

---

## 📊 How All Modules Work Together

```
┌──────────────────────────────────────────────────┐
│          MAIN.PY (Orchestrator)                  │
└──────────────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
    COLLECTION      DETECTION        RESPONSE
    ┌─────────┐    ┌──────────┐    ┌─────────┐
    │monitor  │    │ml_engine │    │response │
    │  (CPU,  │    │(anomaly) │    │ engine  │
    │memory,  │    │          │    │(actions)│
    │ disk)   │    └──────────┘    └─────────┘
    └─────────┘          │               ▲
                         │               │
    ┌─────────┐    ┌─────┴─────┐   ┌────────┐
    │file_    │    │threat_    │   │notif   │
    │guard    │    │engine     │   │ier     │
    │(hashes) │    │(analyze)  │   │(alert) │
    └─────────┘    └───────────┘   └────────┐
                         │                   
    ┌─────────┐    ┌─────┴─────┐           
    │process_ │    │LOG EVENT  │           
    │guard    │    │to Database│           
    │(names)  │    └───────────┘           
    └─────────┘                             
                                             
    ┌─────────────────────────────────────┐
    │ login_monitor  network_guard         │
    │ (login anomaly)(connections)         │
    │ usb_monitor    wifi_analyzer         │
    │ (USB devices)  (WiFi security)       │
    └─────────────────────────────────────┘
```

---

## 🎯 Key Security Concepts

### 1. **Defense in Depth**
- Multiple monitoring layers (processes, files, network, logins)
- Single detection triggering alerts
- Multiple detections increasing severity

### 2. **Hashing (File Guard)**
- MD5 hash: Unique fingerprint of file content
- If hash changes = file modified
- Detects tampering

### 3. **Machine Learning (ML Engine)**
- IsolationForest algorithm finds outliers
- Trained on baseline normal behavior
- Detects deviations from normal

### 4. **Threat Scoring**
- 0 threats = Safe
- 1-2 threats = Medium
- 3-4 threats = High
- 5+ threats = Critical

### 5. **Event Logging**
- All events logged to MongoDB or JSON
- Dashboard shows security events
- Audit trail for investigation

---

## 💡 Teaching Points for Your Professor

1. **Modular Design**: Each module handles ONE responsibility
2. **Error Handling**: Try-except blocks prevent crashes
3. **Logging**: Comprehensive logging for debugging and audit
4. **Thresholds**: Configurable limits for different environments
5. **Cross-module Integration**: Threat engine combines data from all modules
6. **Real-time Monitoring**: Continuous scanning in main.py loop
7. **Machine Learning**: Unsupervised anomaly detection with Isolation Forest
8. **Multi-layered Detection**: Catches threats multiple ways

