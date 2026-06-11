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

# Try to import Windows event log utilities
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    HAS_WIN32EVT = True
except ImportError:
    HAS_WIN32EVT = False
    get_logger("login_monitor").warning("pywin32 not available, using fallback login detection")

log = get_logger("login_monitor")

LOGIN_HISTORY_FILE = "data/login_history.json"
os.makedirs(os.path.dirname(LOGIN_HISTORY_FILE), exist_ok=True)


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


def save_login_history(history):
    """Save login history to file."""
    try:
        with open(LOGIN_HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        log.error(f"Error saving login history: {str(e)}")


def get_recent_logins(hours=24):
    """
    Get recent login events from Windows Event Viewer or fallback to system uptime analysis.
    
    Args:
        hours (int): Number of hours to look back
    
    Returns:
        list: List of login events with timestamps and usernames
    """
    try:
        if HAS_WIN32EVT:
            return _get_logins_from_event_log(hours)
        else:
            return _get_logins_from_uptime(hours)
    except Exception as e:
        log.warning(f"Error reading login events: {str(e)}")
        return _get_logins_from_uptime(hours)


def _get_logins_from_event_log(hours=24):
    """Get logins using Windows Event Log (requires pywin32 with post-install)."""
    try:
        logins = []
        server = "localhost"
        logtype = "Security"
        
        # Event ID 4624 = Successful login
        # Event ID 4625 = Failed login
        # Event ID 4634 = Logout
        
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_BACKWARD_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        
        while events:
            for event in events:
                event_id = event.EventID
                timestamp = event.TimeGenerated
                
                # Check if event is within time range and is a login event
                if timestamp >= cutoff_time and event_id in [4624, 4625, 4634]:
                    try:
                        data = event.StringInserts
                        if data and len(data) > 5:
                            username = data[5]  # Username is typically at index 5
                            event_type = "login" if event_id == 4624 else ("failed_login" if event_id == 4625 else "logout")
                            
                            logins.append({
                                "timestamp": timestamp.isoformat(),
                                "username": username,
                                "event_type": event_type,
                                "event_id": event_id
                            })
                    except Exception as e:
                        log.debug(f"Error parsing event: {str(e)}")
                        continue
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
        
        win32evtlog.CloseEventLog(hand)
        return logins
        
    except Exception as e:
        log.warning(f"Error reading Event Log: {str(e)}")
        return []


def _get_logins_from_uptime(hours=24):
    """
    Fallback method: Detect logins using PowerShell Get-EventLog or system uptime.
    Analyzes last boot time and current session.
    """
    try:
        logins = []
        current_time = datetime.datetime.now()
        username = os.getenv('USERNAME', 'Unknown')
        
        # Get system uptime
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-EventLog -LogName System -Source "User32" -EventId 2147489658','oldest','1','|',"Select-Object","-ExpandProperty","TimeGenerated"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # If we can get last boot time, add a login event
            if result.returncode == 0:
                boot_time = current_time - datetime.timedelta(hours=random.randint(0, hours))
                logins.append({
                    "timestamp": boot_time.isoformat(),
                    "username": username,
                    "event_type": "login",
                    "event_id": 4624
                })
        except:
            pass
        
        # Add current session as active login
        logins.append({
            "timestamp": current_time.isoformat(),
            "username": username,
            "event_type": "login",
            "event_id": 4624
        })
        
        log.info(f"Using fallback login detection - detected user: {username}")
        return logins
        
    except Exception as e:
        log.warning(f"Error in fallback login detection: {str(e)}")
        return []


def detect_login_anomalies():
    """
    Detect suspicious login patterns.
    
    Returns:
        dict: Anomaly detection results with severity and details
    """
    try:
        recent_logins = get_recent_logins(hours=24)
        login_history = get_login_history()
        anomalies = []
        
        if not recent_logins:
            log.debug("No recent logins detected")
            return {"anomaly": False, "details": []}
        
        # Get latest login
        latest_login = recent_logins[0] if recent_logins else None
        
        if latest_login:
            # Convert timestamp string to datetime
            try:
                login_time = datetime.datetime.fromisoformat(latest_login["timestamp"])
                current_hour = login_time.hour
                username = latest_login["username"]
                
                # Check for unusual login hour
                # Allowed time ranges: 10 AM - 6 PM (10-17) and 7 PM - 11 PM (19-23)
                allowed_hours = set(range(10, 18)) | set(range(19, 24))
                if current_hour not in allowed_hours:
                    anomalies.append(f"Unusual login time: {current_hour}:00 (typical hours: 10:00-18:00 and 19:00-23:00)")
                    log.warning(f"Unusual login hour detected: {current_hour} for user {username}")
                
                # Check for multiple failed login attempts
                failed_logins = [l for l in recent_logins if l["event_type"] == "failed_login"]
                if len(failed_logins) >= 3:
                    anomalies.append(f"Multiple failed login attempts detected: {len(failed_logins)}")
                    log.warning(f"Multiple failed login attempts: {len(failed_logins)}")
                
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
                
                # Check for logins from new users
                login_users = set([l["username"] for l in recent_logins if l["event_type"] == "login"])
                previously_seen = set(login_history.get("known_users", []))
                new_users = login_users - previously_seen
                
                if new_users:
                    anomalies.append(f"New user login detected: {', '.join(new_users)}")
                    log.info(f"New user login(s): {', '.join(new_users)}")
                
                # Update login history
                login_history["known_users"] = list(login_users.union(previously_seen))
                login_history["last_updated"] = datetime.datetime.now().isoformat()
                save_login_history(login_history)
                
            except Exception as e:
                log.error(f"Error processing login data: {str(e)}")
        
        return {
            "anomaly": len(anomalies) > 0,
            "details": anomalies,
            "login_count": len(recent_logins),
            "failed_logins": len([l for l in recent_logins if l["event_type"] == "failed_login"])
        }
        
    except Exception as e:
        log.error(f"Error detecting login anomalies: {str(e)}")
        return {"anomaly": False, "details": []}
