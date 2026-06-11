"""
Web Guard Module
Monitors web traffic and checks for malicious websites
"""
import requests
import re
import time
import threading
import json
import os
from datetime import datetime
from logger import get_logger

log = get_logger("web_guard")

# Try to import pyperclip for clipboard monitoring
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False
    log.warning("pyperclip not available - clipboard monitoring disabled")

# Simple blacklist of known malicious domains (expand as needed)
MALICIOUS_DOMAINS = [
    "malicious-site.com",
    "phishing-example.net",
    "fake-bank-login.ru",
    # Add more known malicious domains
]

# VirusTotal API (requires API key - get from virustotal.com)
VIRUSTOTAL_API_KEY = "00fabd336cd2e8c62191ffa59ef8c07858eae48724c356ed8029cf9a43c717d7"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# Global variables for clipboard monitoring
monitoring_active = False
clipboard_monitoring_thread = None

def is_malicious_domain(domain):
    """
    Check if a domain is in the local malicious domains list.
    
    Args:
        domain (str): Domain name to check
        
    Returns:
        bool: True if malicious
    """
    return domain.lower() in MALICIOUS_DOMAINS

def check_url_virustotal(url):
    """
    Check URL against VirusTotal API.
    
    Args:
        url (str): URL to check
        
    Returns:
        dict: {'malicious': bool, 'details': str}
    """
    if not VIRUSTOTAL_API_KEY:
        return {'malicious': False, 'details': 'VirusTotal API key not configured'}
    
    try:
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY,
            "content-type": "application/x-www-form-urlencoded"
        }
        
        data = f"url={url}"
        
        # First, submit URL for analysis
        response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()
            analysis_id = result.get('data', {}).get('id')
            
            if analysis_id:
                # Get analysis results
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                analysis_response = requests.get(analysis_url, headers=headers)
                
                if analysis_response.status_code == 200:
                    analysis = analysis_response.json()
                    stats = analysis.get('data', {}).get('attributes', {}).get('stats', {})
                    
                    malicious_votes = stats.get('malicious', 0)
                    suspicious_votes = stats.get('suspicious', 0)
                    
                    if malicious_votes > 0 or suspicious_votes > 2:
                        return {
                            'malicious': True, 
                            'details': f'Malicious detections: {malicious_votes}, Suspicious: {suspicious_votes}'
                        }
                    else:
                        return {
                            'malicious': False, 
                            'details': f'Clean (Malicious: {malicious_votes}, Suspicious: {suspicious_votes})'
                        }
        
        return {'malicious': False, 'details': 'Unable to check with VirusTotal'}
        
    except Exception as e:
        log.error(f"Error checking URL with VirusTotal: {str(e)}")
        return {'malicious': False, 'details': f'Error: {str(e)}'}

def check_website(url):
    """
    Comprehensive check for malicious website.
    
    Args:
        url (str): Website URL to check
        
    Returns:
        dict: {'malicious': bool, 'reason': str, 'details': str}
    """
    try:
        # Extract domain from URL
        domain_match = re.search(r'https?://([^/]+)', url)
        if not domain_match:
            return {'malicious': False, 'reason': 'Invalid URL', 'details': ''}
        
        domain = domain_match.group(1).lower()
        
        # Check local blacklist
        if is_malicious_domain(domain):
            return {
                'malicious': True, 
                'reason': 'Domain in local blacklist', 
                'details': f'Domain {domain} is known malicious'
            }
        
        # Check with VirusTotal
        vt_result = check_url_virustotal(url)
        if vt_result['malicious']:
            return {
                'malicious': True, 
                'reason': 'Detected by VirusTotal', 
                'details': vt_result['details']
            }
        
        return {
            'malicious': False, 
            'reason': 'No threats detected', 
            'details': vt_result['details']
        }
        
    except Exception as e:
        log.error(f"Error checking website {url}: {str(e)}")
        return {'malicious': False, 'reason': 'Error during check', 'details': str(e)}

def log_clipboard_event(url, malicious, reason, details):
    """
    Log clipboard event for both safe and malicious URLs.
    All URLs are logged to dashboard for visibility.
    
    Args:
        url (str): The URL detected in clipboard
        malicious (bool): Whether URL is malicious
        reason (str): Reason for classification
        details (str): Additional details
    """
    try:
        if malicious:
            event = {
                "timestamp": datetime.now().isoformat(),
                "type": "MALICIOUS_URL",
                "severity": "CRITICAL",
                "data": {
                    "time": datetime.now().isoformat(),
                    "url": url,
                    "reason": reason,
                    "details": details,
                    "status": "MALICIOUS"
                },
                "threats": [f"Malicious URL Detected: {reason}"],
                "url": url,
                "malicious": True,
                "reason": reason,
                "details": details
            }
            log.critical(f"MALICIOUS URL THREAT DETECTED: {url}")
        else:
            # Log safe URLs as INFO level
            event = {
                "timestamp": datetime.now().isoformat(),
                "type": "SAFE_URL",
                "severity": "INFO",
                "data": {
                    "time": datetime.now().isoformat(),
                    "url": url,
                    "reason": reason,
                    "details": details,
                    "status": "SAFE"
                },
                "threats": [f"Safe URL Scanned: {reason}"],
                "url": url,
                "malicious": False,
                "reason": reason,
                "details": details
            }
            log.info(f"SAFE URL LOGGED: {url[:60]}")
        
        # Log event to MongoDB or JSON fallback
        try:
            from database.mongo_db import log_event
            log_event(event)
            log.info(f"Event logged successfully: {event['type']}")
        except Exception as e:
            log.error(f"Error logging event: {str(e)}")
        
    except Exception as e:
        log.error(f"Error in log_clipboard_event: {str(e)}")

def monitor_clipboard():
    """
    Monitor clipboard for URLs and check them for malicious content.
    Runs in a separate thread and detects every clipboard change.
    URL checking happens asynchronously to never block clipboard detection.
    """
    global monitoring_active
    
    if not CLIPBOARD_AVAILABLE:
        log.warning("Clipboard monitoring not available - pyperclip not installed")
        return
    
    log.info("Clipboard monitoring thread started - monitoring for URLs...")
    monitoring_active = True
    last_clipboard_content = ""  # Track to detect changes
    check_count = 0
    
    def scan_url_async(url, check_num):
        """Scan URL in background without blocking clipboard monitor"""
        try:
            log.info(f"[Check #{check_num}] Starting URL scan in background: {url[:80]}...")
            result = check_website(url)
            log.info(f"[Check #{check_num}] Scan result: malicious={result['malicious']}, reason={result['reason']}")
            
            if result['malicious']:
                log.critical(f"[Check #{check_num}] MALICIOUS WEBSITE DETECTED: {url}")
                log.critical(f"[Check #{check_num}] Reason: {result['reason']}")
                log.critical(f"[Check #{check_num}] Details: {result['details']}")
                
                # Log the malicious URL as a threat
                try:
                    log_clipboard_event(url, True, result['reason'], result['details'])
                    log.info(f"[Check #{check_num}] Successfully logged malicious URL")
                except Exception as log_err:
                    log.error(f"[Check #{check_num}] Error logging malicious URL: {str(log_err)}")
                
                # Trigger alert
                try:
                    from .notifier import send_notification
                    send_notification(
                        "MALICIOUS WEBSITE DETECTED",
                        f"URL: {url[:100]}\nReason: {result['reason']}"
                    )
                except Exception as notify_err:
                    log.debug(f"[Check #{check_num}] Could not send notification: {str(notify_err)}")
            else:
                log.info(f"[Check #{check_num}] URL is safe - logging to dashboard: {url[:80]}...")
                try:
                    log_clipboard_event(url, False, result['reason'], result['details'])
                    log.info(f"[Check #{check_num}] Successfully logged safe URL")
                except Exception as log_err:
                    log.error(f"[Check #{check_num}] Error logging safe URL: {str(log_err)}")
        except Exception as e:
            log.error(f"[Check #{check_num}] Error scanning URL {url}: {str(e)}")
    
    while monitoring_active:
        try:
            current = pyperclip.paste()
            
            # Check if clipboard content has CHANGED
            if current and current != last_clipboard_content:
                log.info(f"Clipboard content changed - new content detected")
                log.info(f"Clipboard content length: {len(current)}, first 80 chars: {current[:80]}")
                last_clipboard_content = current  # Update immediately
                
                # Check if it looks like a URL or domain
                is_url = current.startswith(('http://', 'https://'))
                is_domain = '.' in current and not current.startswith(('file://', 'ftp://'))
                
                if is_url or is_domain:
                    # Convert domain to URL if needed
                    url_to_check = current if is_url else f"https://{current}"
                    check_count += 1
                    log.info(f"[Check #{check_count}] Detected URL/domain in clipboard: {url_to_check[:80]}...")
                    
                    # Scan URL asynchronously in background thread
                    scan_thread = threading.Thread(
                        target=scan_url_async,
                        args=(url_to_check, check_count),
                        daemon=True,
                        name=f"URLScan-{check_count}"
                    )
                    scan_thread.start()
                    log.info(f"[Check #{check_count}] Background scan thread started")
                else:
                    log.debug(f"Clipboard changed but is not a URL/domain. Content: {current[:80]}...")
            
            time.sleep(1)  # Check every 1 second for FAST detection
            
        except Exception as e:
            log.error(f"Error in clipboard monitoring: {str(e)}")
    
    log.info("Clipboard monitoring thread stopped")

def start_clipboard_monitoring():
    """
    Start clipboard monitoring in a background thread.
    Safe to call multiple times - only starts one thread.
    """
    global monitoring_active, clipboard_monitoring_thread
    
    if CLIPBOARD_AVAILABLE:
        # Only start if not already running
        if not monitoring_active and (clipboard_monitoring_thread is None or not clipboard_monitoring_thread.is_alive()):
            clipboard_monitoring_thread = threading.Thread(
                target=monitor_clipboard, 
                daemon=True,
                name="ClipboardMonitor"
            )
            clipboard_monitoring_thread.start()
            log.info("Clipboard monitoring started in background thread")
        elif monitoring_active:
            log.debug("Clipboard monitoring already active")
    else:
        log.warning("Cannot start clipboard monitoring - pyperclip not available")

def stop_clipboard_monitoring():
    """
    Gracefully stop clipboard monitoring thread.
    """
    global monitoring_active, clipboard_monitoring_thread
    
    if monitoring_active:
        log.info("Stopping clipboard monitoring...")
        monitoring_active = False
        
        # Wait for thread to finish (max 5 seconds)
        if clipboard_monitoring_thread and clipboard_monitoring_thread.is_alive():
            clipboard_monitoring_thread.join(timeout=5)
        
        log.info("Clipboard monitoring stopped")
    else:
        log.debug("Clipboard monitoring is not active")