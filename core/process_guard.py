"""
Process Guard module
Monitors running processes for suspicious activity and known malware signatures
"""
import psutil
from config import SUSPICIOUS_KEYWORDS
from logger import get_logger

log = get_logger("process_guard")


def detect_suspicious_process():
    """
    Scan all running processes for suspicious names.
    
    Returns:
        list: List of process names that match suspicious keywords
    """
    try:
        found = []
        suspicious_procs = []
        
        for p in psutil.process_iter(['name', 'pid']):
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
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if suspicious_procs:
            log.warning(f"Detected {len(suspicious_procs)} suspicious process(es)")
            for proc in suspicious_procs:
                log.warning(f"  - {proc['name']} (PID: {proc['pid']}) matched keyword: {proc['keyword']}")
        
        return found
    except Exception as e:
        log.error(f"Error detecting suspicious processes: {str(e)}")
        return []