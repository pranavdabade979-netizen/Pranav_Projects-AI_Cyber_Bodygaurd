"""
Response Engine
Takes appropriate action based on threat severity level
"""
from core.notifier import alert
from config import ENABLE_NOTIFICATIONS
from logger import get_logger

log = get_logger("response_engine")


def take_action(severity, threats):
    """
    Execute response actions based on threat severity.
    
    Args:
        severity (str): Threat level (SAFE, MEDIUM, HIGH, CRITICAL)
        threats (list): List of detected threats
    """
    try:
        if not threats or severity == "SAFE":
            log.debug("No action needed - system is safe")
            return

        message = "\n".join(threats)
        log.info(f"Taking action for {severity} threat: {len(threats)} threat(s) detected")

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
            
    except Exception as e:
        log.error(f"Error taking action: {str(e)}")