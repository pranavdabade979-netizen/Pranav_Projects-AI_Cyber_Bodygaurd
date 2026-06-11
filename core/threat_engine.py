"""
Threat Analysis Engine
Analyzes multiple threat indicators and calculates overall severity level
"""
from config import CPU_THRESHOLD, MEMORY_THRESHOLD
from logger import get_logger

log = get_logger("threat_engine")

# Severity levels based on threat count
THREAT_THRESHOLDS = {
    "CRITICAL": 5,  # 5+ threats
    "HIGH": 3,      # 3-4 threats
    "MEDIUM": 1,    # 1-2 threats
    "SAFE": 0       # 0 threats
}


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
            severity_level (str): SAFE, MEDIUM, HIGH, or CRITICAL
            threat_list (list): Detailed threat descriptions
    """
    try:
        threats = []

        if anomaly == -1:
            threats.append("ML-based time anomaly detected")
        
        # Add login anomalies
        if login_anomaly and login_anomaly.get("anomaly"):
            for detail in login_anomaly.get("details", []):
                threats.append(f"Login anomaly: {detail}")

        if data.get("cpu", 0) > CPU_THRESHOLD:
            threats.append(f"High CPU usage: {data['cpu']}%")

        if data.get("memory", 0) > MEMORY_THRESHOLD:
            threats.append(f"High memory usage: {data['memory']}%")

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

        # Determine severity based on threat count
        severity = "SAFE"
        if len(threats) >= THREAT_THRESHOLDS["CRITICAL"]:
            severity = "CRITICAL"
        elif len(threats) >= THREAT_THRESHOLDS["HIGH"]:
            severity = "HIGH"
        elif len(threats) >= THREAT_THRESHOLDS["MEDIUM"]:
            severity = "MEDIUM"

        if severity != "SAFE":
            log.warning(f"Threats detected - Severity: {severity} ({len(threats)} threats)")
        else:
            log.info("System check completed - No threats detected")

        return severity, threats
    except Exception as e:
        log.error(f"Error analyzing threats: {str(e)}")
        return "MEDIUM", [f"Error during threat analysis: {str(e)}"]