"""
System monitoring module
Collects real-time system metrics (CPU, memory, disk, processes)
"""
import psutil
import datetime
from logger import get_logger

log = get_logger("monitor")


def collect_system_data():
    """
    Collect current system metrics.
    
    Returns:
        dict: System metrics including time, CPU, memory, disk usage, and process count
    """
    try:
        return {
            "time": str(datetime.datetime.now()),
            "cpu": psutil.cpu_percent(interval=1),
            "memory": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent,
            "processes": len(psutil.pids())
        }
    except Exception as e:
        log.error(f"Error collecting system data: {str(e)}")
        return {
            "time": str(datetime.datetime.now()),
            "cpu": 0,
            "memory": 0,
            "disk": 0,
            "processes": 0
        }