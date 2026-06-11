"""
Configuration module for AI Cyber Bodyguard
Loads settings from .env file or uses defaults
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://admin:admin123@localhost:27017/")
MONGO_DB = os.getenv("MONGO_DB", "cyber_bodyguard")

# System Monitoring Thresholds
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "10"))
CPU_THRESHOLD = int(os.getenv("CPU_THRESHOLD", "85"))
MEMORY_THRESHOLD = int(os.getenv("MEMORY_THRESHOLD", "90"))
DISK_THRESHOLD = int(os.getenv("DISK_THRESHOLD", "80"))

# ML Model
MODEL_PATH = os.getenv("MODEL_PATH", "data/model.pkl")
BASELINE_DATA = os.getenv("BASELINE_DATA", "data/baseline.csv")

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/bodyguard.log")

# Suspicious Keywords
SUSPICIOUS_KEYWORDS = os.getenv(
    "SUSPICIOUS_KEYWORDS",
    "keylogger,miner,trojan,hack,malware,ransomware"
).split(",")

# Feature Flags
ENABLE_WIFI_MONITORING = os.getenv("ENABLE_WIFI_MONITORING", "false").lower() == "true"
ENABLE_USB_MONITORING = os.getenv("ENABLE_USB_MONITORING", "true").lower() == "true"
ENABLE_FILE_GUARD = os.getenv("ENABLE_FILE_GUARD", "true").lower() == "true"
ENABLE_NETWORK_GUARD = os.getenv("ENABLE_NETWORK_GUARD", "true").lower() == "true"

# Notifications
ENABLE_NOTIFICATIONS = os.getenv("ENABLE_NOTIFICATIONS", "false").lower() == "true"