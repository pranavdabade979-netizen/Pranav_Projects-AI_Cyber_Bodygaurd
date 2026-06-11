"""
Command-line tool to view threat alerts from MongoDB
"""
from pymongo import MongoClient
from config import MONGO_URI
from datetime import datetime
import json

def format_alert(alert):
    """Format alert for display"""
    timestamp = alert.get("data", {}).get("time", "N/A")
    severity = alert.get("severity", "UNKNOWN")
    threats = alert.get("threats", [])
    
    print("\n" + "="*80)
    print(f"SEVERITY: {severity}")
    print(f"TIME: {timestamp}")
    print(f"THREATS ({len(threats)}):")
    for i, threat in enumerate(threats, 1):
        print(f"  {i}. {threat}")
    print("="*80)

def view_all_alerts():
    """View all alerts"""
    client = MongoClient(MONGO_URI)
    db = client["cyber_bodyguard"]
    logs = db["threat_logs"]
    
    alerts = list(logs.find().sort("_id", -1).limit(20))
    
    if not alerts:
        print("No alerts found in database.")
        return
    
    print(f"\n📊 LATEST {len(alerts)} THREAT ALERTS\n")
    for alert in alerts:
        format_alert(alert)

def view_critical_alerts():
    """View only CRITICAL alerts"""
    client = MongoClient(MONGO_URI)
    db = client["cyber_bodyguard"]
    logs = db["threat_logs"]
    
    alerts = list(logs.find({"severity": "CRITICAL"}).sort("_id", -1).limit(20))
    
    if not alerts:
        print("No CRITICAL alerts found.")
        return
    
    print(f"\nCRITICAL THREATS ({len(alerts)})\n")
    for alert in alerts:
        format_alert(alert)

def view_summary():
    """View alert summary statistics"""
    client = MongoClient(MONGO_URI)
    db = client["cyber_bodyguard"]
    logs = db["threat_logs"]
    
    total = logs.count_documents({})
    critical = logs.count_documents({"severity": "CRITICAL"})
    high = logs.count_documents({"severity": "HIGH"})
    medium = logs.count_documents({"severity": "MEDIUM"})
    
    print("\n📈 THREAT SUMMARY")
    print("="*40)
    print(f"Total Alerts: {total}")
    print(f"Critical:  {critical}")
    print(f"High:      {high}")
    print(f"Medium:    {medium}")
    print("="*40)

if __name__ == "__main__":
    print("\nAI CYBER BODYGUARD - ALERT VIEWER\n")
    print("1. View all alerts")
    print("2. View critical alerts only")
    print("3. View summary")
    
    choice = input("\nSelect option (1-3): ").strip()
    
    if choice == "1":
        view_all_alerts()
    elif choice == "2":
        view_critical_alerts()
    elif choice == "3":
        view_summary()
    else:
        print("Invalid option")
