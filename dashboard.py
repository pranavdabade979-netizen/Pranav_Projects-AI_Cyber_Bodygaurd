"""
Web dashboard to view threat alerts in real-time
Run: python dashboard.py
Then open: http://localhost:5000
"""
from flask import Flask, render_template, jsonify, request
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from config import MONGO_URI, MONGO_DB
from datetime import datetime, timedelta
import json
import csv
from io import StringIO
import os

app = Flask(__name__)

LOG_FILE = "logs/threat_logs.json"

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    USE_MONGO = True
except ConnectionFailure:
    print("MongoDB not available, using JSON logging")
    USE_MONGO = False

def get_db():
    """Connect to MongoDB"""
    if USE_MONGO:
        client = MongoClient(MONGO_URI)
        return client[MONGO_DB]
    else:
        return None

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/alerts")
def get_alerts():
    """Get latest alerts with optional filtering"""
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        # Get query parameters
        severity = request.args.get('severity')
        limit = int(request.args.get('limit', 50))
        hours = int(request.args.get('hours', 24))  # Last N hours
        
        # Build query
        query = {}
        if severity and severity != "all":
            query['severity'] = severity.upper()
        
        # Filter by time range
        time_cutoff = datetime.now() - timedelta(hours=hours)
        
        alerts = list(logs.find(query).sort("_id", -1).limit(limit))
        
        # Convert ObjectId to string for JSON serialization
        for alert in alerts:
            alert["_id"] = str(alert["_id"])
    else:
        # Read from JSON file
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        alerts.append(alert)
        
        # Get query parameters
        severity = request.args.get('severity')
        limit = int(request.args.get('limit', 50))
        hours = int(request.args.get('hours', 24))
        
        # Filter
        filtered = []
        time_cutoff = datetime.now() - timedelta(hours=hours)
        for alert in alerts:
            if severity and severity != "all" and alert.get('severity') != severity.upper():
                continue
            if 'timestamp' in alert:
                alert_time = datetime.fromisoformat(alert['timestamp'])
                if alert_time < time_cutoff:
                    continue
            filtered.append(alert)
        
        alerts = filtered[-limit:]  # Last limit
    
    return jsonify({
        "count": len(alerts),
        "alerts": alerts
    })

@app.route("/api/summary")
def get_summary():
    """Get alert summary statistics"""
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        total = logs.count_documents({})
        critical = logs.count_documents({"severity": "CRITICAL"})
        high = logs.count_documents({"severity": "HIGH"})
        medium = logs.count_documents({"severity": "MEDIUM"})
        safe = logs.count_documents({"severity": "SAFE"})
    else:
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        alerts.append(alert)
        
        total = len(alerts)
        critical = sum(1 for a in alerts if a.get('severity') == 'CRITICAL')
        high = sum(1 for a in alerts if a.get('severity') == 'HIGH')
        medium = sum(1 for a in alerts if a.get('severity') == 'MEDIUM')
        safe = sum(1 for a in alerts if a.get('severity') == 'SAFE')
    
    return jsonify({
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "safe": safe
    })

@app.route("/api/alerts/critical")
def get_critical_alerts():
    """Get critical alerts only"""
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        alerts = list(logs.find({"severity": "CRITICAL"}).sort("_id", -1).limit(20))
        
        for alert in alerts:
            alert["_id"] = str(alert["_id"])
    else:
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        if alert.get('severity') == 'CRITICAL':
                            alerts.append(alert)
        alerts = alerts[-20:]  # Last 20
    
    return jsonify(alerts)

@app.route("/api/alerts/by-severity")
def get_alerts_by_severity():
    """Get alert count breakdown by severity"""
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        severity_counts = {
            "CRITICAL": logs.count_documents({"severity": "CRITICAL"}),
            "HIGH": logs.count_documents({"severity": "HIGH"}),
            "MEDIUM": logs.count_documents({"severity": "MEDIUM"}),
            "SAFE": logs.count_documents({"severity": "SAFE"})
        }
    else:
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        alerts.append(alert)
        
        severity_counts = {
            "CRITICAL": sum(1 for a in alerts if a.get('severity') == 'CRITICAL'),
            "HIGH": sum(1 for a in alerts if a.get('severity') == 'HIGH'),
            "MEDIUM": sum(1 for a in alerts if a.get('severity') == 'MEDIUM'),
            "SAFE": sum(1 for a in alerts if a.get('severity') == 'SAFE')
        }
    
    return jsonify(severity_counts)

@app.route("/api/alerts/by-threat")
def get_threats_summary():
    """Get breakdown of threat types detected"""
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        threat_counts = {}
        
        for alert in logs.find({}):
            if 'threats' in alert:
                for threat in alert['threats']:
                    # Extract threat type (first word)
                    threat_type = threat.split(':')[0].strip()
                    threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
    else:
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        alerts.append(alert)
        
        threat_counts = {}
        for alert in alerts:
            if 'threats' in alert:
                for threat in alert['threats']:
                    threat_type = threat.split(':')[0].strip()
                    threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
    
    # Sort by count descending
    sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
    
    return jsonify(dict(sorted_threats[:10]))  # Top 10 threats

@app.route("/api/search")
def search_alerts():
    """Search alerts by keyword"""
    keyword = request.args.get('q', '').lower()
    if not keyword:
        return jsonify({"alerts": [], "count": 0})
    
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        # Search in threats array
        alerts = list(logs.find({
            "threats": {"$regex": keyword, "$options": "i"}
        }).sort("_id", -1).limit(50))
        
        for alert in alerts:
            alert["_id"] = str(alert["_id"])
    else:
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        if 'threats' in alert and any(keyword in threat.lower() for threat in alert['threats']):
                            alerts.append(alert)
        alerts = alerts[-50:]  # Last 50
    
    return jsonify({
        "count": len(alerts),
        "alerts": alerts,
        "query": keyword
    })

@app.route("/api/export/csv")
def export_csv():
    """Export alerts as CSV"""
    # Get severity filter from query params
    severity = request.args.get('severity')
    
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        query = {}
        if severity and severity != "all":
            query['severity'] = severity.upper()
        
        alerts = list(logs.find(query).sort("_id", -1).limit(1000))
    else:
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        if not severity or severity == "all" or alert.get('severity') == severity.upper():
                            alerts.append(alert)
        alerts = alerts[-1000:]  # Last 1000
    
    # Create CSV
    output = StringIO()
    if alerts:
        fieldnames = ['Timestamp', 'Severity', 'Threat Count', 'Threats', 'CPU %', 'Memory %']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for alert in alerts:
            threats_str = '; '.join(alert.get('threats', []))
            writer.writerow({
                'Timestamp': alert.get('data', {}).get('time', 'N/A') or alert.get('timestamp', 'N/A'),
                'Severity': alert.get('severity', 'UNKNOWN'),
                'Threat Count': len(alert.get('threats', [])),
                'Threats': threats_str[:200],  # Truncate long strings
                'CPU %': alert.get('data', {}).get('cpu', 'N/A'),
                'Memory %': alert.get('data', {}).get('memory', 'N/A')
            })
    
    return output.getvalue(), 200, {
        'Content-Disposition': 'attachment; filename=alerts_export.csv',
        'Content-Type': 'text/csv'
    }

@app.route("/api/stats/timeline")
def get_timeline():
    """Get threat count over time (last 24 hours)"""
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        # Get alerts from last 24 hours grouped by hour
        timeline = {}
        
        for alert in logs.find({}):
            time_str = alert.get('data', {}).get('time', '')
            if time_str:
                # Extract hour
                try:
                    hour = time_str[:13]  # YYYY-MM-DD HH
                    timeline[hour] = timeline.get(hour, 0) + 1
                except:
                    pass
    else:
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        alerts.append(alert)
        
        timeline = {}
        for alert in alerts:
            time_str = alert.get('data', {}).get('time', '') or alert.get('timestamp', '')[:13]
            if time_str:
                try:
                    hour = time_str[:13]
                    timeline[hour] = timeline.get(hour, 0) + 1
                except:
                    pass
    
    # Sort by time
    sorted_timeline = sorted(timeline.items())
    
    return jsonify(sorted_timeline)

@app.route("/api/webguard/clipboard")
def get_webguard_clipboard():
    """Get web guard clipboard monitoring events"""
    limit = int(request.args.get('limit', 50))
    threat_type = request.args.get('type', 'all')  # 'all', 'malicious', 'safe'
    
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        # Filter by WEB_GUARD type
        query = {"type": "WEB_GUARD"}
        
        if threat_type == 'malicious':
            query["malicious"] = True
        elif threat_type == 'safe':
            query["malicious"] = False
        
        alerts = list(logs.find(query).sort("_id", -1).limit(limit))
        
        for alert in alerts:
            alert["_id"] = str(alert["_id"])
    else:
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        if alert.get('type') == 'WEB_GUARD':
                            if threat_type == 'malicious' and not alert.get('malicious'):
                                continue
                            elif threat_type == 'safe' and alert.get('malicious'):
                                continue
                            alerts.append(alert)
        
        alerts = alerts[-limit:]  # Last limit
    
    return jsonify({
        "count": len(alerts),
        "alerts": alerts
    })

@app.route("/api/webguard/summary")
def get_webguard_summary():
    """Get web guard clipboard monitoring summary"""
    if USE_MONGO:
        db = get_db()
        logs = db["threat_logs"]
        
        total = logs.count_documents({"type": "WEB_GUARD"})
        malicious = logs.count_documents({"type": "WEB_GUARD", "malicious": True})
        safe = logs.count_documents({"type": "WEB_GUARD", "malicious": False})
    else:
        alerts = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        if alert.get('type') == 'WEB_GUARD':
                            alerts.append(alert)
        
        total = len(alerts)
        malicious = sum(1 for a in alerts if a.get('malicious'))
        safe = total - malicious
    
    return jsonify({
        "total": total,
        "malicious": malicious,
        "safe": safe
    })

if __name__ == "__main__":
    print("\n🛡️  AI CYBER BODYGUARD DASHBOARD")
    print("Starting server at http://localhost:5000")
    print("Press Ctrl+C to stop\n")
    app.run(debug=True, host="localhost", port=5000)
