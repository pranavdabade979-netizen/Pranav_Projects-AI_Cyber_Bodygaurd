from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from config import MONGO_URI
import json
import os
from datetime import datetime

LOG_FILE = "logs/threat_logs.json"

# Ensure logs directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

db = None
logs = None
USE_MONGO = False

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # Explicitly test the connection
    client.admin.command('ping')  
    db = client["cyber_bodyguard"]
    logs = db["threat_logs"]
    USE_MONGO = True
    print("MongoDB connected successfully")
except (ConnectionFailure, ServerSelectionTimeoutError) as e:
    print(f"MongoDB not available ({str(e)}), using JSON logging")
    USE_MONGO = False
except Exception as e:
    print(f"MongoDB connection error ({type(e).__name__}: {str(e)}), using JSON logging")
    USE_MONGO = False

def log_event(data):
    """Log event to MongoDB or JSON file fallback"""
    if USE_MONGO and logs is not None:
        try:
            logs.insert_one(data)
        except Exception as e:
            print(f"MongoDB insert failed: {e}, falling back to JSON")
            # Fall through to JSON logging
            try:
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False)
                    f.write('\n')
                    f.flush()
            except Exception as json_err:
                print(f"JSON logging also failed: {json_err}")
    else:
        # Append to JSON file with UTF-8 encoding
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
                f.write('\n')
                f.flush()
        except Exception as e:
            print(f"Error writing to JSON file: {e}")