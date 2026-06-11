"""
File Guard Module
Monitors critical files for unauthorized modifications
"""
import hashlib
import os
import json
from logger import get_logger

log = get_logger("file_guard")

WATCH_FOLDER = "important_files"
HASH_FILE = "data/file_hashes.json"
hash_map = {}


def load_hashes():
    """
    Load previously stored file hashes from disk.
    """
    global hash_map
    try:
        if os.path.exists(HASH_FILE):
            with open(HASH_FILE, 'r') as f:
                hash_map = json.load(f)
            log.info(f"Loaded {len(hash_map)} file hashes from {HASH_FILE}")
        else:
            hash_map = {}
            log.info("No existing hash file found - starting fresh")
    except Exception as e:
        log.error(f"Error loading hashes: {str(e)}")
        hash_map = {}


def save_hashes():
    """
    Save current file hashes to disk.
    """
    try:
        os.makedirs(os.path.dirname(HASH_FILE) or ".", exist_ok=True)
        with open(HASH_FILE, 'w') as f:
            json.dump(hash_map, f, indent=2)
        log.debug(f"Saved {len(hash_map)} file hashes to {HASH_FILE}")
    except Exception as e:
        log.error(f"Error saving hashes: {str(e)}")


def get_hash(path):
    """
    Calculate MD5 hash of a file.
    
    Args:
        path (str): File path
    
    Returns:
        str: MD5 hash of file contents
    """
    try:
        with open(path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        log.error(f"Error hashing file {path}: {str(e)}")
        return None


def check_integrity():
    """
    Check integrity of files in watch folder.
    Detects modifications by comparing MD5 hashes.
    
    Returns:
        list: Alert messages for modified files
    """
    try:
        alerts = []
        
        # Always load existing hashes to ensure we have the latest
        load_hashes()
        
        # Create watch folder if it doesn't exist
        if not os.path.exists(WATCH_FOLDER):
            os.makedirs(WATCH_FOLDER)
            log.info(f"Created watch folder: {WATCH_FOLDER}")
            return alerts
        
        log.debug(f"Checking {len(os.listdir(WATCH_FOLDER))} files in {WATCH_FOLDER}")
        
        for f in os.listdir(WATCH_FOLDER):
            path = os.path.join(WATCH_FOLDER, f)
            
            # Skip directories
            if not os.path.isfile(path):
                continue
            
            h = get_hash(path)
            if h is None:
                continue

            if f in hash_map and hash_map[f] != h:
                alert_msg = f"File integrity violation: {f} has been modified or tampered with"
                alerts.append(alert_msg)
                log.critical(alert_msg)
                # Update hash to new value (acknowledge the change)
                hash_map[f] = h
            elif f not in hash_map:
                # New file - add to baseline
                hash_map[f] = h
                log.info(f"Added new file to baseline: {f}")

        # Save updated hashes
        save_hashes()
        
        return alerts
    except Exception as e:
        log.error(f"Error checking file integrity: {str(e)}")
        return []