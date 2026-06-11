"""
AI Cyber Bodyguard - Main Application
Continuous security monitoring with ML-based anomaly detection
"""
import time
import sys
from core.monitor import collect_system_data
from core.ml_engine import train, detect
from core.login_monitor import detect_login_anomalies
from core.wifi_analyzer import analyze_wifi
from core.process_guard import detect_suspicious_process
from core.usb_monitor import detect_usb
from core.file_guard import check_integrity
from core.network_guard import check_network
from core.threat_engine import analyze
from core.response_engine import take_action
from core.web_guard import start_clipboard_monitoring
from database.mongo_db import log_event
from config import CHECK_INTERVAL
from logger import get_logger

log = get_logger("main")


def main():
    """
    Main application loop.
    Continuously monitors system for threats and takes action when detected.
    """
    try:
        log.info("=" * 60)
        log.info("🛡️  AI CYBER BODYGUARD STARTING")
        log.info("=" * 60)
        
        # Train/Load ML model
        log.info("Loading ML model for anomaly detection...")
        model = train()
        log.info("ML model loaded successfully")

        # Start web guard clipboard monitoring in the background
        start_clipboard_monitoring()

        log.info(f"Starting continuous monitoring (Check interval: {CHECK_INTERVAL}s)")
        log.info("Press Ctrl+C to stop\n")

        iteration = 0
        while True:
            iteration += 1
            try:
                # Collect all monitoring data
                data = collect_system_data()
                wifi = analyze_wifi()
                processes = detect_suspicious_process()
                usb = detect_usb()
                files = check_integrity()
                network = check_network()
                login_anomaly = detect_login_anomalies()

                # ML anomaly detection
                hour = int(data["time"][11:13])
                anomaly = detect(model, hour)

                # Comprehensive threat analysis
                severity, threats = analyze(data, anomaly, wifi, processes, usb, files, network, login_anomaly)

                # Log event to MongoDB
                log_event({
                    "iteration": iteration,
                    "severity": severity,
                    "threats": threats,
                    "data": data
                })

                # Take action if threats detected
                if severity != "SAFE":
                    take_action(severity, threats)

                # Wait before next check
                time.sleep(CHECK_INTERVAL)

            except KeyboardInterrupt:
                log.info("Keyboard interrupt received")
                break
            except Exception as e:
                log.error(f"Error in monitoring loop (iteration {iteration}): {str(e)}", exc_info=True)
                # Continue monitoring even if there's an error
                time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        log.info("Shutting down...")
    except Exception as e:
        log.critical(f"Fatal error in main application: {str(e)}", exc_info=True)
        sys.exit(1)
    finally:
        log.info("=" * 60)
        log.info("🛡️  AI CYBER BODYGUARD STOPPED")
        log.info("=" * 60)


if __name__ == "__main__":
    main()