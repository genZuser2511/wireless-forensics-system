import argparse
import time
import logging
from datetime import datetime, timedelta
from baseline_engine import BaselineEngine
from kismet_client import KismetClient
from anomaly_detector import AnomalyDetector

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def parse_duration(duration_str):
    """Parses a duration string like '10m' into seconds."""
    if duration_str.endswith('m'):
        return int(duration_str[:-1]) * 60
    elif duration_str.endswith('s'):
        return int(duration_str[:-1])
    elif duration_str.endswith('h'):
        return int(duration_str[:-1]) * 3600
    return int(duration_str)

def run_learning_mode(kismet, baseline, duration_secs):
    """
    Runs the learning mode for a specified duration.
    Polls Kismet periodically and updates the local baseline database.
    """
    logger.info(f"Starting Learning Mode for {duration_secs} seconds...")
    end_time = datetime.now() + timedelta(seconds=duration_secs)
    
    poll_interval = 5 # seconds
    
    while datetime.now() < end_time:
        devices = kismet.get_active_devices()
        if devices:
            for dev in devices:
                mac = dev.get("kismet.device.base.macaddr")
                dev_type = dev.get("kismet.device.base.type")
                name = dev.get("kismet.device.base.name")
                channel = dev.get("kismet.device.base.channel")
                crypt = dev.get("kismet.device.base.crypt")
                
                # If it's an Access Point (Wi-Fi AP)
                if dev_type == "Wi-Fi AP":
                    baseline.add_or_update_ap(
                        bssid=mac, 
                        ssid=name, 
                        channel=int(channel) if channel else None, 
                        encryption=crypt
                    )
                # If it's a Client (Wi-Fi Client)
                elif dev_type == "Wi-Fi Client":
                    # Kismet dot11 structure might nest the last BSSID
                    dot11 = dev.get("dot11.device", {})
                    last_bssid = dot11.get("dot11.device.last_bssid", None)
                    baseline.add_or_update_client(
                        mac=mac,
                        associated_bssid=last_bssid
                    )
                    
        time_left = (end_time - datetime.now()).total_seconds()
        logger.info(f"Learning... {int(time_left)} seconds remaining. Added {len(devices)} active devices to baseline.")
        time.sleep(poll_interval)
        
    logger.info("Learning Mode completed. Baseline populated.")

def run_monitoring_mode(kismet, detector):
    """
    Runs the monitoring mode continuously.
    Polls Kismet for active devices and alerts, and feeds them to the Anomaly Detector.
    """
    logger.info("Starting Monitoring Mode...")
    poll_interval = 5 # seconds
    last_alert_ts = 0

    try:
        while True:
            # 1. State-Based Detection (Devices)
            devices = kismet.get_active_devices()
            if devices:
                detector.process_devices(devices)
            
            # 2. Event-Based Detection (Alerts/Deauth/Brute Force)
            recent_kismet_alerts = kismet.get_recent_alerts(since_ts=last_alert_ts)
            if recent_kismet_alerts:
                detector.process_kismet_alerts(recent_kismet_alerts)
                last_alert_ts = int(time.time()) # Update timestamp so we don't re-process

            time.sleep(poll_interval)
    except KeyboardInterrupt:
        logger.info("Monitoring mode stopped by user.")


def main():
    parser = argparse.ArgumentParser(description="Wireless Forensics Baseline Engine")
    parser.add_argument("--learn", type=str, help="Duration to run in learning mode (e.g., '10m', '60s')")
    parser.add_argument("--monitor", action="store_true", help="Run continuously in monitoring/detection mode")
    parser.add_argument("--kismet-url", type=str, default="http://localhost:2501", help="Kismet REST API URL")
    parser.add_argument("--kismet-api-key", type=str, default="", help="Kismet API Key (if authentication is required)")
    parser.add_argument("--db-path", type=str, default="baseline.db", help="Path to the SQLite baseline database")
    
    args = parser.parse_args()
    
    logger.info("Initializing Baseline Engine...")
    baseline = BaselineEngine(db_path=args.db_path)
    
    logger.info(f"Connecting to Kismet at {args.kismet_url}...")
    kismet = KismetClient(host=args.kismet_url, api_key=args.kismet_api_key)
    
    if args.learn:
        duration_secs = parse_duration(args.learn)
        run_learning_mode(kismet, baseline, duration_secs)
        
        # If both --learn and --monitor are passed, transition automatically
        if args.monitor:
            logger.info("Transitioning to monitoring mode...")
            detector = AnomalyDetector(baseline_engine=baseline)
            run_monitoring_mode(kismet, detector)
    elif args.monitor:
        detector = AnomalyDetector(baseline_engine=baseline)
        run_monitoring_mode(kismet, detector)
    else:
        logger.warning("Please specify either --learn or --monitor (or both).")
    
    baseline.close()

if __name__ == "__main__":
    main()
