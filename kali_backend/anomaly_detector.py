import logging
import time

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, baseline_engine, debounce_seconds=60):
        self.baseline = baseline_engine
        self.debounce_seconds = debounce_seconds
        
        # Debounce dictionary: key -> timestamp
        self.recent_alerts = {}

    def _should_alert(self, alert_key):
        """Returns True if we should trigger the alert, based on debounce window."""
        now = time.time()
        if alert_key in self.recent_alerts:
            last_alert_time = self.recent_alerts[alert_key]
            if (now - last_alert_time) < self.debounce_seconds:
                return False # Debounced
                
        self.recent_alerts[alert_key] = now
        return True

    def process_devices(self, active_devices):
        """
        Analyzes the real-time devices list for state-based anomalies.
        """
        known_ssids = self.baseline.get_known_ssids()
        
        for dev in active_devices:
            mac = dev.get("kismet.device.base.macaddr")
            dev_type = dev.get("kismet.device.base.type")
            name = dev.get("kismet.device.base.name")
            channel = dev.get("kismet.device.base.channel")
            
            if dev_type == "Wi-Fi AP":
                # Check for Rogue AP
                if name in known_ssids:
                    ap_details = self.baseline.get_ap_details(mac)
                    if not ap_details:
                        # Known SSID, but unknown MAC/BSSID!
                        alert_key = f"rogue_ap_{name}_{mac}"
                        if self._should_alert(alert_key):
                            desc = f"Rogue Access Point detected! Broadcasting known SSID '{name}' from unknown MAC."
                            logger.warning(desc)
                            self.baseline.log_alert("Rogue_AP", "High", desc, f"SSID: {name}, Channel: {channel}", bssid=mac)
                    else:
                        # Known AP. Check channel shift.
                        expected_channel = ap_details.get("channel")
                        if expected_channel and channel and expected_channel != int(channel):
                            alert_key = f"channel_shift_{mac}"
                            if self._should_alert(alert_key):
                                desc = f"Known AP '{name}' shifted to unexpected channel {channel} (Expected {expected_channel})."
                                logger.info(desc)
                                self.baseline.log_alert("Channel_Shift", "Low", desc, f"Old: {expected_channel}, New: {channel}", bssid=mac)

            elif dev_type == "Wi-Fi Client":
                dot11 = dev.get("dot11.device", {})
                last_bssid = dot11.get("dot11.device.last_bssid", None)
                
                if last_bssid:
                    client_details = self.baseline.get_client_details(mac)
                    if client_details:
                        expected_bssid = client_details.get("associated_bssid")
                        # If the client was previously associated to a known AP, but now is on a different AP
                        if expected_bssid and expected_bssid != last_bssid:
                            alert_key = f"unexpected_assoc_{mac}_{last_bssid}"
                            if self._should_alert(alert_key):
                                desc = f"Known Client connected to unexpected BSSID {last_bssid} (Expected {expected_bssid})."
                                logger.warning(desc)
                                self.baseline.log_alert("Unexpected_Association", "Medium", desc, f"Client: {mac}", bssid=last_bssid, client_mac=mac)


    def process_kismet_alerts(self, kismet_alerts):
        """
        Analyzes the event stream from Kismet for event-based anomalies like Deauth/Brute Force.
        """
        for alert in kismet_alerts:
            # Kismet alert structure varies, but generally has a 'kismet.alert.name' or similar
            alert_name = alert.get("kismet.alert.name", "")
            alert_text = alert.get("kismet.alert.text", "")
            alert_bssid = alert.get("kismet.alert.bssid", None)
            alert_source = alert.get("kismet.alert.source_mac", None)
            
            if "DEAUTH" in alert_name.upper() or "DISASSOC" in alert_name.upper():
                alert_key = f"deauth_attack_{alert_bssid}"
                if self._should_alert(alert_key):
                    desc = f"Deauthentication/Disassociation attack detected! Details: {alert_text}"
                    logger.warning(desc)
                    self.baseline.log_alert("Deauth_Attack", "High", desc, alert_text, bssid=alert_bssid, client_mac=alert_source)
                    
            elif "BRUTE" in alert_name.upper() or "AUTHFAIL" in alert_name.upper():
                alert_key = f"brute_force_{alert_bssid}"
                if self._should_alert(alert_key):
                    desc = f"Potential Brute Force / Auth Failure detected! Details: {alert_text}"
                    logger.warning(desc)
                    self.baseline.log_alert("Brute_Force", "High", desc, alert_text, bssid=alert_bssid, client_mac=alert_source)
