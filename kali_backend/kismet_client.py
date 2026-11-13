import requests
import logging
import time

logger = logging.getLogger(__name__)

class KismetClient:
    def __init__(self, host="http://localhost:2501", api_key=""):
        self.host = host.rstrip('/')
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"KISMET": api_key})
        
        # Test connection
        try:
            self.get_system_status()
            logger.info(f"Successfully connected to Kismet at {self.host}")
        except Exception as e:
            logger.error(f"Failed to connect to Kismet: {e}")

    def get_system_status(self):
        """Check if Kismet is reachable."""
        response = self.session.get(f"{self.host}/system/status.json")
        response.raise_for_status()
        return response.json()

    def get_active_devices(self):
        """
        Fetches the list of active devices from Kismet.
        We request specific fields to optimize the API call.
        """
        # We query for specific fields to reduce payload size
        # dot11.device -> specific to Wi-Fi
        url = f"{self.host}/devices/last-time/0/devices.json"
        
        # The regex payload asks Kismet to filter or return specific fields, 
        # but for simplicity in this baseline, we can pull the summary fields.
        data = {
            "fields": [
                "kismet.device.base.macaddr",
                "kismet.device.base.type",
                "kismet.device.base.name",
                "kismet.device.base.channel",
                "kismet.device.base.crypt",
                "dot11.device/dot11.device.last_bssid"
            ]
        }
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error fetching devices from Kismet: {e}")
            return []

    def get_recent_alerts(self, since_ts=0):
        """
        Fetches alerts/events from Kismet's messagebus or alerts API.
        We'll query the /alerts/all_alerts.json endpoint.
        """
        url = f"{self.host}/alerts/all_alerts.json"
        if since_ts > 0:
            # Note: Kismet API for filtering alerts by time might require specific params
            # For simplicity, we just fetch them. In a real scenario, use time filtering.
            url = f"{self.host}/alerts/last-time/{since_ts}/alerts.json"

        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error fetching alerts from Kismet: {e}")
            return []

    def stream_alerts(self, callback):
        """
        Stub for connecting to Kismet's websocket/event stream 
        to get real-time alerts. 
        For now, this relies on periodic polling.
        """
        pass
