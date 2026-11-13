import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class BaselineEngine:
    def __init__(self, db_path="baseline.db"):
        self.db_path = Path(db_path)
        self.conn = self._init_db()

    def _init_db(self):
        """Initializes the SQLite database with WAL mode for performance."""
        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        
        # Enable WAL mode for better concurrency and performance
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        
        with conn:
            # Table for Access Points
            conn.execute('''
                CREATE TABLE IF NOT EXISTS known_aps (
                    bssid TEXT PRIMARY KEY,
                    ssid TEXT,
                    channel INTEGER,
                    encryption TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table for Clients/Devices
            conn.execute('''
                CREATE TABLE IF NOT EXISTS known_clients (
                    mac TEXT PRIMARY KEY,
                    associated_bssid TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Table for Alerts (Phase 3)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    anomaly_type TEXT,
                    severity TEXT,
                    description TEXT,
                    evidence TEXT,
                    bssid TEXT,
                    client_mac TEXT
                )
            ''')
            
        return conn

    def add_or_update_ap(self, bssid, ssid=None, channel=None, encryption=None):
        """Adds a new AP or updates the last_seen time of an existing one."""
        try:
            with self.conn:
                self.conn.execute('''
                    INSERT INTO known_aps (bssid, ssid, channel, encryption)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid=coalesce(?, known_aps.ssid),
                        channel=coalesce(?, known_aps.channel),
                        encryption=coalesce(?, known_aps.encryption),
                        last_seen=CURRENT_TIMESTAMP
                ''', (bssid, ssid, channel, encryption, ssid, channel, encryption))
        except sqlite3.Error as e:
            logger.error(f"Database error updating AP {bssid}: {e}")

    def add_or_update_client(self, mac, associated_bssid=None):
        """Adds a new client or updates the last_seen time of an existing one."""
        try:
            with self.conn:
                self.conn.execute('''
                    INSERT INTO known_clients (mac, associated_bssid)
                    VALUES (?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        associated_bssid=coalesce(?, known_clients.associated_bssid),
                        last_seen=CURRENT_TIMESTAMP
                ''', (mac, associated_bssid, associated_bssid))
        except sqlite3.Error as e:
            logger.error(f"Database error updating Client {mac}: {e}")

    def get_known_aps(self):
        """Returns a list of all known access points."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM known_aps")
        return [dict(row) for row in cursor.fetchall()]

    def get_known_ssids(self):
        """Returns a list of all known SSIDs in the baseline."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT ssid FROM known_aps WHERE ssid IS NOT NULL")
        return [row['ssid'] for row in cursor.fetchall()]
        
    def get_ap_details(self, bssid):
        """Returns details for a specific known AP, or None if unknown."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM known_aps WHERE bssid = ?", (bssid,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_client_details(self, mac):
        """Returns details for a specific known client, or None if unknown."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM known_clients WHERE mac = ?", (mac,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def log_alert(self, anomaly_type, severity, description, evidence="", bssid=None, client_mac=None):
        """Logs a new alert into the alerts table."""
        try:
            with self.conn:
                self.conn.execute('''
                    INSERT INTO alerts (anomaly_type, severity, description, evidence, bssid, client_mac)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (anomaly_type, severity, description, evidence, bssid, client_mac))
        except sqlite3.Error as e:
            logger.error(f"Database error logging alert: {e}")

    def close(self):
        """Closes the database connection."""
        self.conn.close()
