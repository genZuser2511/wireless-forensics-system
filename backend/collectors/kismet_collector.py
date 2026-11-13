import requests
import sqlite3
import time
import os

KISMET_URL = "http://localhost:2501"
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'forensics.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    schema_path = os.path.join(os.path.dirname(DB_PATH), 'schema.sql')
    with open(schema_path, 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    return conn

def fetch_devices(auth_token="7AED0A40BF359C75B9D093611D398616"):
    cookies = {}
    if auth_token:
        cookies['KISMET'] = auth_token
        
    try:
        # Fetch summary of all active devices
        resp = requests.get(f"{KISMET_URL}/devices/last-time/-10/devices.json", cookies=cookies, timeout=5)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            print("[!] Kismet requires authentication. Please provide an API token.")
            return None
        else:
            print(f"[!] Error fetching devices: {resp.status_code}")
            return None
    except requests.exceptions.ConnectionError:
        print("[!] Cannot connect to Kismet. Is it running?")
        return None

def store_devices(conn, devices):
    cursor = conn.cursor()
    for dev in devices:
        mac = dev.get('kismet.device.base.macaddr')
        manuf = dev.get('kismet.device.base.manuf', 'Unknown')
        dev_type = dev.get('kismet.device.base.type', 'Unknown')
        
        # Insert or ignore device
        cursor.execute('''
            INSERT OR IGNORE INTO devices (mac_address, device_type, manuf)
            VALUES (?, ?, ?)
        ''', (mac, dev_type, manuf))
        
        # Update last seen
        cursor.execute('''
            UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE mac_address = ?
        ''', (mac,))
        
        # Log observation (for demonstration, grab strong signals)
        signal = dev.get('kismet.device.base.signal', {}).get('kismet.common.signal.last_signal', 0)
        channel = dev.get('kismet.device.base.channel', '')
        
        cursor.execute('''
            INSERT INTO observations (mac_address, signal_dbm, channel, event_type)
            VALUES (?, ?, ?, 'device_observed')
        ''', (mac, signal, channel))
        
    conn.commit()
    print(f"[+] Processed {len(devices)} devices from Kismet.")

if __name__ == '__main__':
    print("[*] Initializing database...")
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = init_db()
    
    print("[*] Starting Kismet Collector...")
    while True:
        data = fetch_devices()
        if data:
            store_devices(conn, data)
        time.sleep(5)
