CREATE TABLE IF NOT EXISTS devices (
    mac_address TEXT PRIMARY KEY,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME,
    device_type TEXT,
    manuf TEXT
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    signal_dbm INTEGER,
    channel INTEGER,
    event_type TEXT,
    FOREIGN KEY(mac_address) REFERENCES devices(mac_address)
);
