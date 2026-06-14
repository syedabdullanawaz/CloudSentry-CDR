import sqlite3
from datetime import datetime

DB_NAME = "cloudsentry_siem.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Create the incidents table with advanced enterprise fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            resource_type TEXT,
            resource_id TEXT,
            severity TEXT,
            description TEXT,
            status TEXT,
            compliance_rule TEXT,
            cost_leak REAL,
            ip_address TEXT,
            country TEXT,
            playbook_history TEXT
        )
    ''')
    
    # Create a simple settings table for storing things like Discord webhook URLs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    # Insert default settings if they don't exist
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('discord_webhook', '')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('remediation_mode', 'MANUAL')")
    
    conn.commit()
    conn.close()

def get_setting(key):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else ""

def set_setting(key, value):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def log_incident(resource_type, resource_id, severity, description, compliance_rule="", cost_leak=0.0, ip_address="", country=""):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # De-duplication check: If there's already an OPEN incident for this resource_id and type, do not log again.
    cursor.execute('''
        SELECT id FROM incidents 
        WHERE resource_id = ? AND resource_type = ? AND status = 'OPEN'
    ''', (resource_id, resource_type))
    
    existing = cursor.fetchone()
    if existing:
        conn.close()
        return False # Skipped duplicate
        
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO incidents (timestamp, resource_type, resource_id, severity, description, status, compliance_rule, cost_leak, ip_address, country, playbook_history)
        VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, 'Initialized detection.')
    ''', (timestamp, resource_type, resource_id, severity, description, compliance_rule, cost_leak, ip_address, country))
    
    conn.commit()
    conn.close()
    return True # Logged new incident

def fetch_incidents(status_filter=None):
    conn = sqlite3.connect(DB_NAME)
    # Return as list of dictionaries for easier integration
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if status_filter:
        cursor.execute("SELECT * FROM incidents WHERE status = ? ORDER BY id DESC", (status_filter,))
    else:
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC")
        
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def remediate_incident(incident_id, action_taken):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT playbook_history FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    
    if row:
        history = row[0] or ""
        new_history = f"{history}\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action_taken}"
        
        cursor.execute('''
            UPDATE incidents 
            SET status = 'RESOLVED', playbook_history = ? 
            WHERE id = ?
        ''', (new_history, incident_id))
        conn.commit()
        success = True
    else:
        success = False
        
    conn.close()
    return success

def suppress_incident(incident_id, reason="User suppressed"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT playbook_history FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    
    if row:
        history = row[0] or ""
        new_history = f"{history}\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Suppressed: {reason}"
        
        cursor.execute('''
            UPDATE incidents 
            SET status = 'SUPPRESSED', playbook_history = ? 
            WHERE id = ?
        ''', (new_history, incident_id))
        conn.commit()
        success = True
    else:
        success = False
        
    conn.close()
    return success

def resolve_stale_incidents(resource_type, active_ids):
    """
    Auto-resolve open incidents for a specific resource type if they are no longer detected.
    This provides self-healing feedback to the SOC.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Fetch all OPEN incidents for this resource type
    cursor.execute('''
        SELECT id, resource_id, playbook_history FROM incidents 
        WHERE resource_type = ? AND status = 'OPEN'
    ''', (resource_type,))
    
    open_incidents = cursor.fetchall()
    resolved_count = 0
    
    for inc_id, res_id, history in open_incidents:
        if res_id not in active_ids:
            # Resource was deleted/fixed outside the platform, resolve it
            new_history = f"{history or ''}\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Auto-resolved (Resource no longer detected in cloud scan)."
            cursor.execute('''
                UPDATE incidents 
                SET status = 'RESOLVED', playbook_history = ? 
                WHERE id = ?
            ''', (new_history, inc_id))
            resolved_count += 1
            
    if resolved_count > 0:
        conn.commit()
        print(f"[*] Auto-resolved {resolved_count} stale incidents of type '{resource_type}'")
        
    conn.close()
    return resolved_count

if __name__ == "__main__":
    init_db()
    print("[+] CloudSentry SIEM Database Initialized.")
