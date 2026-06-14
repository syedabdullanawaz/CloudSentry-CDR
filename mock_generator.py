import sqlite3
from datetime import datetime, timedelta

DB_NAME = "cloudsentry_siem.db"

def inject_mock_data():
    """
    Seeds the SQLite database with high-fidelity, realistic enterprise-level alerts
    representing both cybersecurity threats and FinOps cost leakages.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # We want to clear existing mock alerts to prevent duplicates during demo runs,
    # but only those that were generated as mock data.
    # We will insert them with a unique marker in the playbook_history.
    
    now = datetime.now()
    
    mock_threats = [
        # 1. Leaked IAM Key (CRITICAL Security Threat)
        (
            (now - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S"),
            "IAM Access Key",
            "AKIAIOSFODNN7COMPROMISED",
            "CRITICAL",
            "Compromised Credentials: Active Access Key leaked publicly on GitHub repository 'github.com/cloudsentry/test-repo' (Commit: 8ba3df4). Compromise signature matched threat feed signature.",
            "OPEN",
            "CIS 1.14 (Access Key Rotation)",
            0.0,
            "192.30.255.113", # GitHub IP
            "United States",
            "Initialized detection. [Threat Intel] Leaked key alert triggered via git-hound scraper."
        ),
        
        # 2. Brute-Force Console Login (HIGH Security Threat)
        (
            (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "CloudTrail Log Alert",
            "ConsoleLogin-BruteForce",
            "HIGH",
            "Brute Force Attempt: 8 failed login attempts detected in 90 seconds for username 'admin'. Threat intelligence database matched source IP with known malicious SSH scanner.",
            "OPEN",
            "CIS 1.1 (Root / Console Login Access)",
            0.0,
            "185.156.74.56",
            "Russia",
            "Initialized detection. [Threat Intel] IP matches active brute-force list on AbuseIPDB."
        ),
        
        # 3. Public S3 Bucket Data Exposure (HIGH Security Threat)
        (
            (now - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S"),
            "S3 Bucket Policy",
            "arn:aws:s3:::cloudsentry-production-financials",
            "HIGH",
            "Data Exposure Risk: S3 bucket permissions modified from Private to Publicly Accessible. Block Public Access settings were disabled by User 'contractor-dev'.",
            "OPEN",
            "CIS 2.1 (S3 Bucket Public Access Block)",
            0.0,
            "45.89.231.12",
            "Netherlands",
            "Initialized detection. Bucket policy audit failed compliance checks."
        ),
        
        # 4. Detached EBS Volumes (MEDIUM FinOps Wastes)
        (
            (now - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "EBS Volume",
            "vol-0a3bc7ef88d92cb6",
            "MEDIUM",
            "FinOps Alert: Detached GP3 block storage volume (500GB) has been sitting idle in 'available' status for 45 days. Accumulating cost leaks.",
            "OPEN",
            "FinOps (Idle Storage Volume)",
            40.00, # 500GB * $0.08 = $40.00 / month
            "",
            "",
            "Initialized detection. Volume status is detached."
        ),
        
        # 5. Orphaned Elastic IP (LOW FinOps Waste)
        (
            (now - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S"),
            "Elastic IP",
            "54.210.14.88",
            "LOW",
            "FinOps Alert: Orphaned Elastic IP found in region us-east-1. Elastic IP is allocated but not associated with any active network interfaces.",
            "OPEN",
            "FinOps (Unused Network Resource)",
            3.60, # AWS charge for unattached IP
            "",
            "",
            "Initialized detection. IP address status is unassociated."
        ),
        
        # 6. Compliance Deviation (MEDIUM Security Threat)
        (
            (now - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S"),
            "IAM User Compliance",
            "junior-engineer",
            "MEDIUM",
            "MFA Compliance Audit: User 'junior-engineer' has active Console Login enabled but Multi-Factor Authentication (MFA) is not configured.",
            "OPEN",
            "CIS 1.2 (User MFA Configuration)",
            0.0,
            "",
            "",
            "Initialized detection. MFA state parsed from credentials report."
        )
    ]
    
    # Clean previous mock entries to avoid cluttering the database with identical duplicates
    cursor.execute("DELETE FROM incidents WHERE playbook_history LIKE '%git-hound%' OR playbook_history LIKE '%AbuseIPDB%'")
    
    cursor.executemany('''
        INSERT INTO incidents (timestamp, resource_type, resource_id, severity, description, status, compliance_rule, cost_leak, ip_address, country, playbook_history)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', mock_threats)
    
    conn.commit()
    conn.close()
    print("[+] Enterprise mock security telemetry data successfully injected.")

if __name__ == "__main__":
    inject_mock_data()
