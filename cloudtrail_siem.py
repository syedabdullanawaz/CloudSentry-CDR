import boto3
import json
from datetime import datetime, timezone, timedelta
from database import log_incident
from threat_intel import enrich_ip

def scan_cloudtrail_threats(lookback_hours=24):
    """
    Ingests CloudTrail event history for the last N hours.
    Identifies brute-force console logins, security group alterations, 
    and privilege escalation events, enriching attacker IPs via Threat Intelligence.
    """
    print(f"[*] Ingesting AWS CloudTrail events for the last {lookback_hours} hours...")
    flagged_events = []
    
    try:
        client = boto3.client('cloudtrail', region_name='us-east-1')
        start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        
        response = client.lookup_events(
            StartTime=start_time,
            MaxResults=100
        )
        
        events = response.get('Events', [])
        for event in events:
            event_name = event.get('EventName')
            username = event.get('Username', 'Unknown')
            event_id = event.get('EventId')
            event_time = event.get('EventTime')
            
            # Load raw cloudtrail payload to extract Source IP & Error details
            cloudtrail_payload = json.loads(event.get('CloudTrailEvent', '{}'))
            source_ip = cloudtrail_payload.get('sourceIPAddress', '')
            error_code = cloudtrail_payload.get('errorCode', '')
            error_message = cloudtrail_payload.get('errorMessage', '')
            
            # Enrich IP address with Threat Intel if available
            intel = enrich_ip(source_ip) if source_ip else {}
            country = intel.get('country', 'Unknown')
            abuse_score = intel.get('abuse_score', 0)
            
            # SIEM Correlation Rule 1: Brute-Force Console Logins
            if event_name == 'ConsoleLogin':
                # Check if it was a failed login
                if error_code or response_status_failed(cloudtrail_payload):
                    desc = f"Failed Console Login for username '{username}' from IP {source_ip} ({country}). Intel Abuse Score: {abuse_score}%."
                    log_incident(
                        resource_type="CloudTrail Event",
                        resource_id=event_id,
                        severity="HIGH" if abuse_score < 50 else "CRITICAL",
                        description=desc,
                        compliance_rule="CIS 1.1 (Brute-Force Login Prevention)",
                        cost_leak=0.0,
                        ip_address=source_ip,
                        country=country
                    )
                    flagged_events.append(event_id)
                    
            # SIEM Correlation Rule 2: Defense Evasion (Disabling Logs)
            elif event_name in ['StopLogging', 'DeleteTrail', 'DeleteLogStream', 'UpdateTrail']:
                desc = f"Log auditing modification: User '{username}' executed '{event_name}' from IP {source_ip} ({country}). Possible defense evasion."
                log_incident(
                    resource_type="CloudTrail Event",
                    resource_id=event_id,
                    severity="CRITICAL",
                    description=desc,
                    compliance_rule="CIS 3.1 (Defense Evasion / Log Modification)",
                    cost_leak=0.0,
                    ip_address=source_ip,
                    country=country
                )
                flagged_events.append(event_id)
                
            # SIEM Correlation Rule 3: Privilege Escalation & Backdoor Accounts
            elif event_name in ['CreateUser', 'CreateAccessKey', 'AttachUserPolicy']:
                # Raise warning on admin-level alterations
                desc = f"Identity configuration change: User '{username}' executed '{event_name}' (Target user: {cloudtrail_payload.get('requestParameters', {}).get('userName', 'unknown')})."
                log_incident(
                    resource_type="CloudTrail Event",
                    resource_id=event_id,
                    severity="HIGH",
                    description=desc,
                    compliance_rule="CIS 1.16 (Privilege Escalation Control)",
                    cost_leak=0.0,
                    ip_address=source_ip,
                    country=country
                )
                flagged_events.append(event_id)
                
            # SIEM Correlation Rule 4: Data Exposure (Public S3 Buckets)
            elif event_name in ['PutBucketPolicy', 'PutBucketAcl', 'DeletePublicAccessBlock']:
                desc = f"Public exposure risk: User '{username}' modified permissions on S3 bucket. Verifying security posture..."
                log_incident(
                    resource_type="CloudTrail Event",
                    resource_id=event_id,
                    severity="HIGH",
                    description=desc,
                    compliance_rule="CIS 2.1 (S3 Data Exposure Mitigation)",
                    cost_leak=0.0,
                    ip_address=source_ip,
                    country=country
                )
                flagged_events.append(event_id)
                
    except Exception as e:
        print(f"[-] CloudTrail threat ingestion scan error: {e}")
        
    return flagged_events

def response_status_failed(payload):
    """Checks if the console login response indicates failure."""
    response_elements = payload.get('responseElements', {})
    if response_elements and response_elements.get('ConsoleLogin') == 'Failure':
        return True
    return False

if __name__ == "__main__":
    # Test scan locally
    print(scan_cloudtrail_threats())
