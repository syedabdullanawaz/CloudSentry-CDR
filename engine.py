import boto3
import requests
import json
from database import init_db, log_incident, resolve_stale_incidents, get_setting
from credential_hunter import hunt_zombie_keys, check_mfa_compliance
from resource_hunter import hunt_zombie_resources
from cloudtrail_siem import scan_cloudtrail_threats

def run_security_audit(regions=["us-east-1", "us-west-2"]):
    """
    Main orchestrator that runs audits across credentials, active resources, and CloudTrail.
    Handles auto-resolution of stale incidents and dispatches webhooks.
    """
    print("==================================================")
    print("       CloudSentry CDR Audit Execution Loop        ")
    print("==================================================")
    
    # Initialize the database to ensure tables exist
    init_db()
    
    new_incidents_count = 0
    new_alerts = []
    
    # 1. Run IAM Audit
    zombie_keys = hunt_zombie_keys()
    non_compliant_mfa = check_mfa_compliance()
    
    # Auto-resolve resolved credential issues
    # (i.e. keys that were deleted/deactivated or users who enabled MFA)
    resolve_stale_incidents("IAM Access Key", zombie_keys)
    resolve_stale_incidents("IAM User Compliance", non_compliant_mfa)
    
    # 2. Run Resource Audit (Multi-region supported!)
    active_eips = []
    active_ebs = []
    active_lbs = []
    
    for region in regions:
        region_zombies = hunt_zombie_resources(region=region)
        # Separate them by type for auto-resolution
        # We can scan the region and separate resource IDs
        # To make it simple, we just log them in resource_hunter.
        # Let's collect active IDs for auto-resolution:
        # Since hunt_zombie_resources returns all zombie IDs, we can filter them by looking at prefix/patterns or querying AWS.
        # In our resource_hunter, we added them to zombie_ids list. Let's separate EIPs vs EBS vs LBs
        for z_id in region_zombies:
            if z_id.startswith("vol-"):
                active_ebs.append(z_id)
            elif z_id.startswith("arn:aws:elasticloadbalancing"):
                active_lbs.append(z_id)
            else:
                # IPs
                active_eips.append(z_id)
                
    resolve_stale_incidents("Elastic IP", active_eips)
    resolve_stale_incidents("EBS Volume", active_ebs)
    resolve_stale_incidents("Load Balancer", active_lbs)
    
    # 3. Ingest CloudTrail Events
    scan_cloudtrail_threats(lookback_hours=24)
    
    # 4. Dispatch Alerting webhook if configured
    webhook_url = get_setting("discord_webhook")
    if webhook_url and webhook_url.strip():
        # Fetch incidents logged in this run
        # To keep it simple, we check if any new alerts are present.
        # Since database.py logs directly, we can fetch all open incidents and notify:
        dispatch_webhook_alerts(webhook_url)
        
    print("[+] CloudSentry CDR security correlation audit finished.")
    print("==================================================")

def dispatch_webhook_alerts(webhook_url):
    """
    Fetches open incidents and posts formatted alerts to the configured Discord channel.
    """
    from database import fetch_incidents
    open_incidents = fetch_incidents(status_filter="OPEN")
    
    if not open_incidents:
        return
        
    # Limit to top 5 to avoid webhook spam / rate limits
    incidents_to_send = open_incidents[:5]
    
    payload = {
        "content": "⚠️ **🚨 CLOUD DETECT-AND-RESPONSE SYSTEM ALERT 🚨** ⚠️",
        "embeds": []
    }
    
    for inc in incidents_to_send:
        # Green for LOW, Orange for MEDIUM, Red for HIGH/CRITICAL
        color_map = {
            "LOW": 3066993,      # Green
            "MEDIUM": 15105570,   # Orange
            "HIGH": 15158332,     # Red
            "CRITICAL": 10038562  # Dark Red
        }
        color = color_map.get(inc.get("severity", "MEDIUM"), 15105570)
        
        embed = {
            "title": f"Threat Found: {inc.get('resource_type')}",
            "description": inc.get("description"),
            "color": color,
            "fields": [
                {"name": "Identifier / User", "value": inc.get("resource_id"), "inline": True},
                {"name": "Compliance Check", "value": inc.get("compliance_rule") or "Custom Audit", "inline": True},
                {"name": "Severity", "value": inc.get("severity"), "inline": True}
            ],
            "footer": {
                "text": f"CloudSentry CDR • Detected at {inc.get('timestamp')}"
            }
        }
        
        # Add FinOps cost metrics if relevant
        if inc.get("cost_leak") and inc.get("cost_leak") > 0:
            embed["fields"].append({"name": "Est. Monthly Leakage", "value": f"${inc.get('cost_leak')} USD", "inline": True})
            
        payload["embeds"].append(embed)
        
    try:
        res = requests.post(webhook_url, json=payload, timeout=5)
        if res.status_code in [200, 204]:
            print("[+] Webhook alert dispatch successful.")
        else:
            print(f"[-] Webhook alert failed with code {res.status_code}: {res.text}")
    except Exception as e:
        print(f"[-] Webhook alert failed: {e}")

if __name__ == "__main__":
    run_security_audit()
