import boto3
from datetime import datetime, timezone
from database import log_incident

def hunt_zombie_keys():
    """
    Scans for active access keys that are unused for > 90 days (Dormant)
    or have NEVER been used since creation.
    """
    print("[*] Scanning IAM for Zombie Credentials...")
    zombies_found = []
    
    try:
        iam = boto3.client('iam')
        # Paginate through users to support large environments (enterprise-grade)
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            users = page['Users']
            for user in users:
                username = user['UserName']
                
                # Fetch access keys for this user
                keys_response = iam.list_access_keys(UserName=username)
                access_keys = keys_response.get('AccessKeyMetadata', [])
                
                for key in access_keys:
                    key_id = key['AccessKeyId']
                    status = key['Status']
                    
                    if status == 'Active':
                        # Fetch key usage statistics
                        usage = iam.get_access_key_last_used(AccessKeyId=key_id)
                        last_used_info = usage.get('AccessKeyLastUsed', {})
                        
                        if 'LastUsedDate' in last_used_info:
                            last_used_date = last_used_info['LastUsedDate']
                            age_days = (datetime.now(timezone.utc) - last_used_date).days
                            
                            if age_days > 90:
                                description = f"IAM User '{username}' has an active access key ({key_id}) unused for {age_days} days."
                                log_incident(
                                    resource_type="IAM Access Key",
                                    resource_id=key_id,
                                    severity="HIGH",
                                    description=description,
                                    compliance_rule="CIS 1.14 (Access Key Rotation)",
                                    cost_leak=0.0 # Credentials don't cost money directly, but represent high security risk
                                )
                                zombies_found.append(key_id)
                        else:
                            # Key exists but has never been used
                            description = f"IAM User '{username}' has an active access key ({key_id}) that has NEVER been used since creation."
                            log_incident(
                                resource_type="IAM Access Key",
                                resource_id=key_id,
                                severity="CRITICAL",
                                description=description,
                                compliance_rule="CIS 1.14 (Access Key Deactivation)",
                                cost_leak=0.0
                            )
                            zombies_found.append(key_id)
                            
    except Exception as e:
        print(f"[-] IAM Credential scan error: {e}")
        
    return zombies_found

def check_mfa_compliance():
    """
    Generates and downloads the credential report to verify MFA compliance.
    """
    print("[*] Generating credential report to check MFA compliance...")
    non_compliant_users = []
    
    try:
        iam = boto3.client('iam')
        
        # Request credential report generation
        print("  Requesting credential report...")
        while True:
            report_status = iam.generate_credential_report()
            if report_status.get('State') == 'COMPLETE':
                break
        
        # Fetch the report
        report_response = iam.get_credential_report()
        content = report_response.get('Content', b'').decode('utf-8')
        
        lines = content.split('\n')
        if not lines or len(lines) < 2:
            return non_compliant_users
            
        headers = lines[0].split(',')
        
        # Get column indexes for username, password_enabled, and mfa_active
        try:
            user_idx = headers.index('user')
            password_idx = headers.index('password_enabled')
            mfa_idx = headers.index('mfa_active')
        except ValueError as ve:
            print(f"[-] Missing standard columns in AWS credential report: {ve}")
            return non_compliant_users
            
        for line in lines[1:]:
            if not line.strip():
                continue
            fields = line.split(',')
            
            # Avoid list index errors
            if len(fields) <= max(user_idx, password_idx, mfa_idx):
                continue
                
            username = fields[user_idx]
            password_enabled = fields[password_idx]
            mfa_active = fields[mfa_idx]
            
            # Root account check
            if username == '<root_account>':
                if mfa_active == 'false':
                    log_incident(
                        resource_type="IAM Account Compliance",
                        resource_id="<root_account>",
                        severity="CRITICAL",
                        description="MFA is disabled for AWS Root Account. Highly vulnerable!",
                        compliance_rule="CIS 1.1 (Root MFA Enabled)",
                        cost_leak=0.0
                    )
                    non_compliant_users.append(username)
            # Normal IAM User checks
            elif password_enabled == 'true' and mfa_active == 'false':
                description = f"IAM User '{username}' has console login active but MFA is disabled."
                log_incident(
                    resource_type="IAM User Compliance",
                    resource_id=username,
                    severity="HIGH",
                    description=description,
                    compliance_rule="CIS 1.2 (User MFA Enabled)",
                    cost_leak=0.0
                )
                non_compliant_users.append(username)
                
    except Exception as e:
        print(f"[-] MFA compliance audit error: {e}")
        
    return non_compliant_users

if __name__ == "__main__":
    # Test local scan if AWS configured
    print(hunt_zombie_keys())
    print(check_mfa_compliance())
