import boto3
from database import log_incident

def hunt_zombie_resources(region="us-east-1"):
    """
    Scans the given region for orphaned infrastructure assets:
    - Unattached Elastic IPs
    - Detached EBS Volumes
    - Empty/Idle Load Balancers
    Reports them to the SIEM database with FinOps cost leak details.
    """
    print(f"[*] Scanning region '{region}' for Zombie Resources...")
    zombie_ids = []
    
    # 1. Unattached Elastic IPs Scan
    try:
        ec2 = boto3.client('ec2', region_name=region)
        addresses = ec2.describe_addresses().get('Addresses', [])
        
        for addr in addresses:
            # An Elastic IP is unattached if it has no association ID or instance ID
            if 'InstanceId' not in addr and 'AssociationId' not in addr:
                public_ip = addr['PublicIp']
                description = f"Orphaned Elastic IP ({public_ip}) found in {region}. No EC2 server associated."
                
                # AWS charges approx $0.005 per hour for unattached Elastic IPs ($3.60/month)
                log_incident(
                    resource_type="Elastic IP",
                    resource_id=public_ip,
                    severity="LOW",
                    description=description,
                    compliance_rule="FinOps (Unused Network Resource)",
                    cost_leak=3.60
                )
                zombie_ids.append(public_ip)
                
    except Exception as e:
        print(f"[-] Elastic IP scan error in {region}: {e}")

    # 2. Detached EBS Volumes Scan
    try:
        ec2 = boto3.client('ec2', region_name=region)
        # Detached volumes have a state of 'available' (attached ones are 'in-use')
        volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}]).get('Volumes', [])
        
        for vol in volumes:
            vol_id = vol['VolumeId']
            size_gb = vol['Size']
            vol_type = vol['VolumeType']
            
            # Estimate monthly storage cost based on standard AWS gp3 rates ($0.08 per GB-month)
            monthly_cost = round(size_gb * 0.08, 2)
            
            description = f"Detached EBS Volume ({vol_id}) of size {size_gb}GB ({vol_type}) found sitting idle in {region}."
            log_incident(
                resource_type="EBS Volume",
                resource_id=vol_id,
                severity="MEDIUM",
                description=description,
                compliance_rule="FinOps (Idle Storage Volume)",
                cost_leak=monthly_cost
            )
            zombie_ids.append(vol_id)
            
    except Exception as e:
        print(f"[-] EBS Volume scan error in {region}: {e}")

    # 3. Empty Load Balancers Scan
    try:
        elbv2 = boto3.client('elbv2', region_name=region)
        lbs = elbv2.describe_load_balancers().get('LoadBalancers', [])
        
        for lb in lbs:
            lb_arn = lb['LoadBalancerArn']
            lb_name = lb['LoadBalancerName']
            
            # Retrieve target groups linked to this load balancer
            tgs = elbv2.describe_target_groups(LoadBalancerArn=lb_arn).get('TargetGroups', [])
            
            has_active_backends = False
            for tg in tgs:
                tg_arn = tg['TargetGroupArn']
                # Check targets status in this group
                health_response = elbv2.describe_target_health(TargetGroupArn=tg_arn)
                targets_health = health_response.get('TargetHealthDescriptions', [])
                if len(targets_health) > 0:
                    has_active_backends = True
                    break
            
            if not has_active_backends:
                # Idle load balancer costing a base fee (~$18/month minimum)
                description = f"Load Balancer '{lb_name}' in {region} has no active backend targets configured."
                log_incident(
                    resource_type="Load Balancer",
                    resource_id=lb_arn,
                    severity="MEDIUM",
                    description=description,
                    compliance_rule="FinOps (Idle Load Balancer)",
                    cost_leak=18.00
                )
                zombie_ids.append(lb_arn)
                
    except Exception as e:
        # Load balancer service might be unused / return empty, handle gracefully
        # If API is disabled or throws error, do not break the scanner
        pass
        
    return zombie_ids

if __name__ == "__main__":
    # Test scan locally
    print(hunt_zombie_resources(region="us-east-1"))
