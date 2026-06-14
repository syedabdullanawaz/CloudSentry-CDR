from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import os
import boto3
import database
import engine
import mock_generator

app = FastAPI(
    title="CloudSentry CDR API",
    description="Backend API services for Cloud Detection & Response platform",
    version="1.0.0"
)

# ----------------------------------------------------
# 1. SCHEMAS
# ----------------------------------------------------
class SettingsUpdate(BaseModel):
    discord_webhook: str
    remediation_mode: str

class RemediationRequest(BaseModel):
    action: str
    dry_run: bool

class SuppressionRequest(BaseModel):
    reason: str

# ----------------------------------------------------
# 2. ENDPOINTS
# ----------------------------------------------------

@app.get("/api/incidents")
def get_incidents(status: str = None):
    try:
        incidents = database.fetch_incidents(status_filter=status)
        return incidents
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan")
def trigger_scan(background_tasks: BackgroundTasks):
    """
    Triggers an asynchronous scan of the AWS environment to keep the API responsive.
    """
    try:
        background_tasks.add_task(engine.run_security_audit)
        return {"status": "success", "message": "Cloud audit execution started in background."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/seed")
def seed_database():
    try:
        mock_generator.inject_mock_data()
        return {"status": "success", "message": "Mock telemetry successfully injected into SIEM database."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/settings")
def get_settings():
    try:
        return {
            "discord_webhook": database.get_setting("discord_webhook") or "",
            "remediation_mode": database.get_setting("remediation_mode") or "MANUAL"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/settings")
def update_settings(settings: SettingsUpdate):
    try:
        database.set_setting("discord_webhook", settings.discord_webhook)
        database.set_setting("remediation_mode", settings.remediation_mode)
        return {"status": "success", "message": "Configuration settings saved."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/remediate/{incident_id}")
def execute_remediation(incident_id: int, req: RemediationRequest):
    """
    Triggers the active response playbook. Can be simulated (dry run) or live against AWS.
    """
    try:
        incidents = database.fetch_incidents()
        match = next((i for i in incidents if i['id'] == incident_id), None)
        if not match:
            raise HTTPException(status_code=404, detail="Incident not found.")
            
        res_type = match['resource_type']
        res_id = match['resource_id']
        desc = match['description']
        
        action_note = f"Executed Playbook: {req.action}"
        
        if req.dry_run:
            action_note += " (Dry Run - Simulated execution in database)"
            database.remediate_incident(incident_id, action_note)
            return {"status": "success", "message": f"Dry Run completed. Simulated remediation of '{res_id}'."}
            
        # Live AWS active remediation
        if res_type == "IAM Access Key":
            # Extract username
            username = "unknown"
            if "User '" in desc:
                username = desc.split("User '")[1].split("'")[0]
            if username == "unknown":
                raise HTTPException(status_code=400, detail="Unable to parse IAM username from incident description.")
                
            iam = boto3.client('iam')
            iam.update_access_key(UserName=username, AccessKeyId=res_id, Status='Inactive')
            action_note += f" (Live Action: Access key {res_id} deactivated for user {username})"
            
        elif res_type == "Elastic IP":
            ec2 = boto3.client('ec2')
            addrs = ec2.describe_addresses(PublicIps=[res_id]).get('Addresses', [])
            if not addrs:
                raise HTTPException(status_code=400, detail="Allocation ID not found for Elastic IP.")
            alloc_id = addrs[0].get('AllocationId')
            ec2.release_address(AllocationId=alloc_id)
            action_note += f" (Live Action: Released Elastic IP address {res_id})"
            
        elif res_type == "EBS Volume":
            ec2 = boto3.client('ec2')
            # Create snapshot backup
            snap = ec2.create_snapshot(VolumeId=res_id, Description=f"CloudSentry Quarantine backup for {res_id}")
            # Delete volume
            ec2.delete_volume(VolumeId=res_id)
            action_note += f" (Live Action: Deleted EBS Volume {res_id}. Snapshot created: {snap.get('SnapshotId')})"
            
        else:
            action_note += " (Manual intervention logged)"
            
        database.remediate_incident(incident_id, action_note)
        return {"status": "success", "message": f"Remediation executed successfully for resource '{res_id}'."}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AWS Remediation Error: {str(e)}")

@app.post("/api/suppress/{incident_id}")
def suppress_alert(incident_id: int, req: SuppressionRequest):
    try:
        success = database.suppress_incident(incident_id, reason=req.reason)
        if not success:
            raise HTTPException(status_code=404, detail="Incident not found.")
        return {"status": "success", "message": f"Incident #{incident_id} successfully suppressed."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ----------------------------------------------------
# 3. STATIC FILES & MAIN PAGE ROUTING
# ----------------------------------------------------

# Mount static folder for CSS, JS, and Images
# Create static directory dynamically if it doesn't exist
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def get_dashboard():
    """Serves the main single page dashboard interface."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse(
        status_code=404, 
        content={"message": "Frontend static files index.html not found. Place static assets in /static folder."}
    )

if __name__ == "__main__":
    import uvicorn
    database.init_db()
    print("[*] Starting CloudSentry CDR Web App local server at http://localhost:8000")
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)
