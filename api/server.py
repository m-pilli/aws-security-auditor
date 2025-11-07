"""FastAPI server for security audit API."""
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import Optional, List
from datetime import datetime
import os

from database.db import db
from audit.iam_audit import run_iam_audit
from audit.s3_audit import run_s3_audit
from audit.ec2_audit import run_ec2_audit
from utils.alerts import alert_manager


# Create FastAPI app
app = FastAPI(
    title="AWS Security Auditor API",
    description="REST API for AWS security auditing and reporting",
    version="1.0.0"
)


@app.get("/")
def root():
    """Root endpoint."""
    return {
        "message": "AWS Security Auditor API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "scan": "/scan",
            "report": "/report",
            "findings": "/findings",
            "stats": "/stats"
        }
    }


@app.get("/health")
def health_check():
    """Health check endpoint."""
    try:
        # Check database
        db.get_connection().close()
        
        # Check logs directory
        log_dir_exists = os.path.exists('logs')
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "database": "connected",
            "logs": "available" if log_dir_exists else "unavailable"
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )


@app.post("/scan")
def run_scan(
    scan_type: str = Query(
        "all",
        description="Type of scan to run: iam, s3, ec2, or all"
    )
):
    """Run a security scan."""
    try:
        scan_types = []
        
        if scan_type == "all":
            scan_types = ["iam", "s3", "ec2"]
        elif scan_type in ["iam", "s3", "ec2"]:
            scan_types = [scan_type]
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scan type: {scan_type}. Must be 'iam', 's3', 'ec2', or 'all'"
            )
        
        # Create scan record
        scan_id = db.create_scan(scan_type)
        alert_manager.log_scan_start(scan_type, scan_id)
        
        all_findings = []
        
        # Run scans
        for stype in scan_types:
            if stype == "iam":
                findings = run_iam_audit()
            elif stype == "s3":
                findings = run_s3_audit()
            elif stype == "ec2":
                findings = run_ec2_audit()
            
            # Store findings
            for finding in findings:
                db.add_finding(scan_id, finding)
                alert_manager.log_finding(finding)
            
            all_findings.extend(findings)
        
        # Calculate severity counts
        severity_counts = {
            'critical': len([f for f in all_findings if f['severity'] == 'critical']),
            'high': len([f for f in all_findings if f['severity'] == 'high']),
            'medium': len([f for f in all_findings if f['severity'] == 'medium']),
            'low': len([f for f in all_findings if f['severity'] == 'low'])
        }
        
        # Complete scan
        db.complete_scan(scan_id, len(all_findings), severity_counts)
        alert_manager.log_scan_complete(scan_type, scan_id, len(all_findings))
        
        # Send email alert for critical findings
        if severity_counts['critical'] > 0 or severity_counts['high'] > 0:
            alert_manager.send_email_alert(all_findings)
        
        return {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "status": "completed",
            "findings_count": len(all_findings),
            "severity_counts": severity_counts,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        alert_manager.log_error(f"Scan failed: {str(e)}", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/report")
def get_report(scan_id: Optional[int] = None):
    """Get scan report."""
    try:
        # Get scan details
        if scan_id:
            scan = db.get_scan(scan_id)
        else:
            scan = db.get_latest_scan()
        
        if not scan:
            raise HTTPException(status_code=404, detail="No scan found")
        
        # Get findings for this scan
        findings = db.get_findings(scan_id=scan['id'])
        
        return {
            "scan": scan,
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "critical": len([f for f in findings if f['severity'] == 'critical']),
                "high": len([f for f in findings if f['severity'] == 'high']),
                "medium": len([f for f in findings if f['severity'] == 'medium']),
                "low": len([f for f in findings if f['severity'] == 'low'])
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        alert_manager.log_error(f"Failed to get report: {str(e)}", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/findings")
def get_findings(
    service: Optional[str] = Query(None, description="Filter by service (IAM, S3, EC2)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    resolved: bool = Query(False, description="Include resolved findings")
):
    """Get findings with optional filters."""
    try:
        findings = db.get_findings(
            service=service,
            severity=severity,
            resolved=resolved
        )
        
        return {
            "findings": findings,
            "count": len(findings),
            "filters": {
                "service": service,
                "severity": severity,
                "resolved": resolved
            }
        }
    
    except Exception as e:
        alert_manager.log_error(f"Failed to get findings: {str(e)}", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
def get_statistics():
    """Get security statistics."""
    try:
        stats = db.get_statistics()
        
        return {
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        alert_manager.log_error(f"Failed to get statistics: {str(e)}", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/findings/{finding_id}/resolve")
def resolve_finding(finding_id: int):
    """Mark a finding as resolved."""
    try:
        db.resolve_finding(finding_id)
        
        return {
            "message": f"Finding {finding_id} marked as resolved",
            "finding_id": finding_id
        }
    
    except Exception as e:
        alert_manager.log_error(f"Failed to resolve finding: {str(e)}", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans")
def get_scans(limit: int = Query(10, description="Number of recent scans to return")):
    """Get recent scans."""
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scans
            ORDER BY start_time DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        conn.close()
        
        scans = [dict(zip(columns, row)) for row in rows]
        
        return {
            "scans": scans,
            "count": len(scans)
        }
    
    except Exception as e:
        alert_manager.log_error(f"Failed to get scans: {str(e)}", e)
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    
    print("Starting AWS Security Auditor API...")
    print("API Documentation: http://localhost:8000/docs")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)

