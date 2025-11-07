"""Main entry point for AWS Security Auditor."""
import argparse
import sys
import os
import schedule
import time
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db import db
from audit.iam_audit import run_iam_audit
from audit.s3_audit import run_s3_audit
from audit.ec2_audit import run_ec2_audit
from utils.alerts import alert_manager
from utils.config import config


def run_scan(scan_type: str, detailed: bool = False):
    """Run security scan."""
    try:
        # Validate AWS credentials
        config.validate()
        
        # Determine which scans to run
        scan_types = []
        if scan_type == "all":
            scan_types = ["iam", "s3", "ec2"]
        elif scan_type in ["iam", "s3", "ec2"]:
            scan_types = [scan_type]
        else:
            print(f"[X] Invalid scan type: {scan_type}")
            print("Valid options: iam, s3, ec2, all")
            return False
        
        print(f"\n[*] Starting {scan_type.upper()} security audit...")
        print(f"[TIME] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
        
        # Create scan record
        scan_id = db.create_scan(scan_type)
        alert_manager.log_scan_start(scan_type, scan_id)
        
        all_findings = []
        
        # Run scans
        for stype in scan_types:
            print(f"[SCAN] Running {stype.upper()} audit...")
            
            if stype == "iam":
                findings = run_iam_audit()
            elif stype == "s3":
                findings = run_s3_audit()
            elif stype == "ec2":
                findings = run_ec2_audit()
            
            # Store findings
            for finding in findings:
                db.add_finding(scan_id, finding)
            
            all_findings.extend(findings)
            print(f"   ✓ Found {len(findings)} issues in {stype.upper()}")
        
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
        
        # Print summary
        alert_manager.print_findings_summary(all_findings)
        
        # Print detailed findings if requested
        if detailed and all_findings:
            print("\n" + "="*80)
            print("[DETAILED] FINDINGS")
            print("="*80 + "\n")
            
            for i, finding in enumerate(all_findings, 1):
                print(f"{i}. [{finding['severity'].upper()}] {finding['finding_type']}")
                print(f"   Service: {finding['service']}")
                print(f"   Resource: {finding['resource_id']}")
                print(f"   Description: {finding['description']}")
                print(f"   Risk Score: {finding['risk_score']}/10")
                if finding.get('recommendation'):
                    print(f"   Recommendation: {finding['recommendation']}")
                print()
        
        # Send email alert for critical findings
        if severity_counts['critical'] > 0 or severity_counts['high'] > 0:
            print("[EMAIL] Sending email alert for critical findings...")
            alert_manager.send_email_alert(all_findings)
        
        print(f"\n[OK] Scan completed! Results saved (Scan ID: {scan_id})")
        print(f"[LOG] View logs: {config.LOG_FILE}")
        print(f"[DB] Database: {config.DATABASE_PATH}\n")
        
        return True
    
    except ValueError as e:
        print(f"\n[X] Configuration Error: {e}")
        print("Please set AWS credentials in .env file\n")
        return False
    except Exception as e:
        alert_manager.log_error("Scan failed", e)
        print(f"\n[X] Scan failed: {e}\n")
        return False


def start_api_server():
    """Start the FastAPI server."""
    print("[API] Starting API server...")
    print("[DOCS] API Documentation: http://localhost:8000/docs")
    print("[HEALTH] Health Check: http://localhost:8000/health")
    print("\nPress Ctrl+C to stop\n")
    
    import uvicorn
    from api.server import app
    
    uvicorn.run(app, host="0.0.0.0", port=8000)


def scheduled_scan(scan_type: str):
    """Run scheduled scan."""
    print(f"\n[SCHEDULED] Running scheduled {scan_type} scan...")
    run_scan(scan_type, detailed=False)


def start_scheduler(frequency: str, scan_type: str = "all"):
    """Start scheduled scans."""
    print(f"[SCHEDULER] Scheduling {scan_type} scans to run {frequency}")
    
    if frequency == "hourly":
        schedule.every().hour.do(scheduled_scan, scan_type)
    elif frequency == "daily":
        schedule.every().day.at("00:00").do(scheduled_scan, scan_type)
    elif frequency == "weekly":
        schedule.every().monday.at("00:00").do(scheduled_scan, scan_type)
    else:
        print(f"[X] Invalid frequency: {frequency}")
        print("Valid options: hourly, daily, weekly")
        return
    
    print(f"[OK] Scheduler started! Press Ctrl+C to stop")
    print(f"Next scan: {schedule.next_run()}\n")
    
    # Run initial scan
    scheduled_scan(scan_type)
    
    # Keep running
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    except KeyboardInterrupt:
        print("\n[STOP] Scheduler stopped")


def view_report(scan_id: int = None):
    """View scan report."""
    try:
        if scan_id:
            scan = db.get_scan(scan_id)
        else:
            scan = db.get_latest_scan()
        
        if not scan:
            print("[X] No scan found")
            return
        
        findings = db.get_findings(scan_id=scan['id'])
        
        print("\n" + "="*80)
        print(f"[REPORT] SCAN REPORT (ID: {scan['id']})")
        print("="*80)
        print(f"Type: {scan['scan_type']}")
        print(f"Started: {scan['start_time']}")
        print(f"Completed: {scan['end_time']}")
        print(f"Status: {scan['status']}")
        print(f"\nFindings: {len(findings)}")
        print(f"  [CRITICAL] Critical: {scan['critical_count']}")
        print(f"  [HIGH] High: {scan['high_count']}")
        print(f"  [MEDIUM] Medium: {scan['medium_count']}")
        print(f"  [LOW] Low: {scan['low_count']}")
        print("="*80 + "\n")
        
        if findings:
            print("Top Issues:\n")
            for i, finding in enumerate(findings[:10], 1):
                print(f"{i}. [{finding['severity'].upper()}] {finding['finding_type']}")
                print(f"   {finding['description']}")
                print()
    
    except Exception as e:
        print(f"[X] Failed to view report: {e}")


def view_stats():
    """View statistics."""
    try:
        stats = db.get_statistics()
        
        print("\n" + "="*80)
        print("[STATS] SECURITY STATISTICS")
        print("="*80)
        print(f"Total Scans: {stats['total_scans']}")
        print(f"Total Open Findings: {stats['total_findings']}")
        print(f"Recent Findings (7 days): {stats['recent_findings']}")
        
        print("\n[SEVERITY] Severity Breakdown:")
        for severity, count in stats['severity_counts'].items():
            print(f"  {severity.capitalize()}: {count}")
        
        print("\n[SERVICE] Service Breakdown:")
        for service, count in stats['service_counts'].items():
            print(f"  {service}: {count}")
        
        print("="*80 + "\n")
    
    except Exception as e:
        print(f"[X] Failed to view statistics: {e}")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="AWS Security Auditor - Scan for security misconfigurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full scan
  python main.py --scan all
  
  # Run specific service scan
  python main.py --scan iam
  python main.py --scan s3
  python main.py --scan ec2
  
  # Run scan with detailed output
  python main.py --scan all --detailed
  
  # Start API server
  python main.py --api
  
  # Schedule daily scans
  python main.py --schedule daily
  
  # View latest report
  python main.py --report
  
  # View statistics
  python main.py --stats
        """
    )
    
    parser.add_argument(
        '--scan',
        choices=['iam', 's3', 'ec2', 'all'],
        help='Run security scan'
    )
    
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Show detailed findings'
    )
    
    parser.add_argument(
        '--api',
        action='store_true',
        help='Start API server'
    )
    
    parser.add_argument(
        '--schedule',
        choices=['hourly', 'daily', 'weekly'],
        help='Schedule automated scans'
    )
    
    parser.add_argument(
        '--scan-type',
        default='all',
        choices=['iam', 's3', 'ec2', 'all'],
        help='Type of scan for scheduling (default: all)'
    )
    
    parser.add_argument(
        '--report',
        nargs='?',
        const=-1,
        type=int,
        help='View scan report (optionally specify scan ID)'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='View security statistics'
    )
    
    args = parser.parse_args()
    
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('database', exist_ok=True)
    
    # Print banner
    print("\n" + "="*80)
    print(" "*25 + "AWS SECURITY AUDITOR")
    print("="*80 + "\n")
    
    # Handle commands
    if args.scan:
        run_scan(args.scan, args.detailed)
    elif args.api:
        start_api_server()
    elif args.schedule:
        start_scheduler(args.schedule, args.scan_type)
    elif args.report is not None:
        scan_id = None if args.report == -1 else args.report
        view_report(scan_id)
    elif args.stats:
        view_stats()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

