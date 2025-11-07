"""Alerting and logging utilities."""
import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict
from utils.config import config


class AlertManager:
    """Manage alerts and logging for security findings."""
    
    def __init__(self):
        """Initialize alert manager."""
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging."""
        # Create logs directory if it doesn't exist
        os.makedirs(config.LOG_DIR, exist_ok=True)
        
        # Configure logger
        self.logger = logging.getLogger('security_auditor')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(config.LOG_FILE)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log_finding(self, finding: Dict):
        """Log a security finding."""
        severity = finding['severity'].upper()
        message = (
            f"[{severity}] {finding['service']} - {finding['finding_type']}: "
            f"{finding['description']} (Risk Score: {finding['risk_score']})"
        )
        
        if severity in ['CRITICAL', 'HIGH']:
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def log_scan_start(self, scan_type: str, scan_id: int):
        """Log scan start."""
        self.logger.info(f"Starting {scan_type} scan (ID: {scan_id})")
    
    def log_scan_complete(self, scan_type: str, scan_id: int, findings_count: int):
        """Log scan completion."""
        self.logger.info(
            f"Completed {scan_type} scan (ID: {scan_id}) - "
            f"Found {findings_count} issues"
        )
    
    def log_error(self, message: str, error: Exception = None):
        """Log an error."""
        if error:
            self.logger.error(f"{message}: {str(error)}")
        else:
            self.logger.error(message)
    
    def send_email_alert(self, findings: List[Dict]):
        """Send email alert for critical findings."""
        if not config.ALERT_EMAIL or not config.SMTP_USERNAME or not config.SMTP_PASSWORD:
            self.logger.warning("Email configuration not set, skipping email alert")
            return False
        
        try:
            # Filter critical and high severity findings
            critical_findings = [
                f for f in findings 
                if f['severity'] in ['critical', 'high']
            ]
            
            if not critical_findings:
                return False
            
            # Create email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"Security Alert: {len(critical_findings)} Critical Issues Found"
            msg['From'] = config.SMTP_USERNAME
            msg['To'] = config.ALERT_EMAIL
            
            # Email body
            body = self._create_email_body(critical_findings)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT) as server:
                server.starttls()
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent to {config.ALERT_EMAIL}")
            return True
        
        except Exception as e:
            self.log_error("Failed to send email alert", e)
            return False
    
    def _create_email_body(self, findings: List[Dict]) -> str:
        """Create HTML email body."""
        html = f"""
        <html>
          <head>
            <style>
              body {{ font-family: Arial, sans-serif; }}
              .critical {{ color: #d32f2f; }}
              .high {{ color: #f57c00; }}
              .finding {{ margin: 15px 0; padding: 10px; border-left: 4px solid #ccc; }}
              .finding.critical {{ border-left-color: #d32f2f; }}
              .finding.high {{ border-left-color: #f57c00; }}
            </style>
          </head>
          <body>
            <h2>AWS Security Audit Alert</h2>
            <p>Found {len(findings)} critical security issues requiring attention:</p>
        """
        
        for finding in findings:
            severity_class = finding['severity']
            html += f"""
            <div class="finding {severity_class}">
              <h3 class="{severity_class}">[{finding['severity'].upper()}] {finding['finding_type']}</h3>
              <p><strong>Service:</strong> {finding['service']}</p>
              <p><strong>Resource:</strong> {finding['resource_id']}</p>
              <p><strong>Description:</strong> {finding['description']}</p>
              <p><strong>Risk Score:</strong> {finding['risk_score']}/10</p>
              {f"<p><strong>Recommendation:</strong> {finding.get('recommendation', '')}</p>" if finding.get('recommendation') else ''}
            </div>
            """
        
        html += """
          </body>
        </html>
        """
        
        return html
    
    def print_findings_summary(self, findings: List[Dict]):
        """Print a formatted summary of findings to console."""
        if not findings:
            print("\n[OK] No security issues found!")
            return
        
        # Group by severity
        severity_groups = {}
        for finding in findings:
            severity = finding['severity']
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(finding)
        
        # Print summary
        print("\n" + "="*80)
        print(f"[AUDIT] SECURITY AUDIT SUMMARY - {len(findings)} Issues Found")
        print("="*80)
        
        severity_order = ['critical', 'high', 'medium', 'low']
        severity_icons = {
            'critical': '[CRITICAL]',
            'high': '[HIGH]',
            'medium': '[MEDIUM]',
            'low': '[LOW]'
        }
        
        for severity in severity_order:
            if severity in severity_groups:
                items = severity_groups[severity]
                print(f"\n{severity_icons[severity]} {severity.upper()}: {len(items)} issues")
                
                for i, finding in enumerate(items[:5], 1):  # Show first 5
                    print(f"  {i}. [{finding['service']}] {finding['finding_type']}")
                    print(f"     {finding['description']}")
                    print(f"     Risk Score: {finding['risk_score']}/10")
                
                if len(items) > 5:
                    print(f"  ... and {len(items) - 5} more")
        
        print("\n" + "="*80)
        print("[INFO] Run with --detailed for full report or check the dashboard")
        print("="*80 + "\n")


# Global alert manager instance
alert_manager = AlertManager()

