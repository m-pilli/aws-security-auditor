"""Export security scan report to various formats."""
import sys
import os
import json
import csv
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db import db


def export_to_json(scan_id=None, output_file=None):
    """Export scan report to JSON."""
    if scan_id:
        scan = db.get_scan(scan_id)
    else:
        scan = db.get_latest_scan()
    
    if not scan:
        print("❌ No scan found")
        return
    
    findings = db.get_findings(scan_id=scan['id'])
    
    report = {
        'scan': scan,
        'findings': findings,
        'summary': {
            'total_findings': len(findings),
            'critical': len([f for f in findings if f['severity'] == 'critical']),
            'high': len([f for f in findings if f['severity'] == 'high']),
            'medium': len([f for f in findings if f['severity'] == 'medium']),
            'low': len([f for f in findings if f['severity'] == 'low'])
        },
        'exported_at': datetime.now().isoformat()
    }
    
    if not output_file:
        output_file = f"security_report_{scan['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"✅ Report exported to: {output_file}")


def export_to_csv(scan_id=None, output_file=None):
    """Export scan findings to CSV."""
    if scan_id:
        scan = db.get_scan(scan_id)
    else:
        scan = db.get_latest_scan()
    
    if not scan:
        print("❌ No scan found")
        return
    
    findings = db.get_findings(scan_id=scan['id'])
    
    if not output_file:
        output_file = f"security_findings_{scan['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow([
            'Severity', 'Service', 'Finding Type', 'Resource ID',
            'Resource Name', 'Risk Score', 'Description', 'Recommendation'
        ])
        
        # Findings
        for finding in findings:
            writer.writerow([
                finding['severity'],
                finding['service'],
                finding['finding_type'],
                finding['resource_id'],
                finding.get('resource_name', ''),
                finding['risk_score'],
                finding['description'],
                finding.get('recommendation', '')
            ])
    
    print(f"✅ Findings exported to: {output_file}")


def export_to_html(scan_id=None, output_file=None):
    """Export scan report to HTML."""
    if scan_id:
        scan = db.get_scan(scan_id)
    else:
        scan = db.get_latest_scan()
    
    if not scan:
        print("❌ No scan found")
        return
    
    findings = db.get_findings(scan_id=scan['id'])
    
    if not output_file:
        output_file = f"security_report_{scan['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    # Group by severity
    critical = [f for f in findings if f['severity'] == 'critical']
    high = [f for f in findings if f['severity'] == 'high']
    medium = [f for f in findings if f['severity'] == 'medium']
    low = [f for f in findings if f['severity'] == 'low']
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AWS Security Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .metric {{ display: inline-block; margin: 10px 20px; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; }}
        .critical {{ border-left-color: #d32f2f; background: #ffebee; }}
        .high {{ border-left-color: #f57c00; background: #fff3e0; }}
        .medium {{ border-left-color: #fbc02d; background: #fffde7; }}
        .low {{ border-left-color: #1976d2; background: #e3f2fd; }}
        .severity {{ font-weight: bold; }}
        .critical .severity {{ color: #d32f2f; }}
        .high .severity {{ color: #f57c00; }}
        .medium .severity {{ color: #fbc02d; }}
        .low .severity {{ color: #1976d2; }}
    </style>
</head>
<body>
    <h1>🔒 AWS Security Audit Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="metric"><strong>Scan ID:</strong> {scan['id']}</div>
        <div class="metric"><strong>Type:</strong> {scan['scan_type']}</div>
        <div class="metric"><strong>Date:</strong> {scan['start_time']}</div>
        <br>
        <div class="metric"><strong>Total Findings:</strong> {len(findings)}</div>
        <div class="metric">🔴 <strong>Critical:</strong> {len(critical)}</div>
        <div class="metric">🟠 <strong>High:</strong> {len(high)}</div>
        <div class="metric">🟡 <strong>Medium:</strong> {len(medium)}</div>
        <div class="metric">🔵 <strong>Low:</strong> {len(low)}</div>
    </div>
    """
    
    # Add findings by severity
    for severity_name, severity_findings in [
        ('Critical', critical),
        ('High', high),
        ('Medium', medium),
        ('Low', low)
    ]:
        if severity_findings:
            html += f"<h2>{severity_name} Severity Findings ({len(severity_findings)})</h2>"
            
            for finding in severity_findings:
                html += f"""
                <div class="finding {finding['severity']}">
                    <div class="severity">[{finding['severity'].upper()}] {finding['finding_type']}</div>
                    <p><strong>Service:</strong> {finding['service']}</p>
                    <p><strong>Resource:</strong> {finding['resource_id']}</p>
                    <p><strong>Risk Score:</strong> {finding['risk_score']}/10</p>
                    <p><strong>Description:</strong> {finding['description']}</p>
                    {f"<p><strong>Recommendation:</strong> {finding['recommendation']}</p>" if finding.get('recommendation') else ''}
                </div>
                """
    
    html += """
    <footer>
        <p><em>Generated by AWS Security Auditor</em></p>
    </footer>
</body>
</html>
    """
    
    with open(output_file, 'w') as f:
        f.write(html)
    
    print(f"✅ Report exported to: {output_file}")


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Export security scan report")
    parser.add_argument('--format', choices=['json', 'csv', 'html', 'all'], default='all',
                       help='Export format')
    parser.add_argument('--scan-id', type=int, help='Scan ID (default: latest)')
    parser.add_argument('--output', help='Output file name')
    
    args = parser.parse_args()
    
    print("\n📊 Exporting security report...\n")
    
    if args.format in ['json', 'all']:
        export_to_json(args.scan_id, args.output if args.format == 'json' else None)
    
    if args.format in ['csv', 'all']:
        export_to_csv(args.scan_id, args.output if args.format == 'csv' else None)
    
    if args.format in ['html', 'all']:
        export_to_html(args.scan_id, args.output if args.format == 'html' else None)
    
    print("\n✅ Export complete!\n")


if __name__ == "__main__":
    main()

