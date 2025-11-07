"""Database utilities for storing scan results."""
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional
from utils.config import config


class Database:
    """SQLite database manager for security audit results."""
    
    def __init__(self, db_path: str = None):
        """Initialize database connection."""
        self.db_path = db_path or config.DATABASE_PATH
        self.init_database()
    
    def get_connection(self):
        """Get database connection."""
        return sqlite3.connect(self.db_path)
    
    def init_database(self):
        """Initialize database schema."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                status TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0
            )
        ''')
        
        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                resource_name TEXT,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                description TEXT NOT NULL,
                recommendation TEXT,
                details TEXT,
                created_at TEXT NOT NULL,
                resolved BOOLEAN DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_id ON findings(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_service ON findings(service)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_resolved ON findings(resolved)')
        
        conn.commit()
        conn.close()
    
    def create_scan(self, scan_type: str) -> int:
        """Create a new scan record."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (scan_type, start_time, status)
            VALUES (?, ?, ?)
        ''', (scan_type, datetime.now().isoformat(), 'running'))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
    
    def complete_scan(self, scan_id: int, findings_count: int, severity_counts: Dict[str, int]):
        """Mark scan as completed."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE scans
            SET end_time = ?,
                status = ?,
                findings_count = ?,
                critical_count = ?,
                high_count = ?,
                medium_count = ?,
                low_count = ?
            WHERE id = ?
        ''', (
            datetime.now().isoformat(),
            'completed',
            findings_count,
            severity_counts.get('critical', 0),
            severity_counts.get('high', 0),
            severity_counts.get('medium', 0),
            severity_counts.get('low', 0),
            scan_id
        ))
        
        conn.commit()
        conn.close()
    
    def add_finding(self, scan_id: int, finding: Dict):
        """Add a finding to the database."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO findings (
                scan_id, service, resource_id, resource_name,
                finding_type, severity, risk_score, description,
                recommendation, details, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            finding['service'],
            finding['resource_id'],
            finding.get('resource_name', ''),
            finding['finding_type'],
            finding['severity'],
            finding['risk_score'],
            finding['description'],
            finding.get('recommendation', ''),
            json.dumps(finding.get('details', {})),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def get_scan(self, scan_id: int) -> Optional[Dict]:
        """Get scan details."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))
    
    def get_latest_scan(self, scan_type: str = None) -> Optional[Dict]:
        """Get the most recent scan."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if scan_type:
            cursor.execute('''
                SELECT * FROM scans 
                WHERE scan_type = ?
                ORDER BY start_time DESC 
                LIMIT 1
            ''', (scan_type,))
        else:
            cursor.execute('''
                SELECT * FROM scans 
                ORDER BY start_time DESC 
                LIMIT 1
            ''')
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))
    
    def get_findings(self, scan_id: int = None, service: str = None, 
                     severity: str = None, resolved: bool = False) -> List[Dict]:
        """Get findings with optional filters."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM findings WHERE 1=1'
        params = []
        
        if scan_id:
            query += ' AND scan_id = ?'
            params.append(scan_id)
        
        if service:
            query += ' AND service = ?'
            params.append(service)
        
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
        
        query += ' AND resolved = ?'
        params.append(1 if resolved else 0)
        
        query += ' ORDER BY risk_score DESC, created_at DESC'
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        
        conn.close()
        
        findings = []
        for row in rows:
            finding = dict(zip(columns, row))
            # Parse JSON details
            if finding.get('details'):
                finding['details'] = json.loads(finding['details'])
            findings.append(finding)
        
        return findings
    
    def get_statistics(self) -> Dict:
        """Get overall security statistics."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Total scans
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]
        
        # Total findings (unresolved)
        cursor.execute('SELECT COUNT(*) FROM findings WHERE resolved = 0')
        total_findings = cursor.fetchone()[0]
        
        # Severity breakdown
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM findings 
            WHERE resolved = 0
            GROUP BY severity
        ''')
        severity_counts = dict(cursor.fetchall())
        
        # Service breakdown
        cursor.execute('''
            SELECT service, COUNT(*) 
            FROM findings 
            WHERE resolved = 0
            GROUP BY service
        ''')
        service_counts = dict(cursor.fetchall())
        
        # Recent findings
        cursor.execute('''
            SELECT COUNT(*) 
            FROM findings 
            WHERE resolved = 0
            AND created_at >= datetime('now', '-7 days')
        ''')
        recent_findings = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'total_findings': total_findings,
            'severity_counts': severity_counts,
            'service_counts': service_counts,
            'recent_findings': recent_findings
        }
    
    def resolve_finding(self, finding_id: int):
        """Mark a finding as resolved."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('UPDATE findings SET resolved = 1 WHERE id = ?', (finding_id,))
        
        conn.commit()
        conn.close()


# Global database instance
db = Database()

