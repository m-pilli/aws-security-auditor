# Database Directory

This directory contains the SQLite database for the AWS Security Auditor.

## Files

- `results.db` - SQLite database (created automatically on first scan)

## Database Schema

### Tables

**scans**
- Stores scan execution records
- Tracks start/end times
- Contains summary statistics

**findings**
- Stores individual security findings
- Links to parent scan
- Contains full finding details

## Backup

To backup your scan history:
```bash
cp database/results.db database/results_backup_$(date +%Y%m%d).db
```

## Reset

To start fresh:
```bash
rm database/results.db
# Database will be recreated on next scan
```

## Size

Database grows approximately:
- ~1KB per scan record
- ~1KB per finding
- Typical: 1-5 MB for months of scanning

## Access

You can query the database directly:
```bash
sqlite3 database/results.db

# Example queries:
SELECT * FROM scans ORDER BY start_time DESC LIMIT 10;
SELECT COUNT(*) FROM findings WHERE severity = 'critical';
```

## Privacy

Database contains AWS resource information. Keep secure and do not commit to version control.

