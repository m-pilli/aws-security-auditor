# Security Alerts Log Directory

This directory contains application logs for the AWS Security Auditor.

## Files

- `security_alerts.log` - Main application log (created automatically)
  - Security findings
  - Scan operations
  - Errors and warnings
  - System events

## Log Format

```
2024-01-15 10:30:45,123 - security_auditor - WARNING - [CRITICAL] S3 - Public Access Not Fully Blocked: S3 bucket my-bucket does not have all public access blocks enabled (Risk Score: 9)
```

## Retention

Logs are appended indefinitely. You may want to:
- Archive old logs periodically
- Rotate logs using a tool like `logrotate`
- Clear logs manually: `rm security_alerts.log`

## Privacy

Logs contain AWS resource information. Do not share logs publicly as they may contain:
- Resource names and IDs
- AWS account information
- Security configuration details

