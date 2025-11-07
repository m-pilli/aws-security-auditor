# Testing Checklist

Use this checklist to verify your AWS Security Auditor is working correctly.

## ✅ Initial Setup

- [ ] Python 3.8+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] AWS account created
- [ ] IAM user created with SecurityAudit policy
- [ ] `.env` file created with credentials
- [ ] AWS connection tested (`python quick_start.py`)

## ✅ Basic Functionality

### Command Line Interface
- [ ] Help works: `python main.py --help`
- [ ] Full scan works: `python main.py --scan all`
- [ ] IAM scan works: `python main.py --scan iam`
- [ ] S3 scan works: `python main.py --scan s3`
- [ ] EC2 scan works: `python main.py --scan ec2`
- [ ] Detailed output works: `python main.py --scan all --detailed`

### Reports and Statistics
- [ ] View report: `python main.py --report`
- [ ] View stats: `python main.py --stats`
- [ ] Logs created in `logs/security_alerts.log`
- [ ] Database created in `database/results.db`

## ✅ API Server

- [ ] API starts: `python main.py --api`
- [ ] Health check: http://localhost:8000/health
- [ ] API docs: http://localhost:8000/docs
- [ ] Run scan via API: `curl -X POST "http://localhost:8000/scan?scan_type=all"`
- [ ] Get report: `curl http://localhost:8000/report`
- [ ] Get findings: `curl http://localhost:8000/findings`
- [ ] Get stats: `curl http://localhost:8000/stats`

## ✅ Dashboard

- [ ] Dashboard starts: `streamlit run dashboard/app.py`
- [ ] Dashboard loads: http://localhost:8501
- [ ] Overview page shows data
- [ ] Findings page shows findings
- [ ] Can filter findings by service
- [ ] Can filter findings by severity
- [ ] Trends page shows charts (after multiple scans)
- [ ] Recommendations page shows recommendations

## ✅ Scheduled Scans

- [ ] Hourly schedule works: `python main.py --schedule hourly`
- [ ] Daily schedule works: `python main.py --schedule daily`
- [ ] Can specify scan type: `python main.py --schedule daily --scan-type iam`
- [ ] Runs initial scan immediately
- [ ] Shows next scheduled run time
- [ ] Can stop with Ctrl+C

## ✅ Audit Modules

### IAM Auditor
- [ ] Checks root account MFA
- [ ] Detects users without MFA
- [ ] Identifies admin users
- [ ] Finds unused access keys
- [ ] Checks password policy
- [ ] Detects overly permissive policies
- [ ] Identifies inline policies

### S3 Auditor
- [ ] Checks public access blocks
- [ ] Detects unencrypted buckets
- [ ] Checks versioning
- [ ] Checks logging
- [ ] Detects public bucket policies
- [ ] Detects public ACLs

### EC2 Auditor
- [ ] Detects open security groups
- [ ] Identifies critical ports open to internet
- [ ] Checks for missing tags
- [ ] Detects instances with public IPs
- [ ] Checks for IMDSv1
- [ ] Checks for unencrypted volumes
- [ ] Detects public snapshots

## ✅ Features

### Database
- [ ] Scans are stored in database
- [ ] Findings are stored with details
- [ ] Can retrieve historical scans
- [ ] Statistics are calculated correctly
- [ ] Can mark findings as resolved

### Alerting
- [ ] Findings are logged to file
- [ ] Console output is formatted nicely
- [ ] Email alerts work (if configured)
- [ ] Severity-based filtering works

### Export
- [ ] Export to JSON: `python examples/export_report.py --format json`
- [ ] Export to CSV: `python examples/export_report.py --format csv`
- [ ] Export to HTML: `python examples/export_report.py --format html`
- [ ] Can export specific scan: `python examples/export_report.py --scan-id 1`

## ✅ Docker (Optional)

- [ ] Docker image builds: `docker build -t security-auditor .`
- [ ] Can run scan in container: `docker run security-auditor python main.py --scan all`
- [ ] Docker Compose builds: `docker-compose build`
- [ ] All services start: `docker-compose up -d`
- [ ] API accessible: http://localhost:8000
- [ ] Dashboard accessible: http://localhost:8501
- [ ] Logs are persisted
- [ ] Database is persisted

## ✅ Test Resources (Optional)

- [ ] Can create test resources: `python examples/create_test_resources.py`
- [ ] Test bucket is created
- [ ] Test IAM user is created
- [ ] Test security group is created
- [ ] Scan detects test issues
- [ ] Can clean up test resources

## ✅ Error Handling

- [ ] Graceful error on missing credentials
- [ ] Graceful error on invalid credentials
- [ ] Handles network errors
- [ ] Handles missing resources
- [ ] Shows helpful error messages

## ✅ Performance

- [ ] Scan completes in reasonable time (< 5 minutes)
- [ ] API responds quickly (< 1 second)
- [ ] Dashboard loads quickly
- [ ] Database queries are efficient
- [ ] No memory leaks during scheduled scans

## 🎯 Production Readiness (Optional)

- [ ] .env file not committed to git
- [ ] .gitignore properly configured
- [ ] Documentation is complete
- [ ] Code is commented
- [ ] Error handling is comprehensive
- [ ] Logging is appropriate
- [ ] Security credentials are protected

## 📝 Testing Notes

Use this section to note any issues or observations:

```
Date: ___________
Tester: ___________

Issues found:
1. 
2. 
3. 

Works well:
1. 
2. 
3. 

Suggestions:
1. 
2. 
3. 
```

## 🚀 Ready for Portfolio/Resume

Once you've checked most items above:

- [ ] Project works end-to-end
- [ ] Can demonstrate to others
- [ ] Screenshots taken for portfolio
- [ ] Resume updated with project description
- [ ] Can explain technical decisions
- [ ] Can discuss security concepts
- [ ] Comfortable presenting the project

---

**Need help?** Check SETUP_GUIDE.md for troubleshooting tips.

