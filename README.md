# Cloud Security Audit Automation

A Python-based tool that scans AWS accounts for common security misconfigurations including public S3 buckets, over-permissive IAM roles, and open security groups.

## 🎯 Features

- **IAM Audit**: Detect admin privileges, unused access keys, and overly permissive policies
- **S3 Audit**: Find public buckets, unencrypted storage, and missing versioning
- **EC2 Audit**: Identify open security groups and missing security tags
- **Risk Scoring**: Automatic risk assessment for each finding
- **REST API**: FastAPI endpoints for on-demand scans
- **Local Dashboard**: Streamlit-based visualization
- **Automated Scheduling**: Run scans automatically
- **Local Storage**: SQLite database for scan history

## 🛠️ Tech Stack

- **Python 3.8+**
- **Boto3**: AWS SDK
- **FastAPI**: REST API framework
- **SQLite**: Local database
- **Streamlit**: Dashboard
- **Schedule**: Automated scanning

## 📦 Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd cloud-security-auditor
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure AWS credentials:
```bash
cp .env.example .env
# Edit .env with your AWS credentials
```

4. Set up AWS IAM user with read-only permissions:
   - SecurityAudit (AWS managed policy)
   - ReadOnlyAccess (AWS managed policy)

## 🚀 Usage

### Run a full scan:
```bash
python main.py --scan all
```

### Run specific module:
```bash
python main.py --scan iam
python main.py --scan s3
python main.py --scan ec2
```

### Start API server:
```bash
python main.py --api
```

### Start Dashboard:
```bash
streamlit run dashboard/app.py
```

### Enable scheduled scans:
```bash
python main.py --schedule daily
```

## 📊 API Endpoints

- `GET /health` - Health check
- `GET /scan` - Run a new scan
- `GET /report` - Get latest scan report
- `GET /findings` - Get all findings with filters
- `GET /stats` - Get security statistics

## 🔒 Security Best Practices

1. Use IAM user with minimal read-only permissions
2. Never commit `.env` file with credentials
3. Rotate AWS access keys regularly
4. Enable MFA on your AWS account
5. Use AWS Free Tier for testing

## 📈 Risk Scoring

- **Critical (9-10)**: Public S3 buckets, admin access keys
- **High (7-8)**: Over-permissive policies, open security groups
- **Medium (4-6)**: Missing encryption, unused keys
- **Low (1-3)**: Missing tags, minor misconfigurations

## 🔧 Project Structure

```
cloud-security-auditor/
├── main.py                 # Entry point
├── audit/
│   ├── __init__.py
│   ├── iam_audit.py        # IAM security checks
│   ├── s3_audit.py         # S3 security checks
│   └── ec2_audit.py        # EC2 security checks
├── database/
│   ├── __init__.py
│   ├── db.py               # Database utilities
│   └── results.db          # SQLite database
├── api/
│   ├── __init__.py
│   └── server.py           # FastAPI routes
├── utils/
│   ├── __init__.py
│   ├── alerts.py           # Alerting utilities
│   └── config.py           # Configuration
├── dashboard/
│   └── app.py              # Streamlit dashboard
├── logs/
│   └── security_alerts.log
└── requirements.txt
```

## 🤝 Contributing

This is a learning project. Feel free to extend it with:
- Additional AWS services (RDS, Lambda, etc.)
- Compliance frameworks (CIS, PCI-DSS)
- Export to PDF/HTML reports
- Integration with security tools

## 📝 License

MIT License - Feel free to use for learning and portfolio purposes!
