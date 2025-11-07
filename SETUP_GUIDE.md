# AWS Security Auditor - Setup Guide

Complete guide to set up and run the AWS Security Audit Automation tool.

## 📋 Prerequisites

- Python 3.8 or higher
- AWS Account (Free Tier is sufficient)
- Git (optional)

## 🚀 Step-by-Step Setup

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Up AWS Account & Credentials

#### A. Create AWS Account
1. Go to https://aws.amazon.com
2. Sign up for a free account (includes 12 months free tier)
3. Verify your email and set up billing

#### B. Create IAM User for Security Auditing

1. Log into AWS Console
2. Go to IAM → Users → Add User
3. Username: `security-auditor`
4. Access type: ✅ Programmatic access
5. Attach policies:
   - `SecurityAudit` (AWS managed policy)
   - `ViewOnlyAccess` (AWS managed policy)
6. Click "Create User"
7. **SAVE** your Access Key ID and Secret Access Key

#### C. Configure AWS Credentials

Create a `.env` file in the project root:

```bash
# Copy the example file
cp .env.example .env
```

Edit `.env` with your credentials:

```env
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_DEFAULT_REGION=us-east-1

# Optional: Email alerts
ALERT_EMAIL=your_email@example.com
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_gmail_app_password
```

**For Gmail alerts:**
1. Enable 2FA on your Google account
2. Generate an App Password: https://myaccount.google.com/apppasswords
3. Use the app password (not your regular password)

### 3. Verify Setup

```bash
# Test credentials
python -c "import boto3; print('AWS credentials OK')"
```

## 🎯 Usage Examples

### Basic Scans

```bash
# Run a full security scan
python main.py --scan all

# Scan specific services
python main.py --scan iam
python main.py --scan s3
python main.py --scan ec2

# Detailed output
python main.py --scan all --detailed
```

### View Reports

```bash
# View latest scan report
python main.py --report

# View specific scan by ID
python main.py --report 5

# View statistics
python main.py --stats
```

### API Server

```bash
# Start the API server
python main.py --api

# Access at:
# - API: http://localhost:8000
# - Docs: http://localhost:8000/docs
# - Health: http://localhost:8000/health
```

**API Endpoints:**
```bash
# Run a scan
curl -X POST "http://localhost:8000/scan?scan_type=all"

# Get latest report
curl http://localhost:8000/report

# Get all findings
curl http://localhost:8000/findings

# Get statistics
curl http://localhost:8000/stats
```

### Dashboard

```bash
# Start Streamlit dashboard
streamlit run dashboard/app.py

# Access at: http://localhost:8501
```

### Scheduled Scans

```bash
# Run scans every hour
python main.py --schedule hourly

# Run daily at midnight
python main.py --schedule daily

# Run weekly on Mondays
python main.py --schedule weekly

# Schedule specific service
python main.py --schedule daily --scan-type iam
```

## 🐳 Docker Setup

### Build and Run with Docker Compose

```bash
# Build containers
docker-compose build

# Start all services
docker-compose up -d

# Services available at:
# - API: http://localhost:8000
# - Dashboard: http://localhost:8501

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Run Individual Services

```bash
# Build image
docker build -t security-auditor .

# Run a scan
docker run --rm -v $(pwd)/database:/app/database security-auditor python main.py --scan all

# Start API
docker run -d -p 8000:8000 -v $(pwd)/database:/app/database security-auditor python main.py --api

# Start dashboard
docker run -d -p 8501:8501 -v $(pwd)/database:/app/database security-auditor streamlit run dashboard/app.py
```

## 🔒 AWS Free Tier Limits

The tool respects AWS Free Tier limits:

- **IAM**: Free (no limits)
- **S3**: 5GB storage, 20,000 GET requests/month
- **EC2**: 750 hours/month of t2.micro instances

**API calls this tool makes:**
- IAM: ~10-50 calls per scan
- S3: ~5-10 calls per bucket
- EC2: ~20-100 calls per scan

## 🧪 Testing Setup

### 1. Create Test Resources

```bash
# Create a test S3 bucket (via AWS Console or CLI)
aws s3 mb s3://my-test-security-bucket

# Launch a t2.micro instance (optional)
# Do this via AWS Console EC2 dashboard
```

### 2. Run First Scan

```bash
python main.py --scan all --detailed
```

### 3. Check Results

```bash
# View in terminal
python main.py --report

# View in dashboard
streamlit run dashboard/app.py

# View logs
cat logs/security_alerts.log
```

## 📊 Understanding Results

### Risk Scores

- **9-10 (Critical)**: Immediate action required
  - Public S3 buckets
  - Root account without MFA
  - All ports open to internet

- **7-8 (High)**: High priority
  - Users without MFA
  - Admin privileges
  - Critical ports exposed

- **4-6 (Medium)**: Should address soon
  - Missing encryption
  - Unused access keys (90+ days)
  - No versioning

- **1-3 (Low)**: Best practice
  - Missing tags
  - No detailed monitoring
  - Inline policies

## 🛠️ Troubleshooting

### Issue: "Missing required configuration"

**Solution:** Make sure `.env` file exists with AWS credentials

```bash
cp .env.example .env
# Edit .env with your credentials
```

### Issue: "Access Denied" errors

**Solution:** Verify IAM permissions

```bash
# Your IAM user needs these policies:
# - SecurityAudit
# - ViewOnlyAccess
```

### Issue: Database errors

**Solution:** Delete and reinitialize database

```bash
rm database/results.db
python main.py --scan all
```

### Issue: No findings in test account

**Solution:** This is normal for new accounts! The tool will find issues as you add resources.

## 📝 Best Practices

1. **Credentials Security**
   - Never commit `.env` file
   - Rotate access keys every 90 days
   - Use least privilege IAM policies

2. **Regular Scans**
   - Run daily scans: `--schedule daily`
   - Review critical findings immediately
   - Track trends over time

3. **Resource Management**
   - Clean up test resources
   - Monitor AWS Free Tier usage
   - Set up billing alerts

## 🎓 Learning Resources

- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [S3 Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [EC2 Security Groups](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)

## 🚀 Next Steps

1. ✅ Set up AWS account and credentials
2. ✅ Run your first scan
3. ✅ Explore the dashboard
4. ✅ Set up scheduled scans
5. ✅ Add to your resume/portfolio

## 💼 Resume Bullet Points

Use these for your resume:

- Developed an automated AWS security auditing system using Python and Boto3 to scan IAM, S3, and EC2 for misconfigurations
- Implemented a risk scoring system and REST API using FastAPI to enable on-demand security scans
- Built a real-time dashboard with Streamlit to visualize security findings and track remediation progress
- Designed automated alerting system to notify stakeholders of critical security issues
- Utilized SQLite for local data persistence and historical trend analysis

## 📞 Support

For issues or questions:
1. Check this guide first
2. Review AWS documentation
3. Check logs: `logs/security_alerts.log`

---

**Ready to start?** Run your first scan:

```bash
python main.py --scan all
```

Good luck with your AWS security learning journey! 🔒

