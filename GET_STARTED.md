# 🔒 AWS Security Auditor - Get Started

## 📋 What You Need

- ✅ Python 3.8 or higher
- ✅ AWS Account (free tier is fine)
- ✅ 10 minutes

## 🎯 Quick Start Path

```
┌─────────────────────────────────────────────────────┐
│  1. INSTALL       →     2. CONFIGURE                 │
│  Dependencies           AWS Credentials              │
│  (1 minute)             (2 minutes)                  │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  3. RUN SCAN      →     4. VIEW RESULTS              │
│  First audit            Dashboard & Reports          │
│  (2 minutes)            (2 minutes)                  │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  5. EXPLORE       →     6. CUSTOMIZE                 │
│  More features          Schedule & Alerts            │
│  (3 minutes)            (optional)                   │
└─────────────────────────────────────────────────────┘
```

---

## 📦 Step 1: Install (1 minute)

```bash
# Clone or download the project
cd cloud-security-auditor

# Install Python dependencies
pip install -r requirements.txt
```

**What this installs:**
- `boto3` - AWS SDK
- `fastapi` - REST API framework
- `streamlit` - Dashboard
- `schedule` - Automated scans
- And a few more...

---

## 🔑 Step 2: Configure AWS (2 minutes)

### A. Create AWS IAM User

1. Log into AWS Console
2. Go to **IAM → Users → Add User**
3. Username: `security-auditor`
4. Access type: ✅ **Programmatic access**
5. Attach policies:
   - `SecurityAudit` (AWS managed)
   - `ViewOnlyAccess` (AWS managed)
6. **Save** your credentials!

### B. Add Credentials to .env

```bash
# Run the quick start - it will create .env for you
python quick_start.py
```

Then edit `.env`:

```env
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=your_secret_key_here_40_characters
AWS_DEFAULT_REGION=us-east-1
```

---

## 🔍 Step 3: Run Your First Scan (2 minutes)

```bash
# Run a complete security scan
python main.py --scan all
```

**What happens:**
```
🔍 Starting ALL security audit...
📋 Running IAM audit...
   ✓ Found 3 issues in IAM
📋 Running S3 audit...
   ✓ Found 5 issues in S3
📋 Running EC2 audit...
   ✓ Found 2 issues in EC2

🔍 SECURITY AUDIT SUMMARY - 10 Issues Found
================================================================================
🔴 CRITICAL: 2 issues
  1. [S3] Public Access Not Fully Blocked
  2. [IAM] Root Account MFA Not Enabled
...
```

---

## 📊 Step 4: View Results (2 minutes)

### Option A: Terminal Report

```bash
python main.py --report
```

Shows formatted report with:
- Total findings count
- Breakdown by severity
- Top issues
- Risk scores

### Option B: Web Dashboard

```bash
streamlit run dashboard/app.py
```

Opens at: **http://localhost:8501**

Features:
- 📊 Interactive charts
- 🔍 Filter by service/severity
- 📈 Trends over time
- 💡 Top recommendations

### Option C: API

```bash
# In one terminal
python main.py --api

# In another terminal
curl http://localhost:8000/report
```

API Documentation: **http://localhost:8000/docs**

---

## 🚀 Step 5: Explore More Features (3 minutes)

### Run Specific Service Scans

```bash
python main.py --scan iam    # IAM only
python main.py --scan s3     # S3 only
python main.py --scan ec2    # EC2 only
```

### View Statistics

```bash
python main.py --stats
```

Shows:
- Total scans run
- Open findings
- Severity breakdown
- Service breakdown

### Export Reports

```bash
python examples/export_report.py --format json
python examples/export_report.py --format csv
python examples/export_report.py --format html
```

Creates files you can share or archive.

### Create Test Resources (Optional)

```bash
python examples/create_test_resources.py
```

Creates intentionally insecure AWS resources to test the scanner.

---

## ⚙️ Step 6: Customize (Optional)

### Schedule Automatic Scans

```bash
# Run daily at midnight
python main.py --schedule daily

# Run every hour
python main.py --schedule hourly

# Run weekly on Mondays
python main.py --schedule weekly
```

### Email Alerts

Edit `.env`:

```env
ALERT_EMAIL=your_email@example.com
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_gmail_app_password
```

**For Gmail:**
1. Enable 2FA
2. Create App Password at: https://myaccount.google.com/apppasswords
3. Use that password (not your regular password)

### Docker Deployment

```bash
# Build and start all services
docker-compose up -d

# Services available at:
# - API: http://localhost:8000
# - Dashboard: http://localhost:8501

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## 🎯 What Gets Checked?

### 🔐 IAM (Identity & Access Management)
- ✅ Root account MFA
- ✅ User MFA
- ✅ Admin privileges
- ✅ Unused access keys
- ✅ Password policy
- ✅ Overly permissive policies

### 📦 S3 (Storage)
- ✅ Public access blocks
- ✅ Encryption
- ✅ Versioning
- ✅ Logging
- ✅ Bucket policies
- ✅ Public ACLs

### 💻 EC2 (Compute)
- ✅ Security groups
- ✅ Open ports
- ✅ Public IPs
- ✅ Encryption
- ✅ IMDSv2
- ✅ Missing tags

---

## 📈 Understanding Results

### Risk Scores (1-10)

```
🔴 9-10 = CRITICAL
     ├─ Public S3 buckets
     ├─ Root without MFA
     └─ All ports open to internet

🟠 7-8 = HIGH
     ├─ Users without MFA
     ├─ Admin privileges
     └─ SSH/RDP exposed

🟡 4-6 = MEDIUM
     ├─ No encryption
     ├─ Unused keys
     └─ No versioning

🔵 1-3 = LOW
     ├─ Missing tags
     └─ No monitoring
```

---

## 💡 Pro Tips

### 1. Run Regular Scans
```bash
# Set up daily scans
python main.py --schedule daily
```

### 2. Focus on Critical First
```bash
# View only critical/high issues in dashboard
# Use severity filter
```

### 3. Track Progress
```bash
# Run multiple scans over time
# View trends in dashboard
```

### 4. Export for Sharing
```bash
# Create HTML report
python examples/export_report.py --format html
# Open in browser to share with team
```

### 5. Clean Up Test Resources
```bash
# After testing
python examples/create_test_resources.py
# Choose option 2 to delete
```

---

## ❓ Troubleshooting

### "Missing AWS credentials"
```bash
# Make sure .env exists with correct values
cat .env
```

### "Access Denied"
```bash
# Verify IAM policies:
# - SecurityAudit
# - ViewOnlyAccess
```

### "No findings in scan"
```bash
# Normal for new AWS accounts!
# Options:
# 1. Create test resources
# 2. Wait until you have real resources
# 3. The scanner is working correctly
```

### "Module not found"
```bash
# Reinstall dependencies
pip install -r requirements.txt
```

---

## 📚 Learn More

| Document | Purpose |
|----------|---------|
| `QUICKSTART.md` | Ultra-fast 5-minute guide |
| `SETUP_GUIDE.md` | Detailed setup instructions |
| `README.md` | Project overview |
| `PROJECT_SUMMARY.md` | Technical architecture |
| `TESTING_CHECKLIST.md` | Verify everything works |

---

## 🎓 Next Steps

### For Learning
1. ✅ Run your first scan
2. ✅ Understand the findings
3. ✅ Try fixing issues in AWS Console
4. ✅ Run scan again to verify
5. ✅ Explore the code

### For Portfolio
1. ✅ Take screenshots of dashboard
2. ✅ Export sample reports
3. ✅ Write about the project
4. ✅ Add to resume
5. ✅ Practice explaining it

### For Interviews
**Be ready to discuss:**
- Why you built this
- Technical decisions made
- AWS security best practices
- How you'd scale it
- What you learned

---

## 🏆 Achievement Unlocked!

You now have:
- ✅ Working security automation tool
- ✅ AWS cloud security knowledge
- ✅ Python full-stack project
- ✅ Portfolio project
- ✅ Interview talking point

**Ready for Roblox and similar companies!** 🚀

---

## 🆘 Need Help?

1. **Check the guides**: All questions answered in docs
2. **Review logs**: `logs/security_alerts.log`
3. **Test connection**: `python quick_start.py`
4. **Verify setup**: `TESTING_CHECKLIST.md`

---

## 🎉 You're Ready!

Choose your path:

```bash
# Just scan my AWS
python main.py --scan all

# See results visually
streamlit run dashboard/app.py

# Automate everything
python main.py --schedule daily

# Build with Docker
docker-compose up -d
```

**Happy auditing!** 🔒

---

*Built for learning, designed for impact, ready for production.*

