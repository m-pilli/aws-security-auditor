# 🚀 Quick Start Guide

Get your AWS Security Auditor running in 5 minutes!

## Step 1: Install Dependencies (30 seconds)

```bash
pip install -r requirements.txt
```

## Step 2: Quick Setup (2 minutes)

```bash
python quick_start.py
```

This will:
1. ✅ Check your setup
2. ✅ Test AWS credentials
3. ✅ Run your first scan
4. ✅ Show you the results

## Step 3: Configure AWS (1 minute)

If step 2 says credentials are missing:

1. Create `.env` file (quick_start.py created a template)
2. Add your AWS credentials:

```env
AWS_ACCESS_KEY_ID=your_key_here
AWS_SECRET_ACCESS_KEY=your_secret_here
AWS_DEFAULT_REGION=us-east-1
```

3. Run quick_start.py again

## Step 4: View Results (30 seconds)

### See the report in terminal:
```bash
python main.py --report
```

### See the dashboard:
```bash
streamlit run dashboard/app.py
```

Opens at: http://localhost:8501

## Step 5: Try More Features (1 minute)

### Run specific scans:
```bash
python main.py --scan iam    # Check IAM only
python main.py --scan s3     # Check S3 only
python main.py --scan ec2    # Check EC2 only
```

### Start the API:
```bash
python main.py --api
```

Visit: http://localhost:8000/docs

### Schedule automatic scans:
```bash
python main.py --schedule daily
```

## 🎯 What's Next?

1. **Create test resources** to see the scanner in action:
   ```bash
   python examples/create_test_resources.py
   ```

2. **Export reports**:
   ```bash
   python examples/export_report.py --format html
   ```

3. **Run with Docker**:
   ```bash
   docker-compose up -d
   ```

## 📚 Need More Help?

- **Detailed Setup**: See `SETUP_GUIDE.md`
- **Full Testing**: See `TESTING_CHECKLIST.md`
- **Project Details**: See `PROJECT_SUMMARY.md`
- **General Info**: See `README.md`

## ❓ Common Issues

### "Missing AWS credentials"
→ Edit `.env` file with your AWS keys

### "Access Denied"
→ Make sure your IAM user has `SecurityAudit` policy

### "No findings"
→ Normal for new accounts! Create test resources or wait until you have AWS resources

## 🎉 You're All Set!

Your security auditor is ready. Now you can:
- ✅ Scan your AWS account
- ✅ View security findings
- ✅ Track issues over time
- ✅ Add it to your portfolio
- ✅ Use it in interviews

**Happy auditing!** 🔒

