"""Quick start script to test AWS connection and run first scan."""
import os
import sys


def check_env_file():
    """Check if .env file exists."""
    if not os.path.exists('.env'):
        print("[X] .env file not found!")
        print("\n[*] Creating .env file from template...")
        
        env_content = """# AWS Credentials
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_DEFAULT_REGION=us-east-1

# Alert Settings (Optional)
ALERT_EMAIL=your_email@example.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password

# Scan Settings
UNUSED_KEY_DAYS=90
RISK_SCORE_THRESHOLD=7
"""
        
        with open('.env', 'w') as f:
            f.write(env_content)
        
        print("[OK] .env file created!")
        print("\n[!] Please edit .env file with your AWS credentials:")
        print("   - AWS_ACCESS_KEY_ID")
        print("   - AWS_SECRET_ACCESS_KEY")
        print("\nThen run this script again.\n")
        return False
    
    return True


def check_credentials():
    """Check if AWS credentials are configured."""
    from dotenv import load_dotenv
    load_dotenv()
    
    access_key = os.getenv('AWS_ACCESS_KEY_ID')
    secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    
    if not access_key or access_key == 'your_access_key_here':
        print("[X] AWS credentials not configured in .env file")
        return False
    
    if not secret_key or secret_key == 'your_secret_key_here':
        print("[X] AWS credentials not configured in .env file")
        return False
    
    return True


def test_aws_connection():
    """Test AWS connection."""
    print("[*] Testing AWS connection...")
    
    try:
        import boto3
        from dotenv import load_dotenv
        load_dotenv()
        
        # Try to connect to AWS
        sts = boto3.client(
            'sts',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        )
        
        identity = sts.get_caller_identity()
        
        print("[OK] AWS connection successful!")
        print(f"   Account: {identity['Account']}")
        print(f"   User: {identity['Arn']}")
        return True
    
    except Exception as e:
        print(f"[X] AWS connection failed: {e}")
        print("\n[!] Common issues:")
        print("   - Invalid AWS credentials")
        print("   - Credentials not set in .env file")
        print("   - Network/firewall issues")
        return False


def run_first_scan():
    """Run the first security scan."""
    print("\n[*] Running your first security scan...")
    print("This may take 1-2 minutes depending on your AWS resources.\n")
    
    import subprocess
    
    try:
        # Set UTF-8 encoding for Windows
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        
        result = subprocess.run(
            [sys.executable, 'main.py', '--scan', 'all'],
            capture_output=False,
            text=True,
            env=env
        )
        
        if result.returncode == 0:
            print("\n[OK] Scan completed successfully!")
            return True
        else:
            print("\n[X] Scan failed")
            return False
    
    except Exception as e:
        print(f"\n[X] Error running scan: {e}")
        return False


def show_next_steps():
    """Show next steps."""
    print("\n" + "="*80)
    print("[OK] SETUP COMPLETE!")
    print("="*80)
    print("\n[*] Next steps:\n")
    print("1. View results:")
    print("   python main.py --report")
    print("\n2. View statistics:")
    print("   python main.py --stats")
    print("\n3. Start the dashboard:")
    print("   streamlit run dashboard/app.py")
    print("\n4. Start the API server:")
    print("   python main.py --api")
    print("\n5. Schedule automatic scans:")
    print("   python main.py --schedule daily")
    print("\n[*] For more information, see SETUP_GUIDE.md")
    print("="*80 + "\n")


def main():
    """Main function."""
    print("\n" + "="*80)
    print(" "*20 + "AWS SECURITY AUDITOR - QUICK START")
    print("="*80 + "\n")
    
    # Step 1: Check .env file
    print("Step 1: Checking configuration...")
    if not check_env_file():
        return
    
    # Step 2: Check credentials
    print("Step 2: Validating AWS credentials...")
    if not check_credentials():
        print("\n[!] Please edit .env file with your AWS credentials")
        print("See SETUP_GUIDE.md for detailed instructions\n")
        return
    
    print("[OK] Credentials configured")
    
    # Step 3: Test AWS connection
    print("\nStep 3: Testing AWS connection...")
    if not test_aws_connection():
        return
    
    # Step 4: Run first scan
    print("\nStep 4: Running first scan...")
    if not run_first_scan():
        return
    
    # Show next steps
    show_next_steps()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Setup cancelled by user\n")
    except Exception as e:
        print(f"\n[X] Unexpected error: {e}")
        print("Please check SETUP_GUIDE.md for troubleshooting\n")

