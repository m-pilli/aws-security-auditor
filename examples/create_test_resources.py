"""
Script to create test AWS resources for security scanning.

WARNING: This creates AWS resources that may incur costs.
Use only with AWS Free Tier accounts for learning purposes.
"""
import boto3
import os
from dotenv import load_dotenv

load_dotenv()


def create_test_s3_bucket():
    """Create a test S3 bucket with intentional misconfigurations."""
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
    )
    
    bucket_name = f"security-test-bucket-{os.getenv('AWS_ACCESS_KEY_ID')[:8].lower()}"
    
    try:
        print(f"Creating S3 bucket: {bucket_name}")
        
        # Create bucket
        if os.getenv('AWS_DEFAULT_REGION') == 'us-east-1':
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': os.getenv('AWS_DEFAULT_REGION')
                }
            )
        
        print(f"✅ Created bucket: {bucket_name}")
        print("   This bucket has NO encryption (will be flagged)")
        print("   This bucket has NO versioning (will be flagged)")
        
        return bucket_name
    
    except Exception as e:
        print(f"❌ Failed to create bucket: {e}")
        return None


def create_test_iam_user():
    """Create a test IAM user."""
    iam = boto3.client(
        'iam',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
    )
    
    username = "security-test-user"
    
    try:
        print(f"Creating IAM user: {username}")
        
        # Create user
        iam.create_user(UserName=username)
        
        # Create access key
        response = iam.create_access_key(UserName=username)
        access_key_id = response['AccessKey']['AccessKeyId']
        
        print(f"✅ Created IAM user: {username}")
        print(f"   Access Key ID: {access_key_id}")
        print("   This user has NO MFA (will be flagged)")
        print("   This user has NO policies (will be flagged as unused)")
        
        return username
    
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"⚠️  User {username} already exists")
        return username
    except Exception as e:
        print(f"❌ Failed to create user: {e}")
        return None


def create_test_security_group():
    """Create a test security group with open ports."""
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
    )
    
    try:
        print("Creating test security group...")
        
        # Get default VPC
        vpcs = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
        if not vpcs['Vpcs']:
            print("❌ No default VPC found")
            return None
        
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        
        # Create security group
        response = ec2.create_security_group(
            GroupName='security-test-group',
            Description='Test security group for auditing',
            VpcId=vpc_id
        )
        
        group_id = response['GroupId']
        
        # Add open SSH rule (intentionally insecure for testing)
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH from anywhere'}]
                }
            ]
        )
        
        print(f"✅ Created security group: {group_id}")
        print("   This group has SSH open to 0.0.0.0/0 (will be flagged)")
        
        return group_id
    
    except ec2.exceptions.ClientError as e:
        if 'already exists' in str(e):
            print("⚠️  Security group already exists")
        else:
            print(f"❌ Failed to create security group: {e}")
        return None
    except Exception as e:
        print(f"❌ Failed to create security group: {e}")
        return None


def cleanup_resources():
    """Clean up test resources."""
    print("\n⚠️  CLEANUP MODE")
    print("="*80)
    
    confirm = input("\nAre you sure you want to delete all test resources? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Cleanup cancelled")
        return
    
    # Delete S3 bucket
    s3 = boto3.client('s3')
    bucket_name = f"security-test-bucket-{os.getenv('AWS_ACCESS_KEY_ID')[:8].lower()}"
    
    try:
        print(f"Deleting S3 bucket: {bucket_name}")
        s3.delete_bucket(Bucket=bucket_name)
        print(f"✅ Deleted bucket: {bucket_name}")
    except Exception as e:
        print(f"❌ Failed to delete bucket: {e}")
    
    # Delete IAM user
    iam = boto3.client('iam')
    username = "security-test-user"
    
    try:
        print(f"Deleting IAM user: {username}")
        
        # Delete access keys first
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])
        
        # Delete user
        iam.delete_user(UserName=username)
        print(f"✅ Deleted user: {username}")
    except Exception as e:
        print(f"❌ Failed to delete user: {e}")
    
    # Delete security group
    ec2 = boto3.client('ec2')
    
    try:
        print("Deleting security group: security-test-group")
        
        # Find the group
        groups = ec2.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': ['security-test-group']}]
        )
        
        if groups['SecurityGroups']:
            group_id = groups['SecurityGroups'][0]['GroupId']
            ec2.delete_security_group(GroupId=group_id)
            print(f"✅ Deleted security group: {group_id}")
    except Exception as e:
        print(f"❌ Failed to delete security group: {e}")
    
    print("\n✅ Cleanup complete!")


def main():
    """Main function."""
    print("\n" + "="*80)
    print(" "*20 + "CREATE TEST AWS RESOURCES")
    print("="*80)
    print("\n⚠️  WARNING: This will create AWS resources")
    print("These are FREE with AWS Free Tier but you should delete them after testing.\n")
    
    choice = input("Do you want to:\n1. Create test resources\n2. Clean up test resources\n\nChoice (1/2): ")
    
    if choice == '2':
        cleanup_resources()
        return
    
    if choice != '1':
        print("Invalid choice")
        return
    
    print("\n🚀 Creating test resources...\n")
    
    # Create resources
    bucket = create_test_s3_bucket()
    user = create_test_iam_user()
    sg = create_test_security_group()
    
    # Summary
    print("\n" + "="*80)
    print("✅ TEST RESOURCES CREATED")
    print("="*80)
    print("\nThe following resources were created:")
    if bucket:
        print(f"  - S3 Bucket: {bucket}")
    if user:
        print(f"  - IAM User: {user}")
    if sg:
        print(f"  - Security Group: {sg}")
    
    print("\n🔍 Now run a security scan to detect these issues:")
    print("   python main.py --scan all")
    
    print("\n🧹 To clean up these resources later:")
    print("   python examples/create_test_resources.py")
    print("   (then choose option 2)")
    
    print("\n⚠️  Remember to delete these resources when done testing!")
    print("="*80 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Cancelled by user\n")
    except Exception as e:
        print(f"\n❌ Error: {e}\n")

