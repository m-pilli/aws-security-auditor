"""S3 security audit module."""
import boto3
from typing import List, Dict
from utils.config import config
from utils.alerts import alert_manager


class S3Auditor:
    """Auditor for S3 security misconfigurations."""
    
    def __init__(self):
        """Initialize S3 auditor."""
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
            region_name=config.AWS_DEFAULT_REGION
        )
        self.findings = []
    
    def run_audit(self) -> List[Dict]:
        """Run complete S3 security audit."""
        self.findings = []
        
        try:
            # Get all buckets
            buckets = self.s3_client.list_buckets()['Buckets']
            
            alert_manager.logger.info(f"Auditing {len(buckets)} S3 buckets")
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Run all S3 checks for this bucket
                self.check_bucket_public_access(bucket_name)
                self.check_bucket_encryption(bucket_name)
                self.check_bucket_versioning(bucket_name)
                self.check_bucket_logging(bucket_name)
                self.check_bucket_policy(bucket_name)
                self.check_bucket_acl(bucket_name)
            
            alert_manager.logger.info(f"S3 audit completed - {len(self.findings)} findings")
        
        except Exception as e:
            alert_manager.log_error("S3 audit failed", e)
        
        return self.findings
    
    def check_bucket_public_access(self, bucket_name: str):
        """Check if bucket has public access enabled."""
        try:
            public_access = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config_data = public_access['PublicAccessBlockConfiguration']
            
            # Check if any public access setting is not blocking
            if not all([
                config_data.get('BlockPublicAcls', False),
                config_data.get('BlockPublicPolicy', False),
                config_data.get('IgnorePublicAcls', False),
                config_data.get('RestrictPublicBuckets', False)
            ]):
                self.findings.append({
                    'service': 'S3',
                    'resource_id': bucket_name,
                    'resource_name': bucket_name,
                    'finding_type': 'Public Access Not Fully Blocked',
                    'severity': 'critical',
                    'risk_score': 9,
                    'description': f'S3 bucket {bucket_name} does not have all public access blocks enabled',
                    'recommendation': 'Enable all public access block settings unless public access is required',
                    'details': {
                        'bucket_name': bucket_name,
                        'public_access_block': config_data
                    }
                })
        
        except self.s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
            # No public access block configured at all
            self.findings.append({
                'service': 'S3',
                'resource_id': bucket_name,
                'resource_name': bucket_name,
                'finding_type': 'No Public Access Block',
                'severity': 'critical',
                'risk_score': 10,
                'description': f'S3 bucket {bucket_name} has no public access block configuration',
                'recommendation': 'Configure public access block to prevent accidental public exposure',
                'details': {
                    'bucket_name': bucket_name
                }
            })
        
        except Exception as e:
            alert_manager.log_error(f"Failed to check public access for {bucket_name}", e)
    
    def check_bucket_encryption(self, bucket_name: str):
        """Check if bucket has encryption enabled."""
        try:
            encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            # Bucket has encryption
        
        except self.s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            # No encryption configured
            self.findings.append({
                'service': 'S3',
                'resource_id': bucket_name,
                'resource_name': bucket_name,
                'finding_type': 'No Encryption',
                'severity': 'high',
                'risk_score': 7,
                'description': f'S3 bucket {bucket_name} does not have default encryption enabled',
                'recommendation': 'Enable default encryption (AES-256 or KMS)',
                'details': {
                    'bucket_name': bucket_name
                }
            })
        
        except Exception as e:
            alert_manager.log_error(f"Failed to check encryption for {bucket_name}", e)
    
    def check_bucket_versioning(self, bucket_name: str):
        """Check if bucket has versioning enabled."""
        try:
            versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Disabled')
            
            if status != 'Enabled':
                self.findings.append({
                    'service': 'S3',
                    'resource_id': bucket_name,
                    'resource_name': bucket_name,
                    'finding_type': 'Versioning Not Enabled',
                    'severity': 'medium',
                    'risk_score': 5,
                    'description': f'S3 bucket {bucket_name} does not have versioning enabled',
                    'recommendation': 'Enable versioning to protect against accidental deletion',
                    'details': {
                        'bucket_name': bucket_name,
                        'versioning_status': status
                    }
                })
        
        except Exception as e:
            alert_manager.log_error(f"Failed to check versioning for {bucket_name}", e)
    
    def check_bucket_logging(self, bucket_name: str):
        """Check if bucket has access logging enabled."""
        try:
            logging = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            
            if 'LoggingEnabled' not in logging:
                self.findings.append({
                    'service': 'S3',
                    'resource_id': bucket_name,
                    'resource_name': bucket_name,
                    'finding_type': 'Access Logging Not Enabled',
                    'severity': 'medium',
                    'risk_score': 4,
                    'description': f'S3 bucket {bucket_name} does not have access logging enabled',
                    'recommendation': 'Enable access logging for audit trail',
                    'details': {
                        'bucket_name': bucket_name
                    }
                })
        
        except Exception as e:
            alert_manager.log_error(f"Failed to check logging for {bucket_name}", e)
    
    def check_bucket_policy(self, bucket_name: str):
        """Check bucket policy for overly permissive access."""
        try:
            policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = policy['Policy']
            
            # Parse policy JSON
            import json
            policy_json = json.loads(policy_doc)
            
            # Check for public access in policy
            for statement in policy_json.get('Statement', []):
                effect = statement.get('Effect')
                principal = statement.get('Principal', {})
                
                # Check for public principal
                if effect == 'Allow':
                    if principal == '*' or principal.get('AWS') == '*':
                        self.findings.append({
                            'service': 'S3',
                            'resource_id': bucket_name,
                            'resource_name': bucket_name,
                            'finding_type': 'Public Bucket Policy',
                            'severity': 'critical',
                            'risk_score': 10,
                            'description': f'S3 bucket {bucket_name} has a policy allowing public access',
                            'recommendation': 'Remove public access from bucket policy',
                            'details': {
                                'bucket_name': bucket_name,
                                'statement': statement
                            }
                        })
        
        except self.s3_client.exceptions.NoSuchBucketPolicy:
            # No bucket policy is fine
            pass
        
        except Exception as e:
            alert_manager.log_error(f"Failed to check policy for {bucket_name}", e)
    
    def check_bucket_acl(self, bucket_name: str):
        """Check bucket ACL for public access."""
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission')
                
                # Check for public grantees
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    severity = 'critical' if 'AllUsers' in uri else 'high'
                    risk_score = 10 if 'AllUsers' in uri else 8
                    
                    self.findings.append({
                        'service': 'S3',
                        'resource_id': bucket_name,
                        'resource_name': bucket_name,
                        'finding_type': 'Public ACL',
                        'severity': severity,
                        'risk_score': risk_score,
                        'description': f'S3 bucket {bucket_name} has public ACL granting {permission}',
                        'recommendation': 'Remove public ACL grants',
                        'details': {
                            'bucket_name': bucket_name,
                            'grantee': grantee,
                            'permission': permission
                        }
                    })
        
        except Exception as e:
            alert_manager.log_error(f"Failed to check ACL for {bucket_name}", e)


def run_s3_audit() -> List[Dict]:
    """Run S3 security audit."""
    auditor = S3Auditor()
    return auditor.run_audit()

