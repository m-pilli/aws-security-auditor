"""IAM security audit module."""
import boto3
from datetime import datetime, timezone
from typing import List, Dict
from utils.config import config
from utils.alerts import alert_manager


class IAMAuditor:
    """Auditor for IAM security misconfigurations."""
    
    def __init__(self):
        """Initialize IAM auditor."""
        self.iam_client = boto3.client(
            'iam',
            aws_access_key_id=config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
            region_name=config.AWS_DEFAULT_REGION
        )
        self.findings = []
    
    def run_audit(self) -> List[Dict]:
        """Run complete IAM security audit."""
        self.findings = []
        
        try:
            # Run all IAM checks
            self.check_root_account_mfa()
            self.check_user_mfa()
            self.check_admin_users()
            self.check_unused_access_keys()
            self.check_password_policy()
            self.check_overly_permissive_policies()
            self.check_inline_policies()
            
            alert_manager.logger.info(f"IAM audit completed - {len(self.findings)} findings")
            
        except Exception as e:
            alert_manager.log_error("IAM audit failed", e)
        
        return self.findings
    
    def check_root_account_mfa(self):
        """Check if root account has MFA enabled."""
        try:
            summary = self.iam_client.get_account_summary()
            account_mfa = summary['SummaryMap'].get('AccountMFAEnabled', 0)
            
            if account_mfa == 0:
                self.findings.append({
                    'service': 'IAM',
                    'resource_id': 'root-account',
                    'resource_name': 'Root Account',
                    'finding_type': 'Root Account MFA Not Enabled',
                    'severity': 'critical',
                    'risk_score': 10,
                    'description': 'Root account does not have MFA enabled',
                    'recommendation': 'Enable MFA on the root account immediately',
                    'details': {'account_mfa_enabled': account_mfa}
                })
        except Exception as e:
            alert_manager.log_error("Failed to check root account MFA", e)
    
    def check_user_mfa(self):
        """Check for users without MFA enabled."""
        try:
            users = self.iam_client.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
                
                if not mfa_devices['MFADevices']:
                    # Check if user has console access
                    try:
                        login_profile = self.iam_client.get_login_profile(UserName=username)
                        
                        self.findings.append({
                            'service': 'IAM',
                            'resource_id': username,
                            'resource_name': username,
                            'finding_type': 'User Without MFA',
                            'severity': 'high',
                            'risk_score': 8,
                            'description': f'User {username} has console access but no MFA enabled',
                            'recommendation': 'Enable MFA for this user',
                            'details': {
                                'user_name': username,
                                'create_date': user['CreateDate'].isoformat()
                            }
                        })
                    except self.iam_client.exceptions.NoSuchEntityException:
                        # User doesn't have console access, lower severity
                        pass
        
        except Exception as e:
            alert_manager.log_error("Failed to check user MFA", e)
    
    def check_admin_users(self):
        """Check for users with administrative privileges."""
        try:
            users = self.iam_client.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                
                # Check attached policies
                attached_policies = self.iam_client.list_attached_user_policies(
                    UserName=username
                )['AttachedPolicies']
                
                admin_policies = [
                    'AdministratorAccess',
                    'PowerUserAccess',
                    'IAMFullAccess'
                ]
                
                for policy in attached_policies:
                    if any(admin_policy in policy['PolicyName'] for admin_policy in admin_policies):
                        self.findings.append({
                            'service': 'IAM',
                            'resource_id': username,
                            'resource_name': username,
                            'finding_type': 'User with Admin Privileges',
                            'severity': 'high',
                            'risk_score': 8,
                            'description': f'User {username} has administrative policy {policy["PolicyName"]}',
                            'recommendation': 'Review if admin access is necessary, use groups instead',
                            'details': {
                                'user_name': username,
                                'policy_name': policy['PolicyName'],
                                'policy_arn': policy['PolicyArn']
                            }
                        })
        
        except Exception as e:
            alert_manager.log_error("Failed to check admin users", e)
    
    def check_unused_access_keys(self):
        """Check for unused or old access keys."""
        try:
            users = self.iam_client.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                access_keys = self.iam_client.list_access_keys(UserName=username)
                
                for key in access_keys['AccessKeyMetadata']:
                    key_id = key['AccessKeyId']
                    create_date = key['CreateDate']
                    status = key['Status']
                    
                    # Check key age
                    age_days = (datetime.now(timezone.utc) - create_date).days
                    
                    # Get last used information
                    try:
                        last_used = self.iam_client.get_access_key_last_used(
                            AccessKeyId=key_id
                        )
                        last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                        
                        if last_used_date:
                            days_since_use = (datetime.now(timezone.utc) - last_used_date).days
                        else:
                            days_since_use = age_days
                    except:
                        days_since_use = age_days
                    
                    # Flag old or unused keys
                    if status == 'Active' and days_since_use > config.UNUSED_KEY_DAYS:
                        severity = 'high' if days_since_use > 180 else 'medium'
                        risk_score = 8 if days_since_use > 180 else 6
                        
                        self.findings.append({
                            'service': 'IAM',
                            'resource_id': key_id,
                            'resource_name': username,
                            'finding_type': 'Unused Access Key',
                            'severity': severity,
                            'risk_score': risk_score,
                            'description': f'Access key {key_id} for user {username} unused for {days_since_use} days',
                            'recommendation': 'Rotate or deactivate unused access keys',
                            'details': {
                                'user_name': username,
                                'key_id': key_id,
                                'age_days': age_days,
                                'days_since_use': days_since_use,
                                'status': status
                            }
                        })
                    
                    # Flag very old keys (even if used)
                    elif status == 'Active' and age_days > 365:
                        self.findings.append({
                            'service': 'IAM',
                            'resource_id': key_id,
                            'resource_name': username,
                            'finding_type': 'Old Access Key',
                            'severity': 'medium',
                            'risk_score': 5,
                            'description': f'Access key {key_id} for user {username} is {age_days} days old',
                            'recommendation': 'Rotate access keys regularly (at least annually)',
                            'details': {
                                'user_name': username,
                                'key_id': key_id,
                                'age_days': age_days,
                                'status': status
                            }
                        })
        
        except Exception as e:
            alert_manager.log_error("Failed to check access keys", e)
    
    def check_password_policy(self):
        """Check IAM password policy."""
        try:
            policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            
            # Check for weak password requirements
            if policy.get('MinimumPasswordLength', 0) < 14:
                self.findings.append({
                    'service': 'IAM',
                    'resource_id': 'password-policy',
                    'resource_name': 'Account Password Policy',
                    'finding_type': 'Weak Password Policy',
                    'severity': 'medium',
                    'risk_score': 6,
                    'description': f'Password minimum length is {policy.get("MinimumPasswordLength", 0)} (recommended: 14+)',
                    'recommendation': 'Set minimum password length to at least 14 characters',
                    'details': policy
                })
            
            if not policy.get('RequireSymbols', False):
                self.findings.append({
                    'service': 'IAM',
                    'resource_id': 'password-policy',
                    'resource_name': 'Account Password Policy',
                    'finding_type': 'Weak Password Policy',
                    'severity': 'medium',
                    'risk_score': 5,
                    'description': 'Password policy does not require symbols',
                    'recommendation': 'Enable symbol requirement in password policy',
                    'details': policy
                })
            
            if not policy.get('RequireNumbers', False):
                self.findings.append({
                    'service': 'IAM',
                    'resource_id': 'password-policy',
                    'resource_name': 'Account Password Policy',
                    'finding_type': 'Weak Password Policy',
                    'severity': 'medium',
                    'risk_score': 5,
                    'description': 'Password policy does not require numbers',
                    'recommendation': 'Enable number requirement in password policy',
                    'details': policy
                })
        
        except self.iam_client.exceptions.NoSuchEntityException:
            self.findings.append({
                'service': 'IAM',
                'resource_id': 'password-policy',
                'resource_name': 'Account Password Policy',
                'finding_type': 'No Password Policy',
                'severity': 'high',
                'risk_score': 7,
                'description': 'No password policy configured for the account',
                'recommendation': 'Configure a strong password policy',
                'details': {}
            })
        except Exception as e:
            alert_manager.log_error("Failed to check password policy", e)
    
    def check_overly_permissive_policies(self):
        """Check for policies with overly broad permissions."""
        try:
            policies = self.iam_client.list_policies(Scope='Local')['Policies']
            
            for policy in policies:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']
                
                # Get policy document
                version = self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version
                )['PolicyVersion']['Document']
                
                # Check for wildcard permissions
                for statement in policy_document.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        resources = statement.get('Resource', [])
                        
                        # Convert to list if string
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        
                        # Check for * in actions
                        if '*' in actions:
                            self.findings.append({
                                'service': 'IAM',
                                'resource_id': policy_arn,
                                'resource_name': policy_name,
                                'finding_type': 'Overly Permissive Policy',
                                'severity': 'high',
                                'risk_score': 8,
                                'description': f'Policy {policy_name} allows all actions (*)',
                                'recommendation': 'Follow principle of least privilege, specify exact actions needed',
                                'details': {
                                    'policy_name': policy_name,
                                    'policy_arn': policy_arn,
                                    'statement': statement
                                }
                            })
                        
                        # Check for * in resources with broad actions
                        elif '*' in resources and any(':*' in action for action in actions):
                            self.findings.append({
                                'service': 'IAM',
                                'resource_id': policy_arn,
                                'resource_name': policy_name,
                                'finding_type': 'Overly Permissive Policy',
                                'severity': 'medium',
                                'risk_score': 6,
                                'description': f'Policy {policy_name} allows broad actions on all resources',
                                'recommendation': 'Restrict policy to specific resources',
                                'details': {
                                    'policy_name': policy_name,
                                    'policy_arn': policy_arn,
                                    'actions': actions
                                }
                            })
        
        except Exception as e:
            alert_manager.log_error("Failed to check permissive policies", e)
    
    def check_inline_policies(self):
        """Check for inline policies (should use managed policies instead)."""
        try:
            users = self.iam_client.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                inline_policies = self.iam_client.list_user_policies(UserName=username)
                
                if inline_policies['PolicyNames']:
                    self.findings.append({
                        'service': 'IAM',
                        'resource_id': username,
                        'resource_name': username,
                        'finding_type': 'Inline Policy Usage',
                        'severity': 'low',
                        'risk_score': 3,
                        'description': f'User {username} has {len(inline_policies["PolicyNames"])} inline policies',
                        'recommendation': 'Use managed policies instead of inline policies for better governance',
                        'details': {
                            'user_name': username,
                            'policy_count': len(inline_policies['PolicyNames']),
                            'policy_names': inline_policies['PolicyNames']
                        }
                    })
        
        except Exception as e:
            alert_manager.log_error("Failed to check inline policies", e)


def run_iam_audit() -> List[Dict]:
    """Run IAM security audit."""
    auditor = IAMAuditor()
    return auditor.run_audit()

