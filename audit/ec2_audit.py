"""EC2 security audit module."""
import boto3
from typing import List, Dict
from utils.config import config
from utils.alerts import alert_manager


class EC2Auditor:
    """Auditor for EC2 security misconfigurations."""
    
    def __init__(self):
        """Initialize EC2 auditor."""
        self.ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
            region_name=config.AWS_DEFAULT_REGION
        )
        self.findings = []
    
    def run_audit(self) -> List[Dict]:
        """Run complete EC2 security audit."""
        self.findings = []
        
        try:
            # Run all EC2 checks
            self.check_security_groups()
            self.check_instances()
            self.check_volumes()
            self.check_snapshots()
            
            alert_manager.logger.info(f"EC2 audit completed - {len(self.findings)} findings")
        
        except Exception as e:
            alert_manager.log_error("EC2 audit failed", e)
        
        return self.findings
    
    def check_security_groups(self):
        """Check security groups for overly permissive rules."""
        try:
            security_groups = self.ec2_client.describe_security_groups()['SecurityGroups']
            
            alert_manager.logger.info(f"Auditing {len(security_groups)} security groups")
            
            for sg in security_groups:
                group_id = sg['GroupId']
                group_name = sg['GroupName']
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    protocol = rule.get('IpProtocol', '-1')
                    
                    # Check for 0.0.0.0/0 (open to internet)
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp')
                        
                        if cidr == '0.0.0.0/0':
                            # Check for critical open ports
                            critical_ports = {
                                22: 'SSH',
                                3389: 'RDP',
                                1433: 'SQL Server',
                                3306: 'MySQL',
                                5432: 'PostgreSQL',
                                27017: 'MongoDB',
                                6379: 'Redis'
                            }
                            
                            # All ports open
                            if protocol == '-1' or (from_port == 0 and to_port == 65535):
                                self.findings.append({
                                    'service': 'EC2',
                                    'resource_id': group_id,
                                    'resource_name': group_name,
                                    'finding_type': 'Security Group - All Ports Open',
                                    'severity': 'critical',
                                    'risk_score': 10,
                                    'description': f'Security group {group_name} allows all traffic from 0.0.0.0/0',
                                    'recommendation': 'Restrict security group to specific ports and IP ranges',
                                    'details': {
                                        'group_id': group_id,
                                        'group_name': group_name,
                                        'rule': rule
                                    }
                                })
                            
                            # Critical ports open
                            elif from_port in critical_ports or to_port in critical_ports:
                                port_name = critical_ports.get(from_port) or critical_ports.get(to_port)
                                
                                self.findings.append({
                                    'service': 'EC2',
                                    'resource_id': group_id,
                                    'resource_name': group_name,
                                    'finding_type': f'Security Group - {port_name} Open to Internet',
                                    'severity': 'critical',
                                    'risk_score': 9,
                                    'description': f'Security group {group_name} allows {port_name} (port {from_port}) from 0.0.0.0/0',
                                    'recommendation': f'Restrict {port_name} access to specific IP ranges',
                                    'details': {
                                        'group_id': group_id,
                                        'group_name': group_name,
                                        'port': from_port,
                                        'service': port_name,
                                        'rule': rule
                                    }
                                })
                            
                            # Other ports open to internet
                            elif from_port != 80 and from_port != 443:  # HTTP/HTTPS are expected
                                self.findings.append({
                                    'service': 'EC2',
                                    'resource_id': group_id,
                                    'resource_name': group_name,
                                    'finding_type': 'Security Group - Port Open to Internet',
                                    'severity': 'high',
                                    'risk_score': 7,
                                    'description': f'Security group {group_name} allows port {from_port} from 0.0.0.0/0',
                                    'recommendation': 'Restrict access to specific IP ranges',
                                    'details': {
                                        'group_id': group_id,
                                        'group_name': group_name,
                                        'port': from_port,
                                        'rule': rule
                                    }
                                })
                    
                    # Check for ::/0 (IPv6 open to internet)
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        cidr = ipv6_range.get('CidrIpv6')
                        
                        if cidr == '::/0':
                            self.findings.append({
                                'service': 'EC2',
                                'resource_id': group_id,
                                'resource_name': group_name,
                                'finding_type': 'Security Group - IPv6 Open to Internet',
                                'severity': 'high',
                                'risk_score': 8,
                                'description': f'Security group {group_name} allows IPv6 traffic from ::/0',
                                'recommendation': 'Restrict IPv6 access to specific ranges',
                                'details': {
                                    'group_id': group_id,
                                    'group_name': group_name,
                                    'rule': rule
                                }
                            })
        
        except Exception as e:
            alert_manager.log_error("Failed to check security groups", e)
    
    def check_instances(self):
        """Check EC2 instances for security issues."""
        try:
            reservations = self.ec2_client.describe_instances()['Reservations']
            
            for reservation in reservations:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_state = instance['State']['Name']
                    
                    # Only check running instances
                    if instance_state != 'running':
                        continue
                    
                    # Check for missing tags
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    
                    required_tags = ['Name', 'Environment', 'Owner']
                    missing_tags = [tag for tag in required_tags if tag not in tags]
                    
                    if missing_tags:
                        self.findings.append({
                            'service': 'EC2',
                            'resource_id': instance_id,
                            'resource_name': tags.get('Name', instance_id),
                            'finding_type': 'Missing Security Tags',
                            'severity': 'low',
                            'risk_score': 3,
                            'description': f'Instance {instance_id} missing tags: {", ".join(missing_tags)}',
                            'recommendation': 'Add required tags for proper resource management',
                            'details': {
                                'instance_id': instance_id,
                                'missing_tags': missing_tags,
                                'current_tags': tags
                            }
                        })
                    
                    # Check for public IP
                    if instance.get('PublicIpAddress'):
                        self.findings.append({
                            'service': 'EC2',
                            'resource_id': instance_id,
                            'resource_name': tags.get('Name', instance_id),
                            'finding_type': 'Instance with Public IP',
                            'severity': 'medium',
                            'risk_score': 5,
                            'description': f'Instance {instance_id} has public IP address',
                            'recommendation': 'Review if public IP is necessary, use bastion host or VPN instead',
                            'details': {
                                'instance_id': instance_id,
                                'public_ip': instance.get('PublicIpAddress')
                            }
                        })
                    
                    # Check for IMDSv1 (should use IMDSv2)
                    metadata_options = instance.get('MetadataOptions', {})
                    if metadata_options.get('HttpTokens') != 'required':
                        self.findings.append({
                            'service': 'EC2',
                            'resource_id': instance_id,
                            'resource_name': tags.get('Name', instance_id),
                            'finding_type': 'IMDSv1 Enabled',
                            'severity': 'medium',
                            'risk_score': 6,
                            'description': f'Instance {instance_id} allows IMDSv1 (insecure metadata service)',
                            'recommendation': 'Require IMDSv2 for better security',
                            'details': {
                                'instance_id': instance_id,
                                'metadata_options': metadata_options
                            }
                        })
                    
                    # Check for monitoring
                    if not instance.get('Monitoring', {}).get('State') == 'enabled':
                        self.findings.append({
                            'service': 'EC2',
                            'resource_id': instance_id,
                            'resource_name': tags.get('Name', instance_id),
                            'finding_type': 'Detailed Monitoring Not Enabled',
                            'severity': 'low',
                            'risk_score': 2,
                            'description': f'Instance {instance_id} does not have detailed monitoring enabled',
                            'recommendation': 'Enable detailed monitoring for better visibility',
                            'details': {
                                'instance_id': instance_id
                            }
                        })
        
        except Exception as e:
            alert_manager.log_error("Failed to check instances", e)
    
    def check_volumes(self):
        """Check EBS volumes for encryption."""
        try:
            volumes = self.ec2_client.describe_volumes()['Volumes']
            
            for volume in volumes:
                volume_id = volume['VolumeId']
                encrypted = volume.get('Encrypted', False)
                
                if not encrypted:
                    # Get volume name from tags
                    tags = {tag['Key']: tag['Value'] for tag in volume.get('Tags', [])}
                    volume_name = tags.get('Name', volume_id)
                    
                    self.findings.append({
                        'service': 'EC2',
                        'resource_id': volume_id,
                        'resource_name': volume_name,
                        'finding_type': 'Unencrypted EBS Volume',
                        'severity': 'high',
                        'risk_score': 7,
                        'description': f'EBS volume {volume_id} is not encrypted',
                        'recommendation': 'Enable encryption for all EBS volumes',
                        'details': {
                            'volume_id': volume_id,
                            'size': volume['Size'],
                            'state': volume['State']
                        }
                    })
        
        except Exception as e:
            alert_manager.log_error("Failed to check volumes", e)
    
    def check_snapshots(self):
        """Check for public snapshots."""
        try:
            # Get snapshots owned by the account
            snapshots = self.ec2_client.describe_snapshots(OwnerIds=['self'])['Snapshots']
            
            for snapshot in snapshots:
                snapshot_id = snapshot['SnapshotId']
                
                # Check snapshot permissions
                try:
                    attrs = self.ec2_client.describe_snapshot_attribute(
                        SnapshotId=snapshot_id,
                        Attribute='createVolumePermission'
                    )
                    
                    # Check for public permission
                    for permission in attrs.get('CreateVolumePermissions', []):
                        if permission.get('Group') == 'all':
                            self.findings.append({
                                'service': 'EC2',
                                'resource_id': snapshot_id,
                                'resource_name': snapshot_id,
                                'finding_type': 'Public Snapshot',
                                'severity': 'critical',
                                'risk_score': 9,
                                'description': f'Snapshot {snapshot_id} is publicly accessible',
                                'recommendation': 'Remove public access from snapshot',
                                'details': {
                                    'snapshot_id': snapshot_id,
                                    'volume_id': snapshot.get('VolumeId')
                                }
                            })
                
                except Exception as e:
                    # Error checking specific snapshot, continue
                    pass
        
        except Exception as e:
            alert_manager.log_error("Failed to check snapshots", e)


def run_ec2_audit() -> List[Dict]:
    """Run EC2 security audit."""
    auditor = EC2Auditor()
    return auditor.run_audit()

