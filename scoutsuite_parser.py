#!/usr/bin/env python3
import json
import re
import sys
import argparse
import os
import smtplib
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

try:
    from sqlalchemy import create_engine, text, Column, Integer, String, DateTime, Text, Boolean, JSON, ForeignKey, Index
    from sqlalchemy.orm import declarative_base, sessionmaker
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False

try:
    import boto3
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

class ScoutSuiteParser:
    def __init__(self, db_config=None, email_config=None, debug=False):
        load_dotenv()
        self.db_config = db_config or self._load_db_config()
        self.email_config = email_config or self._load_email_config()
        self.connection = None
        self.debug = debug
        
        # Setup logging
        log_level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
    def _load_db_config(self):
        """Load database configuration from environment variables"""
        if all([os.getenv('DB_HOST'), os.getenv('DB_USER'), os.getenv('DB_PASSWORD'), os.getenv('DB_NAME')]):
            config = {
                'host': os.getenv('DB_HOST'),
                'user': os.getenv('DB_USER'),
                'password': os.getenv('DB_PASSWORD'),
                'database': os.getenv('DB_NAME'),
                'port': int(os.getenv('DB_PORT', '3306')),
                'ssl_disabled': os.getenv('DB_SSL_DISABLED', 'false').lower() == 'true',
                'ssl_ca': os.getenv('DB_SSL_CA'),
                'ssl_cert': os.getenv('DB_SSL_CERT'),
                'ssl_key': os.getenv('DB_SSL_KEY')
            }
            return config
        return None
        
    def _load_email_config(self):
        """Load email configuration from environment variables"""
        if os.getenv('ENABLE_EMAIL_NOTIFICATIONS', 'false').lower() == 'true':
            return {
                'smtp_host': os.getenv('SMTP_HOST', 'localhost'),
                'smtp_port': int(os.getenv('SMTP_PORT', '587')),
                'smtp_user': os.getenv('SMTP_USER', ''),
                'smtp_password': os.getenv('SMTP_PASSWORD', ''),
                'smtp_from': os.getenv('SMTP_FROM', 'alerts@localhost'),
                'smtp_use_tls': os.getenv('SMTP_USE_TLS', 'true').lower() == 'true',
                'recipients': [r.strip() for r in os.getenv('EMAIL_RECIPIENTS', '').split(',') if r.strip()],
                'notify_on_new': os.getenv('NOTIFY_ON_NEW_FINDINGS', 'true').lower() == 'true',
                'notify_severities': [s.strip().lower() for s in os.getenv('NOTIFY_ON_SEVERITY', 'medium,high,critical').split(',')],
                'initial_scan': os.getenv('INITIAL_SCAN', 'false').lower() == 'true',
                'aws_region': os.getenv('AWS_REGION'),
                'aws_access_key': os.getenv('AWS_ACCESS_KEY_ID'),
                'aws_secret_key': os.getenv('AWS_SECRET_ACCESS_KEY')
            }
        return None
        
    def connect_db(self):
        if not SQLALCHEMY_AVAILABLE:
            raise ImportError("sqlalchemy not installed")
        
        # Build connection string with TLS support
        conn_str = f"mysql+pymysql://{self.db_config['user']}:{self.db_config['password']}@{self.db_config['host']}:{self.db_config['port']}/{self.db_config['database']}"
        
        # Add SSL parameters if not disabled
        ssl_params = []
        if not self.db_config.get('ssl_disabled', False):
            ssl_params.append('ssl_disabled=false')
            if self.db_config.get('ssl_ca'):
                ssl_params.append(f"ssl_ca={self.db_config['ssl_ca']}")
            if self.db_config.get('ssl_cert'):
                ssl_params.append(f"ssl_cert={self.db_config['ssl_cert']}")
            if self.db_config.get('ssl_key'):
                ssl_params.append(f"ssl_key={self.db_config['ssl_key']}")
        
        if ssl_params:
            conn_str += '?' + '&'.join(ssl_params)
        
        self.engine = create_engine(conn_str)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        
    def create_tables(self):
        # Create tables using SQLAlchemy
        Base = declarative_base()
        
        class ScoutScan(Base):
            __tablename__ = 'scout_scans'
            id = Column(Integer, primary_key=True, autoincrement=True)
            account_id = Column(String(20), index=True)
            scan_time = Column(DateTime, index=True)
            version = Column(String(20))
            total_findings = Column(Integer)
            created_at = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'), index=True)
            
            __table_args__ = (
                Index('idx_account_scan_time', 'account_id', 'scan_time'),
                Index('idx_account_created', 'account_id', 'created_at'),
                {'mysql_engine': 'InnoDB'},
            )
        
        class ScoutFinding(Base):
            __tablename__ = 'scout_findings'
            id = Column(Integer, primary_key=True, autoincrement=True)
            scan_id = Column(Integer, ForeignKey('scout_scans.id'), index=True)
            service = Column(String(50), index=True)
            finding_id = Column(String(100), index=True)
            level = Column(String(20), index=True)
            flagged_items = Column(Integer)
            checked_items = Column(Integer)
            description = Column(Text)
            
            __table_args__ = (
                Index('idx_scan_service', 'scan_id', 'service'),
                Index('idx_service_level', 'service', 'level'),
                Index('idx_scan_level', 'scan_id', 'level'),
                {'mysql_engine': 'InnoDB'},
            )
        
        class ScoutEvent(Base):
            __tablename__ = 'scout_events'
            id = Column(Integer, primary_key=True, autoincrement=True)
            resource_id = Column(String(255), index=True)
            resource_name = Column(String(255), index=True)
            resource_type = Column(String(100), index=True)
            region = Column(String(50), index=True)
            details = Column(JSON)
            event_hash = Column(String(64), unique=True, index=True)
            first_seen = Column(DateTime, server_default=text('CURRENT_TIMESTAMP'), index=True)
            last_seen = Column(DateTime, server_default=text('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'), index=True)
            resolved_at = Column(DateTime, nullable=True, index=True)
            notified = Column(Boolean, default=False, index=True)
            
            __table_args__ = (
                Index('idx_resource_type_region', 'resource_type', 'region'),
                Index('idx_resolved_notified', 'resolved_at', 'notified'),
                Index('idx_last_seen_resolved', 'last_seen', 'resolved_at'),
                Index('idx_resource_id_type', 'resource_id', 'resource_type'),
                {'mysql_engine': 'InnoDB'},
            )
        
        class ScoutEventFinding(Base):
            __tablename__ = 'scout_event_findings'
            id = Column(Integer, primary_key=True, autoincrement=True)
            event_id = Column(Integer, ForeignKey('scout_events.id'), index=True)
            finding_id = Column(Integer, ForeignKey('scout_findings.id'), index=True)
            scan_id = Column(Integer, ForeignKey('scout_scans.id'), index=True)
            
            __table_args__ = (
                Index('idx_event_finding', 'event_id', 'finding_id'),
                Index('idx_scan_event', 'scan_id', 'event_id'),
                Index('idx_scan_finding', 'scan_id', 'finding_id'),
                {'mysql_engine': 'InnoDB'},
            )
        
        Base.metadata.create_all(self.engine)
        self.ScoutScan = ScoutScan
        self.ScoutFinding = ScoutFinding
        self.ScoutEvent = ScoutEvent
        self.ScoutEventFinding = ScoutEventFinding
        
    def parse_js_file(self, file_path):
        """Extract JSON data from JavaScript file"""
        self.logger.info(f"Reading ScoutSuite file: {file_path}")
        content = Path(file_path).read_text()
        
        # Extract JSON from JavaScript variable assignment
        if 'scoutsuite_results =' in content:
            self.logger.info("Found ScoutSuite results, parsing JSON...")
            json_start = content.find('{')
            json_data = content[json_start:]
            data = json.loads(json_data)
            self.logger.info(f"Parsed JSON successfully - Account: {data.get('account_id', 'unknown')}")
            return data
        self.logger.error("No ScoutSuite results found in file")
        return None
        
    def get_value_at(self, path, data):
        """ScoutSuite's getValueAt function - recursively traverse nested objects"""
        if not path:
            return data
            
        current_path = path
        value = data
        
        while current_path:
            if '.' in current_path:
                key = current_path[:current_path.index('.')]
                current_path = current_path[current_path.index('.') + 1:]
            else:
                key = current_path
                current_path = None
                
            try:
                if key == 'id':
                    # Handle wildcard expansion like ScoutSuite
                    results = []
                    if isinstance(value, dict):
                        for k in value:
                            sub_path = k + ('.' + current_path if current_path else '')
                            sub_result = self.get_value_at(sub_path, value)
                            if isinstance(sub_result, list):
                                results.extend(sub_result)
                            else:
                                results.append(sub_result)
                    return results
                else:
                    if isinstance(value, dict) and key in value:
                        value = value[key]
                    else:
                        return None
            except Exception as e:
                self.logger.debug(f"Error traversing path {path} at key {key}: {e}")
                return None
                
        return value
    
    def get_resource_path_from_finding(self, finding_path, finding_data):
        """Extract resource path from finding path like ScoutSuite"""
        if finding_path.endswith('.items'):
            # Try to get display_path or path from finding metadata
            display_path = finding_data.get('display_path')
            if not display_path:
                display_path = finding_data.get('path')
            
            if display_path:
                path_array = display_path.split('.')
                if path_array:
                    path_array.pop()  # Remove last component
                return 'services.' + '.'.join(path_array)
        
        return finding_path
    
    def extract_findings(self, data):
        """Extract key findings and individual events from ScoutSuite data using native logic"""
        self.logger.info("Extracting findings and events using ScoutSuite native logic...")
        findings = []
        events = []
        account_id = data.get('account_id', 'unknown')
        scan_time = data.get('last_run', {}).get('time', '')
        version = data.get('last_run', {}).get('version', '')
        
        # Parse scan time
        try:
            scan_datetime = datetime.strptime(scan_time, '%Y-%m-%d %H:%M:%S%z')
        except:
            scan_datetime = datetime.now()
            
        scan_info = {
            'account_id': account_id,
            'scan_time': scan_datetime,
            'version': version,
            'total_findings': 0
        }
        
        # Extract findings from services using ScoutSuite's structure
        services = data.get('services', {})
        self.logger.info(f"Processing {len(services)} services...")
        
        for service_name, service_data in services.items():
            service_findings = service_data.get('findings', {})
            if service_findings:
                self.logger.info(f"  {service_name}: {len(service_findings)} findings")
            
            for finding_id, finding_data in service_findings.items():
                flagged_items_count = finding_data.get('flagged_items', 0)
                
                # Skip findings with no flagged items (no issues found)
                if flagged_items_count == 0:
                    continue
                    
                finding = {
                    'service': service_name,
                    'finding_id': finding_id,
                    'level': finding_data.get('level', 'unknown'),
                    'flagged_items': flagged_items_count,
                    'checked_items': finding_data.get('checked_items', 0),
                    'description': finding_data.get('description', ''),
                    'events': []
                }
                
                # Use ScoutSuite's native item extraction
                flagged_items = finding_data.get('items', [])
                if flagged_items:
                    self.logger.debug(f"    {finding_id}: {len(flagged_items)} flagged items")
                    
                    # Get resource path for this finding
                    finding_path = f"services.{service_name}.findings.{finding_id}"
                    resource_path = self.get_resource_path_from_finding(finding_path + '.items', finding_data)
                    
                    # Extract events using ScoutSuite's logic
                    for item_path in flagged_items:
                        event = self._extract_event_using_scoutsuite_logic(item_path, service_name, finding_id, resource_path, data)
                        if event:
                            finding['events'].append(event)
                            events.append(event)
                
                findings.append(finding)
                
        scan_info['total_findings'] = len(findings)
        self.logger.info(f"Extracted {len(findings)} findings with {len(events)} total events")
        return scan_info, findings, events
        
    def _extract_event_using_scoutsuite_logic(self, item_path, service, finding_id, resource_path, data):
        """Extract individual event using ScoutSuite's native logic"""
        try:
            self.logger.debug(f"      Processing path: {item_path}")
            
            # Use ScoutSuite's getValueAt to get the actual resource data
            resource_data = self.get_value_at(item_path, data)
            
            # Parse path components using ScoutSuite's logic
            path_parts = item_path.split('.')
            resource_path_parts = resource_path.split('.') if resource_path else []
            
            # Extract region using ScoutSuite's pattern
            region = None
            for i, part in enumerate(path_parts):
                if i > 0 and path_parts[i-1] == 'regions':
                    region = part
                    break
            
            # Extract resource ID using ScoutSuite's patterns
            resource_id = None
            resource_name = None
            
            # Look for AWS resource ID patterns - prioritize the last matching ID in the path
            aws_id_patterns = [
                'i-',           # EC2 instances
                'sg-',          # Security groups
                'vpc-',         # VPCs
                'subnet-',      # Subnets
                'vol-',         # EBS volumes
                'ami-',         # AMI images
                'snap-',        # EBS snapshots
                'rtb-',         # Route tables
                'igw-',         # Internet gateways
                'nat-',         # NAT gateways
                'eni-',         # Network interfaces
                'acl-',         # Network ACLs
                'pcx-',         # Peering connections
                'fl-',          # Flow logs
                'dopt-',        # DHCP options
                'eipalloc-',    # Elastic IP allocations
                'eipassoc-',    # Elastic IP associations
                'vpce-',        # VPC endpoints
                'vgw-',         # Virtual gateways
                'cgw-',         # Customer gateways
                'vpn-',         # VPN connections
            ]
            for part in reversed(path_parts):  # Start from the end to get the most specific resource
                if any(part.startswith(pattern) for pattern in aws_id_patterns) or part.startswith('arn:'):
                    resource_id = part
                    break
            
            # For IAM and other services, use the last meaningful component
            if not resource_id:
                # Skip generic path components but keep meaningful ones
                skip_components = {'services', 'regions', 'id', 'vpcs', 'subnets', 'instances', 'security_groups'}
                
                # Service-specific resource extraction using ScoutSuite patterns
                if service == 'iam':
                    # IAM resource extraction - find the actual IAM resource name
                    iam_containers = ['policies', 'users', 'roles', 'groups', 'password_policy', 'root_account', 'credential_reports', 'inline_policies']
                    iam_config_terms = ['notconfigured', 'MaxPasswordAge', 'MinimumPasswordLength', 'PasswordReusePrevention', 'assume_role_policy', 'PolicyDocument', 'Statement']
                    
                    # Look for the resource name that comes after a container
                    for i, part in enumerate(path_parts):
                        if i > 0 and path_parts[i-1] in ['roles', 'users', 'policies', 'groups']:
                            if (part not in skip_components and 
                                part not in iam_containers and
                                part not in iam_config_terms and
                                len(part) > 2 and not part.isdigit()):
                                resource_id = part
                                break
                    
                    # Fallback to reverse search if not found
                    if not resource_id:
                        for part in reversed(path_parts):
                            if (part not in skip_components and 
                                part not in iam_containers and
                                part not in iam_config_terms and
                                len(part) > 2 and not part.isdigit()):
                                resource_id = part
                                break
                            
                elif service == 's3':
                    # S3 resource extraction - skip configuration settings
                    s3_config_terms = ['secure_transport_enabled', 'logging', 'mfa_delete', 'versioning', 'encryption', 'public_access_block_configuration']
                    s3_containers = ['buckets', 'keys', 'objects', 'acls']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in s3_containers and
                            part not in s3_config_terms and
                            len(part) > 2):
                            resource_id = part
                            break
                            
                elif service == 'ec2':
                    # EC2 resource extraction - handle regional settings and other resources
                    ec2_containers = ['instances', 'security_groups', 'volumes', 'snapshots', 'images', 'regional_settings']
                    ec2_config_terms = ['NoDefaultEBSEncryption', 'ebs_encryption_default', 'ebs_default_encryption_key_id']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in ec2_containers and
                            part not in ec2_config_terms and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'cloudtrail':
                    # CloudTrail resource extraction
                    cloudtrail_containers = ['trails', 'regions']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in cloudtrail_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'cloudwatch':
                    # CloudWatch resource extraction
                    cloudwatch_containers = ['alarms', 'metric_filters']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in cloudwatch_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'rds':
                    # RDS resource extraction
                    rds_containers = ['instances', 'snapshots', 'parameter_groups', 'security_groups', 'subnet_groups']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in rds_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'elb' or service == 'elbv2':
                    # ELB resource extraction
                    elb_containers = ['elbs', 'lbs', 'elb_policies', 'listeners']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in elb_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'awslambda':
                    # Lambda resource extraction
                    lambda_containers = ['functions']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in lambda_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'kms':
                    # KMS resource extraction
                    kms_containers = ['keys']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in kms_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'sns':
                    # SNS resource extraction
                    sns_containers = ['topics']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in sns_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'sqs':
                    # SQS resource extraction
                    sqs_containers = ['queues']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in sqs_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'cloudfront':
                    # CloudFront resource extraction
                    cloudfront_containers = ['distributions']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in cloudfront_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'route53':
                    # Route53 resource extraction
                    route53_containers = ['hosted_zones', 'domains']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in route53_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'dynamodb':
                    # DynamoDB resource extraction
                    dynamodb_containers = ['tables']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in dynamodb_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'secretsmanager':
                    # Secrets Manager resource extraction
                    secrets_containers = ['secrets']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in secrets_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'acm':
                    # ACM resource extraction
                    acm_containers = ['certificates']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in acm_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'config':
                    # Config resource extraction
                    config_containers = ['recorders', 'rules']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in config_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'cloudformation':
                    # CloudFormation resource extraction
                    cloudformation_containers = ['stacks']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in cloudformation_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'ses':
                    # SES resource extraction
                    ses_containers = ['identities']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in ses_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'emr':
                    # EMR resource extraction
                    emr_containers = ['clusters']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in emr_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'redshift':
                    # Redshift resource extraction
                    redshift_containers = ['clusters', 'parameter_groups', 'security_groups']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in redshift_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'elasticache':
                    # ElastiCache resource extraction
                    elasticache_containers = ['clusters', 'parameter_groups', 'security_groups', 'subnet_groups']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in elasticache_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                elif service == 'vpc':
                    # VPC resource extraction
                    vpc_containers = ['vpcs', 'subnets', 'network_acls', 'peering_connections', 'flow_logs']
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            part not in vpc_containers and
                            len(part) > 2 and not part.isdigit()):
                            resource_id = part
                            break
                            
                else:
                    # Generic service resource extraction
                    for part in reversed(path_parts):
                        if (part not in skip_components and 
                            not part.endswith('s') and 
                            len(part) > 2 and 
                            not part.isdigit()):
                            resource_id = part
                            break
                
                # If still no resource_id, generate one from the finding using ScoutSuite patterns
                if not resource_id:
                    if service == 'iam':
                        # For IAM, use a more descriptive approach based on path analysis
                        if 'role' in item_path.lower():
                            resource_id = f"iam_role_{finding_id}"
                        elif 'policy' in item_path.lower():
                            resource_id = f"iam_policy_{finding_id}"
                        elif 'user' in item_path.lower():
                            resource_id = f"iam_user_{finding_id}"
                        elif 'group' in item_path.lower():
                            resource_id = f"iam_group_{finding_id}"
                        elif 'password_policy' in item_path.lower():
                            resource_id = "iam_password_policy"
                        elif 'root_account' in item_path.lower():
                            resource_id = "iam_root_account"
                        else:
                            resource_id = f"iam_{finding_id}"
                    elif service == 'ec2':
                        # For EC2, be more specific about resource types
                        if 'regional_settings' in item_path.lower():
                            # Extract region from path for regional settings
                            region_part = region if region else 'global'
                            resource_id = f"ec2_regional_settings_{region_part}"
                        elif 'security_group' in item_path.lower():
                            resource_id = f"ec2_security_group_{finding_id}"
                        elif 'instance' in item_path.lower():
                            resource_id = f"ec2_instance_{finding_id}"
                        elif 'volume' in item_path.lower():
                            resource_id = f"ec2_volume_{finding_id}"
                        else:
                            resource_id = f"ec2_{finding_id}"
                    elif service == 's3':
                        # For S3, try to extract bucket name from path
                        if 'bucket' in item_path.lower():
                            resource_id = f"s3_bucket_{finding_id}"
                        else:
                            resource_id = f"s3_{finding_id}"
                    elif service == 'cloudtrail':
                        if 'trail' in item_path.lower():
                            resource_id = f"cloudtrail_trail_{finding_id}"
                        elif 'region' in item_path.lower():
                            region_part = region if region else 'global'
                            resource_id = f"cloudtrail_region_{region_part}"
                        else:
                            resource_id = f"cloudtrail_{finding_id}"
                    elif service == 'config':
                        if 'recorder' in item_path.lower():
                            resource_id = f"config_recorder_{finding_id}"
                        elif 'rule' in item_path.lower():
                            resource_id = f"config_rule_{finding_id}"
                        else:
                            resource_id = f"config_{finding_id}"
                    else:
                        # For other services, use service name and finding ID
                        resource_id = f"{service}_{finding_id}"
            
            # Extract resource type using ScoutSuite's comprehensive container logic
            resource_type = None
            resource_containers = {
                # EC2 resources
                'instances': 'instance',
                'security_groups': 'security_group',
                'vpcs': 'vpc',
                'subnets': 'subnet',
                'volumes': 'volume',
                'snapshots': 'snapshot',
                'images': 'image',
                'regional_settings': 'configuration',
                'network_acls': 'network_acl',
                'peering_connections': 'peering_connection',
                'flow_logs': 'flow_log',
                
                # IAM resources
                'policies': 'policy',
                'users': 'user',
                'roles': 'role',
                'groups': 'group',
                'credential_reports': 'credential_report',
                'inline_policies': 'inline_policy',
                'password_policy': 'configuration',
                'root_account': 'configuration',
                'MaxPasswordAge': 'configuration',
                'MinimumPasswordLength': 'configuration',
                'PasswordReusePrevention': 'configuration',
                
                # S3 resources
                'buckets': 'bucket',
                'keys': 'key',
                'objects': 'object',
                'acls': 'acl',
                'public_access_block_configuration': 'configuration',
                
                # CloudFront resources
                'distributions': 'distribution',
                
                # Lambda resources
                'functions': 'function',
                
                # RDS resources
                'parameter_groups': 'parameter_group',
                'security_groups': 'security_group',
                'subnet_groups': 'subnet_group',
                
                # ElastiCache resources
                'clusters': 'cluster',
                
                # ELB resources
                'elbs': 'load_balancer',
                'lbs': 'load_balancer',
                'elb_policies': 'elb_policy',
                'listeners': 'listener',
                
                # CloudTrail resources
                'trails': 'trail',
                'regions': 'region',
                
                # CloudWatch resources
                'alarms': 'alarm',
                'metric_filters': 'metric_filter',
                
                # Config resources
                'recorders': 'recorder',
                'rules': 'rule',
                
                # KMS resources
                'keys': 'key',
                
                # SNS resources
                'topics': 'topic',
                
                # SQS resources
                'queues': 'queue',
                
                # SES resources
                'identities': 'identity',
                
                # CloudFormation resources
                'stacks': 'stack',
                
                # ACM resources
                'certificates': 'certificate',
                
                # Route53 resources
                'hosted_zones': 'hosted_zone',
                'domains': 'domain',
                
                # DynamoDB resources
                'tables': 'table',
                
                # Secrets Manager resources
                'secrets': 'secret',
                
                # EMR resources
                'repositories': 'repository',
                
                # Redshift resources
                
                # General configuration items
                'NoDefaultEBSEncryption': 'configuration',
                'external_attack_surface': 'attack_surface',
                'permissions': 'permission'
            }
            
            # Find the resource container in the path - prioritize the last container
            for part in reversed(path_parts):  # Start from the end to get the most specific container
                if part in resource_containers:
                    resource_type = resource_containers[part]
                    break
            
            # Fallback resource type inference using ScoutSuite patterns
            if not resource_type:
                # Try to infer resource type from path or finding using ScoutSuite logic
                if service == 'iam':
                    if any(term in item_path.lower() for term in ['password', 'mfa', 'root']) or any(term in item_path for term in ['MaxPasswordAge', 'MinimumPasswordLength', 'PasswordReusePrevention']):
                        resource_type = 'configuration'
                    elif 'role' in item_path.lower():
                        resource_type = 'role'
                    elif 'user' in item_path.lower():
                        resource_type = 'user'
                    elif 'group' in item_path.lower():
                        resource_type = 'group'
                    elif 'policy' in item_path.lower():
                        resource_type = 'policy'
                    elif 'credential' in item_path.lower():
                        resource_type = 'credential_report'
                    else:
                        resource_type = 'iam_resource'
                elif service == 'ec2':
                    if 'regional_settings' in item_path.lower() or 'NoDefaultEBSEncryption' in item_path:
                        resource_type = 'configuration'
                    elif 'security_group' in item_path.lower():
                        resource_type = 'security_group'
                    elif 'instance' in item_path.lower():
                        resource_type = 'instance'
                    elif 'volume' in item_path.lower():
                        resource_type = 'volume'
                    elif 'snapshot' in item_path.lower():
                        resource_type = 'snapshot'
                    elif 'image' in item_path.lower():
                        resource_type = 'image'
                    else:
                        resource_type = 'ec2_resource'
                elif service == 's3':
                    if 'bucket' in item_path.lower():
                        resource_type = 'bucket'
                    elif 'key' in item_path.lower() or 'object' in item_path.lower():
                        resource_type = 'object'
                    else:
                        resource_type = 's3_resource'
                elif service == 'cloudtrail':
                    if 'trail' in item_path.lower():
                        resource_type = 'trail'
                    elif 'region' in item_path.lower():
                        resource_type = 'region'
                    else:
                        resource_type = 'cloudtrail_resource'
                elif service == 'cloudwatch':
                    if 'alarm' in item_path.lower():
                        resource_type = 'alarm'
                    elif 'metric' in item_path.lower():
                        resource_type = 'metric_filter'
                    else:
                        resource_type = 'cloudwatch_resource'
                elif service == 'rds':
                    if 'instance' in item_path.lower():
                        resource_type = 'instance'
                    elif 'snapshot' in item_path.lower():
                        resource_type = 'snapshot'
                    elif 'parameter_group' in item_path.lower():
                        resource_type = 'parameter_group'
                    elif 'security_group' in item_path.lower():
                        resource_type = 'security_group'
                    else:
                        resource_type = 'rds_resource'
                elif service == 'elb' or service == 'elbv2':
                    if 'elb' in item_path.lower() or 'load_balancer' in item_path.lower():
                        resource_type = 'load_balancer'
                    elif 'listener' in item_path.lower():
                        resource_type = 'listener'
                    elif 'policy' in item_path.lower():
                        resource_type = 'elb_policy'
                    else:
                        resource_type = 'elb_resource'
                elif service == 'awslambda':
                    if 'function' in item_path.lower():
                        resource_type = 'function'
                    else:
                        resource_type = 'lambda_resource'
                elif service == 'kms':
                    if 'key' in item_path.lower():
                        resource_type = 'key'
                    else:
                        resource_type = 'kms_resource'
                elif service == 'sns':
                    if 'topic' in item_path.lower():
                        resource_type = 'topic'
                    else:
                        resource_type = 'sns_resource'
                elif service == 'sqs':
                    if 'queue' in item_path.lower():
                        resource_type = 'queue'
                    else:
                        resource_type = 'sqs_resource'
                elif service == 'cloudfront':
                    if 'distribution' in item_path.lower():
                        resource_type = 'distribution'
                    else:
                        resource_type = 'cloudfront_resource'
                elif service == 'route53':
                    if 'hosted_zone' in item_path.lower():
                        resource_type = 'hosted_zone'
                    elif 'domain' in item_path.lower():
                        resource_type = 'domain'
                    else:
                        resource_type = 'route53_resource'
                elif service == 'dynamodb':
                    if 'table' in item_path.lower():
                        resource_type = 'table'
                    else:
                        resource_type = 'dynamodb_resource'
                elif service == 'secretsmanager':
                    if 'secret' in item_path.lower():
                        resource_type = 'secret'
                    else:
                        resource_type = 'secrets_resource'
                elif service == 'acm':
                    if 'certificate' in item_path.lower():
                        resource_type = 'certificate'
                    else:
                        resource_type = 'acm_resource'
                elif service == 'config':
                    if 'recorder' in item_path.lower():
                        resource_type = 'recorder'
                    elif 'rule' in item_path.lower():
                        resource_type = 'rule'
                    else:
                        resource_type = 'config_resource'
                elif service == 'cloudformation':
                    if 'stack' in item_path.lower():
                        resource_type = 'stack'
                    else:
                        resource_type = 'cloudformation_resource'
                elif service == 'ses':
                    if 'identity' in item_path.lower():
                        resource_type = 'identity'
                    else:
                        resource_type = 'ses_resource'
                elif service == 'emr':
                    if 'cluster' in item_path.lower():
                        resource_type = 'cluster'
                    else:
                        resource_type = 'emr_resource'
                elif service == 'redshift':
                    if 'cluster' in item_path.lower():
                        resource_type = 'cluster'
                    elif 'parameter_group' in item_path.lower():
                        resource_type = 'parameter_group'
                    elif 'security_group' in item_path.lower():
                        resource_type = 'security_group'
                    else:
                        resource_type = 'redshift_resource'
                elif service == 'elasticache':
                    if 'cluster' in item_path.lower():
                        resource_type = 'cluster'
                    elif 'parameter_group' in item_path.lower():
                        resource_type = 'parameter_group'
                    elif 'security_group' in item_path.lower():
                        resource_type = 'security_group'
                    elif 'subnet_group' in item_path.lower():
                        resource_type = 'subnet_group'
                    else:
                        resource_type = 'elasticache_resource'
                elif service == 'vpc':
                    if 'vpc' in item_path.lower() and 'subnet' not in item_path.lower():
                        resource_type = 'vpc'
                    elif 'subnet' in item_path.lower():
                        resource_type = 'subnet'
                    elif 'network_acl' in item_path.lower():
                        resource_type = 'network_acl'
                    elif 'peering' in item_path.lower():
                        resource_type = 'peering_connection'
                    elif 'flow_log' in item_path.lower():
                        resource_type = 'flow_log'
                    else:
                        resource_type = 'vpc_resource'
                else:
                    # Generic fallback
                    resource_type = f"{service}_resource"
            
            # Extract resource details from the actual data
            details = {}
            if isinstance(resource_data, dict):
                # Get resource name from data
                resource_name = (resource_data.get('name') or 
                               resource_data.get('Name') or 
                               resource_data.get('RoleName') or
                               resource_data.get('UserName') or
                               resource_data.get('PolicyName') or
                               resource_data.get('id') or 
                               resource_data.get('arn') or 
                               resource_id)
                
                # Store key details
                detail_keys = ['name', 'Name', 'RoleName', 'UserName', 'PolicyName', 'id', 'arn', 'state', 'status', 'region', 'availability_zone']
                for key in detail_keys:
                    if key in resource_data:
                        details[key] = resource_data[key]
            
            # Use resource_id as name if no name found
            if not resource_name:
                resource_name = resource_id
                
            # For IAM resources, extract the actual resource name from the path and data
            if service == 'iam':
                # Try to get the role/user/policy name from the path structure
                # IAM paths typically look like: services.iam.roles.RoleName.assume_role_policy.PolicyDocument.Statement.0
                role_name_from_path = None
                for i, part in enumerate(path_parts):
                    if i > 0 and path_parts[i-1] in ['roles', 'users', 'policies', 'groups']:
                        role_name_from_path = part
                        break
                
                # Use the name from path if found, otherwise try resource data
                if role_name_from_path and role_name_from_path not in ['assume_role_policy', 'inline_policies', 'PolicyDocument', 'Statement']:
                    resource_id = role_name_from_path
                    resource_name = role_name_from_path
                elif isinstance(resource_data, dict):
                    if resource_type == 'role' and 'RoleName' in resource_data:
                        resource_name = resource_data['RoleName']
                        resource_id = resource_data['RoleName']
                    elif resource_type == 'user' and 'UserName' in resource_data:
                        resource_name = resource_data['UserName']
                        resource_id = resource_data['UserName']
                    elif resource_type == 'policy' and 'PolicyName' in resource_data:
                        resource_name = resource_data['PolicyName']
                        resource_id = resource_data['PolicyName']
                    elif 'name' in resource_data:
                        resource_name = resource_data['name']
                        resource_id = resource_data['name']
                
                # If we still have generic names, try to extract from the parent path
                if resource_id in ['Statement', 'PolicyDocument', 'assume_role_policy'] or not resource_id:
                    # Go up the path to find the actual IAM resource
                    parent_path_parts = item_path.split('.')
                    for i in range(len(parent_path_parts) - 1, -1, -1):
                        if i > 0 and parent_path_parts[i-1] in ['roles', 'users', 'policies', 'groups']:
                            potential_name = parent_path_parts[i]
                            if potential_name not in ['assume_role_policy', 'inline_policies', 'PolicyDocument', 'Statement']:
                                resource_id = potential_name
                                resource_name = potential_name
                                break
            
            # Handle configuration findings and IAM policy settings
            config_terms = ['notconfigured', 'false', 'true', 'maxpasswordage', 'minimumpasswordlength', 'expirepasswords', 'passwordreuseprevention', 'mfa_active', 'mfa_active_hardware', 'password_policy']
            
            # Check if this is a configuration finding or needs special handling
            is_config_finding = (resource_id and resource_id.lower() in config_terms) or (service == 'iam' and resource_id in ['MaxPasswordAge', 'MinimumPasswordLength', 'PasswordReusePrevention'])
            
            # Check for S3 configuration findings
            s3_config_findings = service == 's3' and resource_id in ['secure_transport_enabled', 'logging', 'mfa_delete', 'versioning']
            
            if is_config_finding or (service == 'iam' and any(term in item_path.lower() for term in ['password', 'mfa', 'root'])) or (service == 'ec2' and resource_id in ['NoDefaultEBSEncryption']) or s3_config_findings:
                if service == 'iam':
                    # IAM configuration findings - use the specific setting name
                    if 'MaxPasswordAge' in item_path:
                        resource_id = 'MaxPasswordAge'
                        resource_name = 'Password Age Policy'
                    elif 'MinimumPasswordLength' in item_path:
                        resource_id = 'MinimumPasswordLength'
                        resource_name = 'Password Length Policy'
                    elif 'PasswordReusePrevention' in item_path:
                        resource_id = 'PasswordReusePrevention'
                        resource_name = 'Password Reuse Policy'
                    elif 'password_policy' in item_path:
                        resource_id = 'password_policy'
                        resource_name = 'Password Policy'
                    elif 'root_account' in item_path or 'mfa_active' in item_path:
                        resource_id = 'root_account'
                        resource_name = 'Root Account'
                    else:
                        resource_id = f"iam_{finding_id}"
                        resource_name = finding_id.replace('_', ' ').title()
                    resource_type = 'configuration'
                elif service == 'ec2':
                    # EC2 configuration findings
                    if 'NoDefaultEBSEncryption' in item_path:
                        resource_id = f"ebs_encryption_{region or 'global'}"
                        resource_name = f"EBS Default Encryption ({region or 'Global'})"
                        resource_type = 'configuration'
                    else:
                        resource_id = f"{service}_{finding_id}"
                        resource_name = finding_id.replace('_', ' ').title()
                        resource_type = 'configuration'
                elif service == 's3':
                    # S3 configuration findings - try to extract bucket name from path
                    bucket_name = None
                    for part in path_parts:
                        if part not in ['services', 's3', 'buckets'] and part not in ['secure_transport_enabled', 'logging', 'mfa_delete', 'versioning']:
                            bucket_name = part
                            break
                    
                    if bucket_name:
                        resource_id = bucket_name
                        resource_name = bucket_name
                        resource_type = 'bucket'
                    else:
                        resource_id = f"s3_{finding_id}"
                        resource_name = finding_id.replace('_', ' ').title()
                        resource_type = 'configuration'
                else:
                    resource_id = f"{service}_{finding_id}"
                    resource_name = finding_id.replace('_', ' ').title()
                    resource_type = 'configuration'
            
            # If we still don't have a proper resource_name, generate one
            if not resource_name or resource_name == resource_id:
                if service == 'iam':
                    if resource_type == 'role':
                        resource_name = f"IAM Role ({resource_id})"
                    elif resource_type == 'policy':
                        resource_name = f"IAM Policy ({resource_id})"
                    elif resource_type == 'user':
                        resource_name = f"IAM User ({resource_id})"
                    else:
                        resource_name = resource_id
                else:
                    resource_name = resource_id
            
            # Create event hash for deduplication
            event_data = f"{service}:{finding_id}:{resource_id}:{item_path}"
            event_hash = hashlib.sha256(event_data.encode()).hexdigest()
            
            result = {
                'resource_id': resource_id,
                'resource_name': resource_name,
                'resource_type': resource_type,
                'region': region,
                'item_path': item_path,
                'details': details,
                'event_hash': event_hash
            }
            
            self.logger.debug(f"        -> {result['resource_type']}: {result['resource_id']} in {result['region'] or 'global'}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error extracting event from path {item_path}: {e}")
            if self.debug:
                import traceback
                self.logger.debug(f"Full traceback: {traceback.format_exc()}")
            return None
        
    def save_to_db(self, scan_info, findings, events):
        """Save data to database using SQLAlchemy"""
        self.logger.info("Connecting to database...")
        
        # Check if this exact scan already exists
        existing_scan = self.session.query(self.ScoutScan).filter_by(
            account_id=scan_info['account_id'],
            scan_time=scan_info['scan_time']
        ).first()
        
        if existing_scan:
            self.logger.info(f"Scan for account {scan_info['account_id']} at {scan_info['scan_time']} already exists (ID: {existing_scan.id})")
            return []
        
        # Insert scan record
        self.logger.info(f"Saving new scan for account {scan_info['account_id']}...")
        scan = self.ScoutScan(
            account_id=scan_info['account_id'],
            scan_time=scan_info['scan_time'],
            version=scan_info['version'],
            total_findings=scan_info['total_findings']
        )
        self.session.add(scan)
        self.session.flush()  # Get the ID
        scan_id = scan.id
        self.logger.info(f"Created scan record with ID: {scan_id}")
        
        new_events = []
        
        # Insert findings and events
        self.logger.info(f"Processing {len(findings)} findings...")
        for i, finding in enumerate(findings):
            if i % 10 == 0:  # Progress indicator
                self.logger.info(f"  Processing finding {i+1}/{len(findings)}")
                
            finding_obj = self.ScoutFinding(
                scan_id=scan_id,
                service=finding['service'],
                finding_id=finding['finding_id'],
                level=finding['level'],
                flagged_items=finding['flagged_items'],
                checked_items=finding['checked_items'],
                description=finding['description']
            )
            self.session.add(finding_obj)
            self.session.flush()  # Get the ID
            finding_db_id = finding_obj.id
            
            # Insert events for this finding
            for event in finding.get('events', []):
                # Check if event already exists (globally, not just this scan)
                existing = self.session.query(self.ScoutEvent).filter_by(event_hash=event['event_hash']).first()
                
                if existing:
                    # Update last_seen timestamp only
                    existing.last_seen = datetime.now()
                    event_id = existing.id
                    self.logger.debug(f"        Updated existing event: {event['resource_id']}")
                else:
                    # Insert new event
                    # Check if this is an initial scan
                    is_initial_scan = self.email_config and self.email_config.get('initial_scan', False)
                    
                    event_obj = self.ScoutEvent(
                        resource_id=event['resource_id'],
                        resource_name=event['resource_name'],
                        resource_type=event['resource_type'],
                        region=event['region'],
                        details=event['details'],
                        event_hash=event['event_hash'],
                        notified=is_initial_scan  # Mark as notified if initial scan
                    )
                    self.session.add(event_obj)
                    self.session.flush()
                    event_id = event_obj.id
                    self.logger.debug(f"        Added new event: {event['resource_id']}")
                    
                    # Only add to notification queue if not initial scan
                    if not is_initial_scan:
                        new_events.append({
                            'finding': finding,
                            'event': event,
                            'scan_info': scan_info
                        })
                
                # Link event to this scan's finding
                event_finding = self.ScoutEventFinding(
                    event_id=event_id,
                    finding_id=finding_db_id,
                    scan_id=scan_id
                )
                self.session.add(event_finding)
        
        self.logger.info("Committing to database...")
        # Mark events as resolved if they haven't been seen in this scan
        self.logger.info("Checking for resolved events...")
        current_event_hashes = {event['event_hash'] for finding in findings for event in finding.get('events', [])}
        
        # Find events for this account that weren't in this scan
        account_events = self.session.query(self.ScoutEvent).join(
            self.ScoutEventFinding, self.ScoutEvent.id == self.ScoutEventFinding.event_id
        ).join(
            self.ScoutFinding, self.ScoutEventFinding.finding_id == self.ScoutFinding.id
        ).join(
            self.ScoutScan, self.ScoutFinding.scan_id == self.ScoutScan.id
        ).filter(
            self.ScoutScan.account_id == scan_info['account_id'],
            self.ScoutEvent.resolved_at.is_(None)
        ).all()
        
        resolved_count = 0
        for event in account_events:
            if event.event_hash not in current_event_hashes:
                event.resolved_at = datetime.now()
                resolved_count += 1
        
        self.session.commit()
        
        # Generate detailed statistics
        self._print_scan_statistics(scan_info, findings, events, new_events, resolved_count)
        
        self.logger.info(f"Saved scan {scan_id} with {len(findings)} findings and {len(events)} events to database")
        self.logger.info(f"Found {len(new_events)} new events, marked {resolved_count} events as resolved")
        
        # Send notifications for new events (one email per scan)
        if new_events and self.email_config:
            self.logger.info("Sending email notifications...")
            self._send_notifications(new_events, scan_id)
        elif not self.email_config:
            self.logger.info("Email notifications disabled")
        
        return new_events
    
    def _print_scan_statistics(self, scan_info, findings, events, new_events, resolved_count):
        """Print detailed scan statistics"""
        print(f"\n{'='*60}")
        print(f"SCAN RESULTS FOR ACCOUNT: {scan_info['account_id']}")
        print(f"{'='*60}")
        print(f"Scan Time: {scan_info['scan_time']}")
        print(f"ScoutSuite Version: {scan_info['version']}")
        print(f"Total Findings: {len(findings)}")
        print(f"Total Events: {len(events)}")
        print(f"New Events: {len(new_events)}")
        print(f"Resolved Events: {resolved_count}")
        
        # Findings by service
        service_stats = {}
        for finding in findings:
            service = finding['service']
            if service not in service_stats:
                service_stats[service] = {'findings': 0, 'events': 0}
            service_stats[service]['findings'] += 1
            service_stats[service]['events'] += len(finding.get('events', []))
        
        if service_stats:
            print(f"\nFINDINGS BY SERVICE:")
            for service, stats in sorted(service_stats.items()):
                print(f"  {service}: {stats['findings']} findings, {stats['events']} events")
        
        # Findings by severity
        severity_stats = {}
        for finding in findings:
            level = finding['level']
            if level not in severity_stats:
                severity_stats[level] = {'findings': 0, 'events': 0}
            severity_stats[level]['findings'] += 1
            severity_stats[level]['events'] += len(finding.get('events', []))
        
        if severity_stats:
            print(f"\nFINDINGS BY SEVERITY:")
            for level in ['critical', 'high', 'medium', 'low', 'warning', 'danger']:
                if level in severity_stats:
                    stats = severity_stats[level]
                    print(f"  {level.upper()}: {stats['findings']} findings, {stats['events']} events")
        
        # Events by resource type
        resource_stats = {}
        for event in events:
            resource_type = event['resource_type']
            region = event['region'] or 'global'
            key = f"{resource_type} ({region})"
            resource_stats[key] = resource_stats.get(key, 0) + 1
        
        if resource_stats:
            print(f"\nEVENTS BY RESOURCE TYPE:")
            for resource_key, count in sorted(resource_stats.items(), key=lambda x: x[1], reverse=True):
                print(f"  {resource_key}: {count} events")
        
        # New events by severity (if any)
        if new_events:
            new_severity_stats = {}
            for event_data in new_events:
                level = event_data['finding']['level']
                new_severity_stats[level] = new_severity_stats.get(level, 0) + 1
            
            print(f"\nNEW EVENTS BY SEVERITY:")
            for level in ['critical', 'high', 'medium', 'low', 'warning', 'danger']:
                if level in new_severity_stats:
                    print(f"  {level.upper()}: {new_severity_stats[level]} new events")
        
        print(f"{'='*60}\n")
        
    def output_json(self, scan_info, findings, events):
        """Output parsed data as JSON to console (debug mode only)"""
        if self.debug:
            output = {
                'scan_info': {
                    'account_id': scan_info['account_id'],
                    'scan_time': scan_info['scan_time'].isoformat(),
                    'version': scan_info['version'],
                    'total_findings': scan_info['total_findings']
                },
                'findings': findings,
                'total_events': len(events)
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            # Show statistics even in non-debug mode
            print(f"\n{'='*60}")
            print(f"SCAN RESULTS FOR ACCOUNT: {scan_info['account_id']}")
            print(f"{'='*60}")
            print(f"Scan Time: {scan_info['scan_time']}")
            print(f"ScoutSuite Version: {scan_info['version']}")
            print(f"Total Findings: {len(findings)}")
            print(f"Total Events: {len(events)}")
            print(f"{'='*60}\n")
            self.logger.info("Use --debug flag to see detailed JSON output")
        
    def _send_notifications(self, new_events, scan_id):
        """Send email notifications for new events with graceful error handling"""
        if not self.email_config or not self.email_config.get('recipients'):
            self.logger.debug("Email notifications disabled or no recipients configured")
            return
            
        try:
            # Filter events by severity
            notify_severities = self.email_config.get('notify_severities', ['medium', 'high', 'critical'])
            filtered_events = [e for e in new_events if e['finding']['level'].lower() in notify_severities]
            
            if not filtered_events:
                self.logger.debug("No events match notification severity criteria")
                return
                
            # Group events by severity
            events_by_severity = {}
            for event_data in filtered_events:
                severity = event_data['finding']['level']
                if severity not in events_by_severity:
                    events_by_severity[severity] = []
                events_by_severity[severity].append(event_data)
            
            # Create email content
            subject = f"ScoutSuite Alert: {len(filtered_events)} new security findings"
            body = self._create_email_body(events_by_severity, filtered_events[0]['scan_info'])
            
            # Attempt to send email with fallback handling
            email_sent = False
            last_error = None
            
            # Try AWS SES first if configured
            if self.email_config.get('aws_region') and AWS_AVAILABLE:
                try:
                    self._send_via_ses(subject, body)
                    email_sent = True
                except Exception as ses_error:
                    last_error = ses_error
                    self.logger.warning(f"AWS SES delivery failed, trying SMTP fallback: {ses_error}")
            
            # Fallback to SMTP if SES failed or not configured
            if not email_sent:
                try:
                    self._send_via_smtp(subject, body)
                    email_sent = True
                except Exception as smtp_error:
                    last_error = smtp_error
                    self.logger.error(f"SMTP delivery also failed: {smtp_error}")
            
            if email_sent:
                # Mark all events from this scan as notified only if email was sent successfully
                if self.session:
                    try:
                        event_hashes = [e['event']['event_hash'] for e in new_events]
                        self.session.query(self.ScoutEvent).filter(
                            self.ScoutEvent.event_hash.in_(event_hashes)
                        ).update({self.ScoutEvent.notified: True}, synchronize_session=False)
                        self.session.commit()
                        self.logger.info(f"Successfully sent notifications for {len(filtered_events)} new events")
                    except Exception as db_error:
                        self.logger.error(f"Failed to mark events as notified in database: {db_error}")
                        # Don't re-raise - email was sent successfully
            else:
                # Log comprehensive error but don't fail the entire scan
                self.logger.error(f"All email delivery methods failed. Last error: {last_error}")
                self.logger.warning(f"Scan completed successfully but {len(filtered_events)} security events could not be emailed")
                self.logger.info("Please check email configuration in .env file:")
                self.logger.info("  - SMTP settings: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD")
                self.logger.info("  - AWS SES settings: AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
                self.logger.info("  - Recipient settings: EMAIL_RECIPIENTS")
                
        except Exception as e:
            # Catch any other unexpected errors to prevent scan failure
            self.logger.error(f"Unexpected error in notification system: {e}")
            self.logger.warning("Scan completed successfully but notification system encountered an error")
            if self.debug:
                import traceback
                self.logger.debug(f"Full notification error traceback: {traceback.format_exc()}")
    
    def _create_email_body(self, events_by_severity, scan_info):
        """Create HTML email body"""
        html = f"""
        <html>
        <body>
        <h2>ScoutSuite Security Alert</h2>
        <p><strong>Account:</strong> {scan_info['account_id']}</p>
        <p><strong>Scan Time:</strong> {scan_info['scan_time']}</p>
        <p><strong>Version:</strong> {scan_info['version']}</p>
        <hr>
        """
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in events_by_severity:
                events = events_by_severity[severity]
                html += f"<h3>{severity.upper()} Severity ({len(events)} events)</h3><ul>"
                
                for event_data in events:
                    finding = event_data['finding']
                    event = event_data['event']
                    html += f"""
                    <li>
                        <strong>{finding['finding_id']}</strong> ({finding['service']})<br>
                        Resource: {event['resource_name'] or event['resource_id']} 
                        ({event['resource_type']} in {event['region'] or 'global'})<br>
                        <em>{finding['description']}</em>
                    </li>
                    """
                html += "</ul>"
        
        html += "</body></html>"
        return html
    
    def _send_via_smtp(self, subject, body):
        """Send email via SMTP with graceful error handling"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.email_config['smtp_from']
            msg['To'] = ', '.join(self.email_config['recipients'])
            
            msg.attach(MIMEText(body, 'html'))
            
            # Connection with timeout to prevent hanging
            server = smtplib.SMTP(self.email_config['smtp_host'], self.email_config['smtp_port'], timeout=30)
            
            try:
                if self.email_config['smtp_use_tls']:
                    server.starttls()
                    
                if self.email_config['smtp_user']:
                    server.login(self.email_config['smtp_user'], self.email_config['smtp_password'])
                    
                server.send_message(msg)
                self.logger.info("Email notification sent successfully via SMTP")
                
            finally:
                try:
                    server.quit()
                except:
                    pass  # Ignore quit errors
                    
        except smtplib.SMTPAuthenticationError as e:
            self.logger.error(f"SMTP authentication failed: Invalid username/password for {self.email_config['smtp_user']}")
            raise Exception(f"Email authentication failed - please check SMTP credentials")
        except smtplib.SMTPRecipientsRefused as e:
            self.logger.error(f"SMTP recipients refused: {e}")
            raise Exception(f"Email recipients rejected by server - please check recipient addresses")
        except smtplib.SMTPServerDisconnected as e:
            self.logger.error(f"SMTP server disconnected unexpectedly: {e}")
            raise Exception(f"Email server connection lost - please check SMTP server status")
        except smtplib.SMTPConnectError as e:
            self.logger.error(f"SMTP connection failed: Cannot connect to {self.email_config['smtp_host']}:{self.email_config['smtp_port']}")
            raise Exception(f"Cannot connect to email server - please check SMTP host and port settings")
        except smtplib.SMTPException as e:
            self.logger.error(f"SMTP error: {e}")
            raise Exception(f"Email delivery failed - SMTP error: {str(e)}")
        except OSError as e:
            self.logger.error(f"Network error connecting to SMTP server: {e}")
            raise Exception(f"Network error - please check internet connection and SMTP server availability")
        except Exception as e:
            self.logger.error(f"Unexpected error sending email via SMTP: {e}")
            raise Exception(f"Email delivery failed - unexpected error: {str(e)}")
    
    def _send_via_ses(self, subject, body):
        """Send email via AWS SES"""
        if not AWS_AVAILABLE:
            raise Exception("boto3 not available for SES")
            
        session = boto3.Session(
            aws_access_key_id=self.email_config.get('aws_access_key'),
            aws_secret_access_key=self.email_config.get('aws_secret_key'),
            region_name=self.email_config['aws_region']
        )
        
        ses = session.client('ses')
        ses.send_email(
            Source=self.email_config['smtp_from'],
            Destination={'ToAddresses': self.email_config['recipients']},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Html': {'Data': body}}
            }
        )
    
    def parse_file(self, file_path):
        """Main parsing function"""
        self.logger.info(f"Starting ScoutSuite parser...")
        
        data = self.parse_js_file(file_path)
        if not data:
            self.logger.error("Failed to parse ScoutSuite file")
            return
            
        scan_info, findings, events = self.extract_findings(data)
        
        if self.db_config:
            try:
                self.logger.info("Database configuration found, attempting to connect...")
                self.logger.debug(f"DB Config: host={self.db_config.get('host')}, user={self.db_config.get('user')}, database={self.db_config.get('database')}")
                self.connect_db()
                self.logger.info("Connected to database successfully")
                self.create_tables()
                self.logger.info("Database tables ready")
                new_events = self.save_to_db(scan_info, findings, events)
                self.logger.info("Processing completed successfully")
                return new_events
            except Exception as e:
                self.logger.error(f"Database error: {e}")
                if self.debug:
                    import traceback
                    self.logger.debug(f"Full traceback: {traceback.format_exc()}")
                self.logger.info("Falling back to JSON output...")
                self.output_json(scan_info, findings, events)
        else:
            self.logger.warning("No database configuration found in .env file")
            self.logger.info("Required: DB_HOST, DB_USER, DB_PASSWORD, DB_NAME")
            self.output_json(scan_info, findings, events)

def main():
    parser = argparse.ArgumentParser(description='Parse ScoutSuite results')
    parser.add_argument('file', help='ScoutSuite results JS file')
    parser.add_argument('--db-host', help='MySQL host')
    parser.add_argument('--db-user', help='MySQL user')
    parser.add_argument('--db-password', help='MySQL password')
    parser.add_argument('--db-name', help='MySQL database name')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    db_config = None
    if all([args.db_host, args.db_user, args.db_password, args.db_name]):
        if not SQLALCHEMY_AVAILABLE:
            print("SQLAlchemy not available. Install with: pip install sqlalchemy pymysql")
            sys.exit(1)
        db_config = {
            'host': args.db_host,
            'user': args.db_user,
            'password': args.db_password,
            'database': args.db_name
        }
    
    parser_instance = ScoutSuiteParser(db_config, debug=args.debug)
    parser_instance.parse_file(args.file)

if __name__ == '__main__':
    main()