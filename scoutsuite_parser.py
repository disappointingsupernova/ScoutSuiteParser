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
        
    def extract_findings(self, data):
        """Extract key findings and individual events from ScoutSuite data"""
        self.logger.info("Extracting findings and events...")
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
        
        # Extract findings from services
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
                
                # Extract individual flagged items
                flagged_items = finding_data.get('items', [])
                if flagged_items:
                    self.logger.debug(f"    {finding_id}: {len(flagged_items)} flagged items")
                    
                for item_path in flagged_items:
                    event = self._extract_event_from_path(item_path, service_name, finding_id, data)
                    if event:
                        finding['events'].append(event)
                        events.append(event)
                
                findings.append(finding)
                
        scan_info['total_findings'] = len(findings)
        self.logger.info(f"Extracted {len(findings)} findings with {len(events)} total events")
        return scan_info, findings, events
        
    def _extract_event_from_path(self, item_path, service, finding_id, data):
        """Extract individual event details from ScoutSuite item path"""
        try:
            self.logger.debug(f"      Processing path: {item_path}")
            
            # Parse the path to extract resource details
            path_parts = item_path.split('.')
            
            # Extract key information from path structure
            region = None
            resource_id = None
            resource_name = None
            resource_type = None
            
            # Analyze path parts to extract information
            for i, part in enumerate(path_parts):
                # Extract region
                if i > 0 and path_parts[i-1] == 'regions':
                    region = part
                
                # Extract resource ID patterns
                if part.startswith(('i-', 'sg-', 'vpc-', 'subnet-', 'vol-', 'ami-', 'arn:', 'user-', 'role-', 'policy-')):
                    resource_id = part
                    
                # For IAM users, roles, policies - the name is often the last part
                if service == 'iam' and i == len(path_parts) - 1 and not resource_id:
                    resource_id = part
                    resource_name = part
                    
                # For other services, try to get the actual resource identifier
                if not resource_id and i == len(path_parts) - 1:
                    resource_id = part
            
            # Navigate to the actual data to get resource details
            current = data
            details = {}
            
            try:
                for part in path_parts:
                    if isinstance(current, dict) and part in current:
                        current = current[part]
                    else:
                        break
                        
                # Extract resource name and details if we found the object
                if isinstance(current, dict):
                    resource_name = resource_name or current.get('name') or current.get('Name') or current.get('id', resource_id)
                    
                    # Store minimal details
                    for key in ['name', 'Name', 'id', 'arn', 'state', 'status', 'region']:
                        if key in current:
                            details[key] = current[key]
            except:
                pass  # If navigation fails, continue with what we have
            
            # Universal resource type extraction - find the resource container
            # Skip 'services', 'regions' and look for actual resource containers
            skip_parts = {'services', 'regions', 'id', 'vpcs'}
            
            for part in path_parts:
                if part not in skip_parts and part.endswith('s') and len(part) > 3:
                    # Handle special cases
                    if part == 'policies':
                        resource_type = 'policy'
                    elif part == 'identities':
                        resource_type = 'identity'
                    elif part == 'repositories':
                        resource_type = 'repository'
                    elif part == 'activities':
                        resource_type = 'activity'
                    elif part == 'security_groups':
                        resource_type = 'security_group'
                    else:
                        resource_type = part.rstrip('s')  # Remove plural
                    break
            
            # If no resource container found, use service name
            if not resource_type:
                resource_type = service
            
            # Create event hash for deduplication
            event_data = f"{service}:{finding_id}:{resource_id}:{item_path}"
            event_hash = hashlib.sha256(event_data.encode()).hexdigest()
            
            result = {
                'resource_id': resource_id or item_path.split('.')[-1],
                'resource_name': resource_name or resource_id,
                'resource_type': resource_type or 'unknown',
                'region': region,
                'item_path': item_path,
                'details': details,
                'event_hash': event_hash
            }
            
            self.logger.debug(f"        -> {result['resource_type']}: {result['resource_id']} in {result['region'] or 'global'}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error extracting event from path {item_path}: {e}")
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