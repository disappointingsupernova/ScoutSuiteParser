# ScoutSuite Parser

A comprehensive parser for NCC Group's open-source ScoutSuite security auditing tool, designed to extract individual resource-level security events from ScoutSuite JavaScript results files and store them in a MySQL/MariaDB database with intelligent deduplication and email notification capabilities.

## TL;DR - Quick Start

```bash
# 1. Setup (first time only)
python3 scout_runner.py --setup
pip3 install sqlalchemy pymysql python-dotenv boto3
mysql -u root -p < setup_database.sql
cp .env.example .env  # Edit with your DB credentials

# 2. Scan all AWS accounts
python3 scout_runner.py

# 3. Scan specific account
python3 scout_runner.py --account production
```

## Usage

### Automated Scanning with Scout Runner
```bash
# Setup ScoutSuite environment (first time only)
python3 scout_runner.py --setup

# Scan all AWS profiles in ~/.aws/config
python3 scout_runner.py

# Scan specific AWS profile
python3 scout_runner.py --account my-profile

# Debug mode
python3 scout_runner.py --debug
```

### Manual Parser Operation
```bash
# Console output (no database)
python3 scoutsuite_parser.py results.js

# Database storage with .env configuration
python3 scoutsuite_parser.py results.js

# Debug mode with detailed logging
python3 scoutsuite_parser.py results.js --debug
```

### Scout Runner Command Line Arguments
```bash
# Setup ScoutSuite environment
python3 scout_runner.py --setup

# Scan all AWS profiles
python3 scout_runner.py

# Scan specific profile
python3 scout_runner.py --account production

# Debug mode with detailed logging
python3 scout_runner.py --debug

# Combine options
python3 scout_runner.py --account staging --debug
```

### Manual Parser Command Line Arguments
```bash
# Override database settings
python3 scoutsuite_parser.py results.js \
  --db-host production-db.company.com \
  --db-user prod_user \
  --db-password secure_password \
  --db-name scoutsuite_db \
  --debug
```

## Architecture Overview

```mermaid
graph TB
    A[AWS Profiles] --> B[Scout Runner]
    B --> C[ScoutSuite Scan]
    C --> D[JS Results Files]
    D --> E[ScoutSuite Parser]
    E --> F{Database Config?}
    F -->|Yes| G[SQLAlchemy ORM]
    F -->|No| H[JSON Console Output]
    G --> I[(MySQL/MariaDB)]
    I --> J[Event Deduplication via SHA256]
    J --> K{New Events?}
    K -->|Yes| L[Email Notifications]
    K -->|No| M[Update last_seen Timestamps]
    L --> N[SMTP/SES Delivery]
    N --> O[Mark Events as Notified]
    M --> P[Mark Resolved Events]
    O --> P
    P --> Q[Commit Transaction]
```

## Core Features

### ScoutSuite Integration
- **JavaScript File Parsing**: Extracts JSON data from ScoutSuite's JavaScript variable assignments (`scoutsuite_results =`)
- **Service Discovery**: Automatically processes all AWS services found in the results
- **Finding Extraction**: Converts ScoutSuite findings into structured database records
- **Resource Path Analysis**: Intelligently parses ScoutSuite's dot-notation paths to extract individual AWS resources

### Individual Resource Tracking
The parser transforms ScoutSuite's aggregated findings into individual resource events by:
- **Path Decomposition**: Breaking down paths like `services.ec2.regions.eu-west-2.vpcs.vpc-123.instances.i-456.security_groups`
- **Resource Identification**: Extracting AWS resource IDs using pattern matching (i-, sg-, vpc-, subnet-, vol-, ami-, arn:, etc.)
- **Region Extraction**: Identifying AWS regions from path structures
- **Resource Type Classification**: Determining resource types from path containers (instances → instance, security_groups → security_group)

### Event Deduplication System
- **SHA256 Hashing**: Creates unique hashes from `service:finding_id:resource_id:item_path` combinations
- **Global Deduplication**: Prevents duplicate events across multiple scans and time periods
- **Timestamp Management**: Updates `last_seen` for existing events, maintains `first_seen` for historical tracking
- **Resolution Detection**: Automatically marks events as resolved when they disappear from subsequent scans

### Email Notification System
- **Severity Filtering**: Configurable notification thresholds (critical, high, medium, low)
- **New Event Detection**: Only notifies on genuinely new security events
- **HTML Email Generation**: Rich email formatting with severity grouping and resource details
- **Dual Delivery Methods**: Support for both SMTP and AWS SES
- **Notification Tracking**: Prevents duplicate notifications via database flags

### Secure Database Connectivity
- **TLS/SSL Support**: Encrypted connections with custom certificate validation
- **Connection Pooling**: SQLAlchemy-managed connection lifecycle
- **Transaction Management**: Atomic operations with rollback capability
- **Performance Optimization**: Comprehensive indexing strategy for query performance

## Database Schema

```mermaid
erDiagram
    SCOUT_SCANS {
        int id PK
        varchar account_id
        datetime scan_time
        varchar version
        int total_findings
        timestamp created_at
    }
    
    SCOUT_FINDINGS {
        int id PK
        int scan_id FK
        varchar service
        varchar finding_id
        varchar level
        int flagged_items
        int checked_items
        text description
    }
    
    SCOUT_EVENTS {
        int id PK
        varchar resource_id
        varchar resource_name
        varchar resource_type
        varchar region
        json details
        varchar event_hash UK
        datetime first_seen
        datetime last_seen
        datetime resolved_at
        boolean notified
    }
    
    SCOUT_EVENT_FINDINGS {
        int id PK
        int event_id FK
        int finding_id FK
        int scan_id FK
    }
    
    SCOUT_SCANS ||--o{ SCOUT_FINDINGS : contains
    SCOUT_FINDINGS ||--o{ SCOUT_EVENT_FINDINGS : links
    SCOUT_EVENTS ||--o{ SCOUT_EVENT_FINDINGS : links
    SCOUT_SCANS ||--o{ SCOUT_EVENT_FINDINGS : tracks
```

### Table Purposes

#### scout_scans
Stores metadata about each ScoutSuite scan execution:
- **account_id**: AWS account identifier being scanned
- **scan_time**: Timestamp from ScoutSuite's execution
- **version**: ScoutSuite version used for the scan
- **total_findings**: Count of findings in this scan
- **created_at**: When this record was inserted

#### scout_findings
Represents individual ScoutSuite findings:
- **scan_id**: Links to the scan that generated this finding
- **service**: AWS service (ec2, iam, s3, etc.)
- **finding_id**: ScoutSuite's internal finding identifier
- **level**: Severity level (critical, high, medium, low, warning, danger)
- **flagged_items/checked_items**: ScoutSuite's statistics
- **description**: Human-readable finding description

#### scout_events
Individual AWS resource security events:
- **resource_id**: AWS resource identifier (i-123, sg-456, etc.)
- **resource_name**: Human-readable resource name
- **resource_type**: Type classification (instance, security_group, etc.)
- **region**: AWS region or NULL for global resources
- **details**: JSON object with additional resource metadata
- **event_hash**: SHA256 hash for deduplication
- **first_seen**: When this event was first detected
- **last_seen**: Most recent detection timestamp
- **resolved_at**: When event was marked as resolved (NULL if active)
- **notified**: Whether email notifications have been sent

#### scout_event_findings
Junction table linking events to findings across scans:
- **event_id**: Reference to the security event
- **finding_id**: Reference to the finding that detected this event
- **scan_id**: Reference to the scan where this relationship was observed

## Data Processing Flow

```mermaid
sequenceDiagram
    participant R as Scout Runner
    participant S as ScoutSuite
    participant P as Parser
    participant DB as Database
    participant E as Email Service
    
    R->>R: Read AWS Profiles
    loop For Each Profile
        R->>S: Execute Scout Scan
        S->>R: Generate JS Results
        R->>P: Process Results File
        P->>P: Extract JSON from JS Variable
        P->>P: Parse Services and Findings
        P->>P: Extract Individual Resource Events
        P->>DB: Check for Existing Scan
        
        alt New Scan
            P->>DB: Insert Scan Record
            P->>DB: Insert Findings
            
            loop For Each Event
                P->>DB: Check Event Hash
                alt Existing Event
                    P->>DB: Update last_seen
                else New Event
                    P->>DB: Insert New Event
                    P->>P: Add to Notification Queue
                end
                P->>DB: Link Event to Finding
            end
            
            P->>DB: Mark Missing Events as Resolved
            P->>DB: Commit Transaction
            
            alt New Events Found
                P->>E: Send Notifications
                E->>P: Delivery Confirmation
                P->>DB: Mark Events as Notified
            end
        else Duplicate Scan
            P->>P: Skip Processing
        end
        R->>R: Cleanup Temp Files
    end
```

## Installation

### Quick Setup with Scout Runner
```bash
# Clone the repository
git clone <repository-url>
cd ScoutSuiteParser

# Setup ScoutSuite environment (installs system deps and ScoutSuite)
python3 scout_runner.py --setup

# Install parser dependencies
pip3 install sqlalchemy pymysql python-dotenv boto3

# Create database
mysql -u root -p < setup_database.sql

# Configure environment
cp .env.example .env
# Edit .env with your database credentials
```

### Manual Installation

#### System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3-pip python3-dev python3-venv default-libmysqlclient-dev build-essential git

# RHEL/CentOS
sudo yum install python3-pip python3-devel python3-venv git

# Install Python packages
pip3 install sqlalchemy pymysql python-dotenv boto3
```

#### ScoutSuite Setup
```bash
# Clone ScoutSuite
git clone https://github.com/nccgroup/ScoutSuite.git
cd ScoutSuite

# Create virtual environment
python3 -m venv ../scoutsuite_venv
source ../scoutsuite_venv/bin/activate
pip install -e .
```

#### Database Setup
```bash
# Create database and user
mysql -u root -p < setup_database.sql
```

## Configuration

### Environment Variables (.env)
The parser uses environment variables for configuration, loaded via python-dotenv:

```env
# Database Configuration (Required for DB storage)
DB_HOST=localhost
DB_PORT=3306
DB_USER=scoutsuite_user
DB_PASSWORD=your_secure_password
DB_NAME=scoutsuite_db

# TLS/SSL Configuration (Optional)
DB_SSL_DISABLED=false
DB_SSL_CA=/path/to/ca-cert.pem
DB_SSL_CERT=/path/to/client-cert.pem
DB_SSL_KEY=/path/to/client-key.pem

# Email Configuration (Optional)
ENABLE_EMAIL_NOTIFICATIONS=true
SMTP_HOST=mail.yourcompany.com
SMTP_PORT=587
SMTP_USER=alerts@yourcompany.com
SMTP_PASSWORD=smtp_password
SMTP_FROM=scoutsuite-alerts@yourcompany.com
SMTP_USE_TLS=true

# AWS SES Alternative (Optional)
AWS_REGION=eu-west-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# Notification Settings
EMAIL_RECIPIENTS=security@yourcompany.com,devops@yourcompany.com
NOTIFY_ON_NEW_FINDINGS=true
NOTIFY_ON_SEVERITY=medium,high,critical
INITIAL_SCAN=false
```

### Configuration Loading Logic
1. **Environment Variables**: Primary configuration source via `.env` file
2. **Command Line Override**: Database settings can be overridden via CLI arguments
3. **Fallback Behavior**: Missing database config results in JSON console output
4. **Email Conditional**: Notifications only enabled if `ENABLE_EMAIL_NOTIFICATIONS=true`
5. **Initial Scan Mode**: When `INITIAL_SCAN=true`, new events are marked as notified to prevent mass emails on first scan

### Scout Runner Automation

#### Overview
The `scout_runner.py` script provides complete automation for ScoutSuite scanning and processing:

- **Environment Management**: Automatically downloads ScoutSuite and creates isolated virtual environment
- **Multi-Platform Support**: Handles system dependencies for Ubuntu/Debian and RHEL/CentOS
- **AWS Integration**: Reads all profiles from `~/.aws/config` for comprehensive scanning
- **Selective Scanning**: Target specific accounts with `--account` parameter
- **Automated Processing**: Seamlessly processes scan results through the parser
- **Cleanup Management**: Uses temporary directories with automatic cleanup

#### Setup Process
1. **System Dependencies**: Installs python3-pip, python3-venv, python3-dev, git
2. **ScoutSuite Download**: Clones latest ScoutSuite from GitHub
3. **Virtual Environment**: Creates isolated Python environment for ScoutSuite
4. **Dependency Installation**: Installs ScoutSuite and its dependencies

#### Scanning Workflow
1. **Profile Discovery**: Reads AWS profiles from `~/.aws/config`
2. **Temporary Directory**: Creates unique temp directory for each scan
3. **ScoutSuite Execution**: Runs ScoutSuite with appropriate profile
4. **Result Processing**: Automatically processes JS results through parser
5. **Database Storage**: Saves findings and events to database
6. **Cleanup**: Removes temporary files after processing

#### Error Handling
- **Individual Scan Failures**: Continues processing other profiles if one fails
- **Missing Dependencies**: Automatically installs required system packages
- **AWS Profile Issues**: Logs errors but continues with remaining profiles
- **Processing Failures**: Reports failures but doesn't stop batch processing

### Logging Levels
- **INFO**: Standard operational messages (scan progress, database operations)
- **DEBUG**: Detailed processing information (individual resource extraction, SQL queries)
- **ERROR**: Error conditions and fallback operations
- **WARNING**: Configuration issues and non-fatal problems

## Resource Extraction Logic

### Path Analysis Algorithm
The parser uses sophisticated path analysis to extract individual AWS resources:

```python
# Example path: services.ec2.regions.eu-west-2.vpcs.vpc-123.instances.i-456.security_groups
# Extraction process:
1. Split by dots: ['services', 'ec2', 'regions', 'eu-west-2', 'vpcs', 'vpc-123', 'instances', 'i-456', 'security_groups']
2. Extract region: 'eu-west-2' (follows 'regions')
3. Extract resource_id: 'i-456' (matches AWS ID pattern)
4. Extract resource_type: 'instance' (from 'instances' container, singularized)
5. Generate event_hash: SHA256('ec2:finding-id:i-456:full-path')
```

### Resource ID Pattern Matching
The parser recognizes standard AWS resource ID patterns:
- **EC2**: `i-`, `sg-`, `vpc-`, `subnet-`, `vol-`, `ami-`
- **ARN**: `arn:aws:service:region:account:resource`
- **IAM**: `user-`, `role-`, `policy-` or final path component
- **Generic**: Final path component as fallback

### Resource Type Classification
Resource types are derived from path containers with special case handling:
- `instances` → `instance`
- `security_groups` → `security_group`
- `policies` → `policy`
- `identities` → `identity`
- `repositories` → `repository`
- Generic plurals → singular form

## Database Indexes and Performance

### Index Strategy
The database schema includes comprehensive indexing for optimal query performance:

#### scout_scans
- **Primary**: `id` (auto-increment)
- **Single Column**: `account_id`, `scan_time`, `created_at`
- **Composite**: 
  - `idx_account_scan_time` (account_id, scan_time) - Duplicate scan detection
  - `idx_account_created` (account_id, created_at) - Historical queries

#### scout_findings
- **Primary**: `id` (auto-increment)
- **Foreign Key**: `scan_id`
- **Single Column**: `service`, `finding_id`, `level`
- **Composite**:
  - `idx_scan_service` (scan_id, service) - Service-specific queries
  - `idx_service_level` (service, level) - Severity filtering
  - `idx_scan_level` (scan_id, level) - Scan severity analysis

#### scout_events
- **Primary**: `id` (auto-increment)
- **Unique**: `event_hash` - Deduplication enforcement
- **Single Column**: `resource_id`, `resource_name`, `resource_type`, `region`, `first_seen`, `last_seen`, `resolved_at`, `notified`
- **Composite**:
  - `idx_resource_type_region` (resource_type, region) - Resource filtering
  - `idx_resolved_notified` (resolved_at, notified) - Active event queries
  - `idx_last_seen_resolved` (last_seen, resolved_at) - Temporal analysis
  - `idx_resource_id_type` (resource_id, resource_type) - Resource lookup

#### scout_event_findings
- **Primary**: `id` (auto-increment)
- **Foreign Keys**: `event_id`, `finding_id`, `scan_id`
- **Composite**:
  - `idx_event_finding` (event_id, finding_id) - Event-finding relationships
  - `idx_scan_event` (scan_id, event_id) - Scan-specific events
  - `idx_scan_finding` (scan_id, finding_id) - Scan-finding relationships

### Optimized Query Patterns

#### Recent High-Severity Events
```sql
SELECT se.resource_id, se.resource_name, sf.service, sf.level, se.last_seen
FROM scout_events se 
JOIN scout_event_findings sef ON se.id = sef.event_id
JOIN scout_findings sf ON sef.finding_id = sf.id 
WHERE sf.level IN ('high', 'critical')
  AND se.resolved_at IS NULL
ORDER BY se.last_seen DESC;
-- Uses: idx_resolved_notified, idx_service_level
```

#### Account-Specific Active Events
```sql
SELECT se.*, sf.service, sf.level
FROM scout_events se
JOIN scout_event_findings sef ON se.id = sef.event_id
JOIN scout_findings sf ON sef.finding_id = sf.id
JOIN scout_scans ss ON sf.scan_id = ss.id
WHERE ss.account_id = '123456789012'
  AND se.resolved_at IS NULL;
-- Uses: idx_account_scan_time, idx_resolved_notified
```

#### Resource Type Distribution
```sql
SELECT resource_type, region, COUNT(*) as count
FROM scout_events 
WHERE resolved_at IS NULL
GROUP BY resource_type, region 
ORDER BY count DESC;
-- Uses: idx_resource_type_region, idx_resolved_notified
```

#### Unnotified Events for Alerting
```sql
SELECT COUNT(*) as pending_notifications
FROM scout_events 
WHERE notified = FALSE 
  AND resolved_at IS NULL;
-- Uses: idx_resolved_notified
```

#### Event Timeline Analysis
```sql
SELECT DATE(first_seen) as date, COUNT(*) as new_events
FROM scout_events 
WHERE first_seen >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(first_seen)
ORDER BY date;
-- Uses: first_seen index
```

## Email Notification System

### Notification Logic Flow
```mermaid
flowchart TD
    A[New Events Detected] --> B{Email Config Enabled?}
    B -->|No| C[Skip Notifications]
    B -->|Yes| D[Filter by Severity Threshold]
    D --> E{Events Match Criteria?}
    E -->|No| C
    E -->|Yes| F[Group Events by Severity]
    F --> G[Generate HTML Email Body]
    G --> H{AWS SES Available?}
    H -->|Yes| I[Send via AWS SES]
    H -->|No| J[Send via SMTP]
    I --> K[Mark Events as Notified]
    J --> K
    K --> L[Commit Database Transaction]
```

### Email Content Structure
- **Header**: Account ID, scan timestamp, ScoutSuite version
- **Severity Sections**: Events grouped by critical, high, medium, low
- **Resource Details**: Resource ID, name, type, region for each event
- **Finding Context**: ScoutSuite finding ID, service, and description
- **HTML Formatting**: Rich formatting for improved readability

### Delivery Methods
1. **SMTP**: Traditional email server connectivity with TLS support
2. **AWS SES**: Managed email service with boto3 integration
3. **Automatic Selection**: SES preferred if AWS credentials available

## Error Handling and Fallback

### Database Connection Failures
- **Graceful Degradation**: Falls back to JSON console output
- **Error Logging**: Detailed error messages with optional stack traces
- **Configuration Validation**: Checks for required environment variables

### Parsing Failures
- **Individual Event Errors**: Logged but don't stop processing
- **Malformed JSON**: Terminates with clear error message
- **Missing ScoutSuite Data**: Handles incomplete result files

### Email Delivery Failures
- **Non-blocking**: Email failures don't affect database operations
- **Detailed Logging**: SMTP/SES error messages captured
- **Partial Success**: Successfully processes events even if notifications fail

## Security Considerations

### Database Security
- **TLS Encryption**: All connections encrypted by default
- **Certificate Validation**: Custom CA certificate support
- **Credential Isolation**: Environment-based configuration
- **SQL Injection Prevention**: SQLAlchemy ORM parameterized queries

### Email Security
- **TLS SMTP**: Encrypted email transmission
- **Credential Separation**: Isolated email service credentials
- **Content Sanitization**: HTML escaping in email templates

### Data Privacy
- **Minimal Data Storage**: Only security-relevant resource metadata
- **Hash-based Deduplication**: Cryptographic event identification
- **Configurable Retention**: Resolved events can be archived/purged

## Troubleshooting

### Common Issues

#### Database Connection Problems
```bash
# Check connectivity
mysql -h $DB_HOST -u $DB_USER -p $DB_NAME

# Verify SSL configuration
mysql -h $DB_HOST -u $DB_USER -p --ssl-ca=/path/to/ca.pem
```

#### Email Delivery Issues
```bash
# Test SMTP connectivity
telnet $SMTP_HOST $SMTP_PORT

# Verify AWS SES setup
aws ses verify-email-identity --email-address alerts@company.com
```

#### Performance Issues
```sql
-- Check index usage
EXPLAIN SELECT * FROM scout_events WHERE resource_type = 'instance';

-- Monitor table sizes
SELECT table_name, table_rows, data_length 
FROM information_schema.tables 
WHERE table_schema = 'scoutsuite_db';
```

### Debug Mode
Enable detailed logging with `--debug` flag:
- Individual resource extraction details
- SQL query execution information
- Full error stack traces
- JSON output of parsed data

### Log Analysis
```bash
# Monitor processing in real-time
python3 scoutsuite_parser.py results.js --debug | tee parser.log

# Extract timing information
grep "Processing finding" parser.log

# Check for errors
grep "ERROR" parser.log
```