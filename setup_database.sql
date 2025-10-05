-- ScoutSuite Parser Database Setup
-- Run this script to create the database and user

-- Create database
CREATE DATABASE IF NOT EXISTS scoutsuite_db;

-- Create user (replace 'your_password' with a secure password)
CREATE USER IF NOT EXISTS 'scoutsuite_user'@'localhost' IDENTIFIED BY 'your_password';

-- Grant permissions
GRANT ALL PRIVILEGES ON scoutsuite_db.* TO 'scoutsuite_user'@'localhost';
FLUSH PRIVILEGES;

-- Use the database
USE scoutsuite_db;

-- Tables will be created automatically by the parser
-- But you can create them manually if needed:

-- Main scan results table
CREATE TABLE IF NOT EXISTS scout_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_id VARCHAR(20),
    scan_time DATETIME,
    version VARCHAR(20),
    total_findings INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Findings table
CREATE TABLE IF NOT EXISTS scout_findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    service VARCHAR(50),
    finding_id VARCHAR(100),
    level VARCHAR(20),
    flagged_items INT,
    checked_items INT,
    description TEXT,
    FOREIGN KEY (scan_id) REFERENCES scout_scans(id)
);

-- Individual events/items table
CREATE TABLE IF NOT EXISTS scout_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    finding_id INT,
    resource_id VARCHAR(255),
    resource_name VARCHAR(255),
    resource_type VARCHAR(100),
    region VARCHAR(50),
    details JSON,
    event_hash VARCHAR(64) UNIQUE,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    notified BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (finding_id) REFERENCES scout_findings(id),
    INDEX idx_event_hash (event_hash),
    INDEX idx_resource_id (resource_id)
);

-- Useful queries for monitoring:

-- Show recent scans
-- SELECT * FROM scout_scans ORDER BY scan_time DESC LIMIT 10;

-- Show new events that haven't been notified
-- SELECT se.*, sf.service, sf.finding_id, sf.level 
-- FROM scout_events se 
-- JOIN scout_findings sf ON se.finding_id = sf.id 
-- WHERE se.notified = FALSE;

-- Show events by resource type
-- SELECT resource_type, COUNT(*) as count 
-- FROM scout_events 
-- GROUP BY resource_type 
-- ORDER BY count DESC;

-- Show high severity events
-- SELECT se.resource_id, se.resource_name, sf.service, sf.finding_id, sf.level
-- FROM scout_events se 
-- JOIN scout_findings sf ON se.finding_id = sf.id 
-- WHERE sf.level IN ('high', 'critical')
-- ORDER BY se.last_seen DESC;