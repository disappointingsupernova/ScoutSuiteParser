#!/usr/bin/env python3
"""
Example usage of ScoutSuite Parser
"""
from scoutsuite_parser import ScoutSuiteParser

def example_json_output():
    """Example: Parse and output to JSON console"""
    print("=== JSON Console Output Example ===")
    parser = ScoutSuiteParser()
    parser.parse_file('sample-scoutsuite-report/scoutsuite-results/scoutsuite_results_aws-078288879880.js')

def example_database_usage():
    """Example: Parse and save to MySQL database with email notifications"""
    print("\n=== Database Storage with Email Notifications Example ===")
    
    # Load configuration from .env file
    parser = ScoutSuiteParser()
    
    try:
        new_events = parser.parse_file('sample-scoutsuite-report/scoutsuite-results/scoutsuite_results_aws-078288879880.js')
        if new_events:
            print(f"Found {len(new_events)} new security events that triggered notifications")
        else:
            print("No new events found or notifications disabled")
    except Exception as e:
        print(f"Processing failed: {e}")
        print("Make sure .env file is configured and MySQL is running")

def example_individual_events():
    """Example: Show individual events extraction"""
    print("\n=== Individual Events Example ===")
    
    parser = ScoutSuiteParser()
    data = parser.parse_js_file('sample-scoutsuite-report/scoutsuite-results/scoutsuite_results_aws-078288879880.js')
    
    if data:
        scan_info, findings, events = parser.extract_findings(data)
        
        print(f"Scan Summary:")
        print(f"  Account: {scan_info['account_id']}")
        print(f"  Total Findings: {len(findings)}")
        print(f"  Total Individual Events: {len(events)}")
        
        # Show sample events
        if events:
            print(f"\nSample Events:")
            for i, event in enumerate(events[:5]):  # Show first 5 events
                print(f"  {i+1}. {event['resource_type']}: {event['resource_name'] or event['resource_id']}")
                print(f"     Region: {event['region'] or 'global'}")
                print(f"     Hash: {event['event_hash'][:16]}...")
        
        # Show findings with event counts
        print(f"\nFindings with Event Counts:")
        for finding in findings[:5]:  # Show first 5 findings
            event_count = len(finding.get('events', []))
            print(f"  {finding['service']}.{finding['finding_id']}: {event_count} events ({finding['level']})")

if __name__ == '__main__':
    # Run JSON output example (always works)
    example_json_output()
    
    # Show individual events extraction
    example_individual_events()
    
    # Uncomment to test database functionality with notifications
    # example_database_usage()