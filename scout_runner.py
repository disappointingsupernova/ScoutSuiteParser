#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import tempfile
import shutil
import configparser
import logging
import smtplib
import boto3
import signal
import atexit
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from dotenv import load_dotenv

class ScoutRunner:
    def __init__(self, debug=False):
        self.debug = debug
        self.setup_logging()
        self.script_dir = Path(__file__).parent
        self.scoutsuite_dir = self.script_dir / "ScoutSuite"
        self.venv_dir = self.script_dir / "scoutsuite_venv"
        self.scan_results = {
            'successful': [],
            'failed_scan': [],
            'failed_parse': [],
            'errors': [],
            'attempted': []  # Track all profiles that were attempted
        }
        self.temp_dir = None
        self.setup_cleanup_handlers()
        load_dotenv()
        
    def setup_cleanup_handlers(self):
        """Setup cleanup handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self.cleanup_and_exit)
        signal.signal(signal.SIGTERM, self.cleanup_and_exit)
        atexit.register(self.cleanup_temp_dir)
        
    def cleanup_temp_dir(self):
        """Clean up temporary directory"""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                self.logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
            except Exception as e:
                self.logger.error(f"Failed to cleanup temp directory: {e}")
                
    def cleanup_and_exit(self, signum, frame):
        """Handle Ctrl+C and other signals"""
        print("\n\nReceived interrupt signal. Generating summary...")
        
        # Always generate summary, even if no results yet
        summary = self.generate_summary_report(interrupted=True)
        print(summary)
        
        # Try to send notification but don't block on it
        if self.scan_results['attempted']:
            try:
                print("Sending interrupt notification...")
                html_summary = summary.replace('\n', '<br>').replace(' ', '&nbsp;')
                self.send_failure_notification(
                    f"ScoutSuite Runner Interrupted - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    f"<html><body><pre>{html_summary}</pre></body></html>",
                    timeout=5
                )
            except Exception as e:
                print(f"Failed to send notification: {e}")
        
        print("\nCleaning up temporary files...")
        self.cleanup_temp_dir()
        print("Cleanup complete.")
        
        # Countdown before exit
        import time
        print("Exiting in 5 seconds... (Press Ctrl+C again to exit immediately)", end='', flush=True)
        for i in range(5, 0, -1):
            try:
                time.sleep(1)
                if i > 1:
                    print(f"\rExiting in {i-1} seconds... (Press Ctrl+C again to exit immediately)", end='', flush=True)
            except KeyboardInterrupt:
                print("\nForced exit.")
                sys.exit(1)
        print("\rExiting now...                                                    ")
        sys.exit(1)
        
    def create_temp_dir(self):
        """Create centralized temporary directory for all scans"""
        if not self.temp_dir:
            self.temp_dir = Path(tempfile.mkdtemp(prefix='scoutsuite_runner_'))
            self.logger.info(f"Created temporary directory: {self.temp_dir}")
        return self.temp_dir
        
    def setup_logging(self):
        level = logging.DEBUG if self.debug else logging.INFO
        logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
    def install_system_deps(self):
        """Install system dependencies for ScoutSuite"""
        self.logger.info("Installing system dependencies...")
        
        # Detect OS
        try:
            subprocess.run(['which', 'apt'], check=True, capture_output=True)
            # Ubuntu/Debian
            subprocess.run([
                'sudo', 'apt', 'update'
            ], check=True)
            subprocess.run([
                'sudo', 'apt', 'install', '-y', 
                'python3-pip', 'python3-venv', 'python3-dev', 'git'
            ], check=True)
        except subprocess.CalledProcessError:
            try:
                subprocess.run(['which', 'yum'], check=True, capture_output=True)
                # RHEL/CentOS
                subprocess.run([
                    'sudo', 'yum', 'install', '-y',
                    'python3-pip', 'python3-venv', 'python3-devel', 'git'
                ], check=True)
            except subprocess.CalledProcessError:
                self.logger.error("Unsupported OS. Please install python3-pip, python3-venv, python3-dev, and git manually")
                sys.exit(1)
                
    def setup_scoutsuite(self):
        """Download and setup ScoutSuite"""
        if not self.scoutsuite_dir.exists():
            self.logger.info("Cloning ScoutSuite...")
            subprocess.run([
                'git', 'clone', 
                'https://github.com/disappointingsupernova/ScoutSuite.git',
                str(self.scoutsuite_dir)
            ], check=True)
        else:
            self.logger.info("ScoutSuite already exists, updating...")
            subprocess.run(['git', 'pull'], cwd=self.scoutsuite_dir, check=True)
            
        if not self.venv_dir.exists():
            self.logger.info("Creating virtual environment...")
            subprocess.run([
                'python3', '-m', 'venv', str(self.venv_dir)
            ], check=True)
            
        # Install ScoutSuite and parser dependencies in venv
        self.logger.info("Installing ScoutSuite dependencies...")
        pip_path = self.venv_dir / "bin" / "pip"
        subprocess.run([
            str(pip_path), 'install', '-e', str(self.scoutsuite_dir)
        ], check=True)
        
        self.logger.info("Installing parser dependencies...")
        subprocess.run([
            str(pip_path), 'install', 'sqlalchemy', 'pymysql', 'python-dotenv', 'boto3'
        ], check=True)
        
    def healthcheck(self):
        """Check virtual environment dependencies"""
        if not self.venv_dir.exists():
            self.logger.error("Virtual environment not found. Run --setup first.")
            return False
            
        pip_path = self.venv_dir / "bin" / "pip"
        python_path = self.venv_dir / "bin" / "python"
        
        # Required packages for parser
        parser_requirements = ['sqlalchemy', 'pymysql', 'python-dotenv', 'boto3']
        
        # Required packages for ScoutSuite (core ones)
        scoutsuite_requirements = ['boto3', 'botocore', 'azure-identity', 'azure-mgmt-resource', 'google-auth']
        
        print(f"\n{'='*60}")
        print("VIRTUAL ENVIRONMENT HEALTHCHECK")
        print(f"{'='*60}")
        print(f"Virtual Environment: {self.venv_dir}")
        print(f"Python Path: {python_path}")
        
        try:
            # Get installed packages
            result = subprocess.run([str(pip_path), 'list'], capture_output=True, text=True, check=True)
            installed_packages = {}
            for line in result.stdout.split('\n')[2:]:  # Skip header lines
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        installed_packages[parts[0].lower()] = parts[1]
            
            print(f"\nTotal Installed Packages: {len(installed_packages)}")
            
            # Check parser requirements
            print(f"\nPARSER REQUIREMENTS:")
            parser_ok = True
            for pkg in parser_requirements:
                if pkg.lower() in installed_packages:
                    print(f"  ✓ {pkg}: {installed_packages[pkg.lower()]}")
                else:
                    print(f"  ✗ {pkg}: MISSING")
                    parser_ok = False
            
            # Check ScoutSuite requirements
            print(f"\nSCOUTSUITE CORE REQUIREMENTS:")
            scoutsuite_ok = True
            for pkg in scoutsuite_requirements:
                pkg_key = pkg.lower().replace('-', '_')  # Handle package name variations
                found = False
                for installed_pkg in installed_packages:
                    if pkg_key in installed_pkg or pkg.lower() in installed_pkg:
                        print(f"  ✓ {pkg}: {installed_packages[installed_pkg]}")
                        found = True
                        break
                if not found:
                    print(f"  ✗ {pkg}: MISSING")
                    scoutsuite_ok = False
            
            # Test ScoutSuite import
            print(f"\nSCOUTSUITE IMPORT TEST:")
            try:
                subprocess.run([str(python_path), '-c', 'import ScoutSuite; print("ScoutSuite import: OK")'], 
                             check=True, capture_output=True)
                print(f"  ✓ ScoutSuite module import: OK")
            except subprocess.CalledProcessError:
                print(f"  ✗ ScoutSuite module import: FAILED")
                scoutsuite_ok = False
            
            # Test parser dependencies import
            print(f"\nPARSER DEPENDENCIES TEST:")
            test_imports = [
                ('sqlalchemy', 'import sqlalchemy'),
                ('pymysql', 'import pymysql'),
                ('python-dotenv', 'from dotenv import load_dotenv'),
                ('boto3', 'import boto3')
            ]
            
            for pkg_name, import_cmd in test_imports:
                try:
                    subprocess.run([str(python_path), '-c', import_cmd], 
                                 check=True, capture_output=True)
                    print(f"  ✓ {pkg_name} import: OK")
                except subprocess.CalledProcessError:
                    print(f"  ✗ {pkg_name} import: FAILED")
                    parser_ok = False
            
            print(f"\n{'='*60}")
            print(f"HEALTHCHECK SUMMARY")
            print(f"{'='*60}")
            print(f"Parser Dependencies: {'✓ OK' if parser_ok else '✗ FAILED'}")
            print(f"ScoutSuite Dependencies: {'✓ OK' if scoutsuite_ok else '✗ FAILED'}")
            print(f"Overall Status: {'✓ HEALTHY' if (parser_ok and scoutsuite_ok) else '✗ ISSUES FOUND'}")
            
            if not (parser_ok and scoutsuite_ok):
                print(f"\nTo fix issues, run: python3 scout_runner.py --setup")
            
            print(f"{'='*60}\n")
            
            return parser_ok and scoutsuite_ok
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to check dependencies: {e}")
            return False
        
    def get_aws_profiles(self):
        """Get AWS profiles from ~/.aws/config"""
        config_path = Path.home() / ".aws" / "config"
        if not config_path.exists():
            self.logger.error("AWS config file not found at ~/.aws/config")
            return []
            
        config = configparser.ConfigParser()
        config.read(config_path)
        
        profiles = []
        for section in config.sections():
            if section.startswith('profile '):
                profile_name = section.replace('profile ', '')
                profiles.append(profile_name)
            elif section == 'default':
                profiles.append('default')
                
        return profiles
    
    def get_profiles_by_account_id(self, account_id):
        """Find profiles that match the given account ID"""
        config_path = Path.home() / ".aws" / "config"
        if not config_path.exists():
            return []
            
        config = configparser.ConfigParser()
        config.read(config_path)
        
        matching_profiles = []
        for section in config.sections():
            profile_name = None
            if section.startswith('profile '):
                profile_name = section.replace('profile ', '')
            elif section == 'default':
                profile_name = 'default'
                
            if profile_name:
                # Check if account_id is mentioned in any of the profile settings
                for key, value in config[section].items():
                    if account_id in value:
                        matching_profiles.append(profile_name)
                        break
                        
        return matching_profiles
    
    def resolve_account_parameter(self, account_param):
        """Resolve account parameter to actual profile name(s)"""
        all_profiles = self.get_aws_profiles()
        
        # First check for direct profile name match
        if account_param in all_profiles:
            return [account_param]
            
        # If no direct match, search by account ID
        matching_profiles = self.get_profiles_by_account_id(account_param)
        
        if not matching_profiles:
            self.logger.error(f"No profiles found matching '{account_param}'")
            return []
            
        if len(matching_profiles) == 1:
            self.logger.info(f"Found profile '{matching_profiles[0]}' for account ID '{account_param}'")
            return matching_profiles
            
        # Multiple matches - present selection menu
        print(f"\nFound {len(matching_profiles)} profiles matching account ID '{account_param}':")
        for i, profile in enumerate(matching_profiles, 1):
            print(f"  {i}. {profile}")
        print(f"  {len(matching_profiles) + 1}. All profiles")
        print(f"  {len(matching_profiles) + 2}. Cancel")
        
        while True:
            try:
                choice = input("\nSelect profiles to scan (comma-separated numbers or single number): ").strip()
                if not choice:
                    continue
                    
                if ',' in choice:
                    # Multiple selections
                    indices = [int(x.strip()) for x in choice.split(',')]
                    selected_profiles = []
                    for idx in indices:
                        if 1 <= idx <= len(matching_profiles):
                            selected_profiles.append(matching_profiles[idx - 1])
                        elif idx == len(matching_profiles) + 1:
                            return matching_profiles  # All profiles
                        elif idx == len(matching_profiles) + 2:
                            return []  # Cancel
                    if selected_profiles:
                        return selected_profiles
                else:
                    # Single selection
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(matching_profiles):
                        return [matching_profiles[choice_num - 1]]
                    elif choice_num == len(matching_profiles) + 1:
                        return matching_profiles  # All profiles
                    elif choice_num == len(matching_profiles) + 2:
                        return []  # Cancel
                        
                print("Invalid selection. Please try again.")
            except (ValueError, IndexError):
                print("Invalid input. Please enter valid numbers.")
        
    def run_scout_scan(self, profile, output_dir):
        """Run ScoutSuite scan for a specific profile"""
        self.logger.info(f"Running ScoutSuite scan for profile: {profile}")
        
        scout_path = self.venv_dir / "bin" / "scout"
        cmd = [
            str(scout_path), 'aws',
            '--profile', profile,
            '--report-dir', str(output_dir),
            '--no-browser'
        ]
        
        try:
            print(f"Scanning AWS account with profile '{profile}'...")
            # Always show ScoutSuite output in real-time
            result = subprocess.run(cmd, check=True)
            self.logger.info(f"Scan completed for profile: {profile}")
            return True, None
        except subprocess.CalledProcessError as e:
            error_msg = f"Exit code {e.returncode}: ScoutSuite scan failed"
            self.logger.error(f"Scan failed for profile {profile}: {error_msg}")
            return False, error_msg
            
    def process_scan_results(self, output_dir, profile):
        """Process ScoutSuite results with the parser"""
        # Find the results JS file
        results_files = list(Path(output_dir).glob("**/scoutsuite_results_*.js"))
        if not results_files:
            error_msg = "No results file found"
            self.logger.error(f"{error_msg} for profile {profile}")
            return False, error_msg
            
        results_file = results_files[0]
        self.logger.info(f"Processing results: {results_file}")
        
        # Run the parser using venv python with proper environment
        parser_path = self.script_dir / "scoutsuite_parser.py"
        python_path = self.venv_dir / "bin" / "python"
        cmd = [str(python_path), str(parser_path), str(results_file)]
        
        if self.debug:
            cmd.append('--debug')
        
        # Set environment to use the virtual environment
        env = os.environ.copy()
        env['PATH'] = f"{self.venv_dir / 'bin'}:{env.get('PATH', '')}"
        env['VIRTUAL_ENV'] = str(self.venv_dir)
        env['PYTHONPATH'] = str(self.script_dir)
            
        try:
            print(f"Processing scan results for profile '{profile}'...")
            if self.debug:
                # Show all parser output in debug mode
                result = subprocess.run(cmd, check=True, env=env)
            else:
                # Show parser output but capture stderr for errors
                result = subprocess.run(cmd, check=True, stderr=subprocess.PIPE, text=True, env=env)
            self.logger.info(f"Results processed for profile: {profile}")
            return True, None
        except subprocess.CalledProcessError as e:
            if hasattr(e, 'stderr') and e.stderr:
                error_msg = f"Exit code {e.returncode}: {e.stderr.strip()}"
            else:
                error_msg = f"Exit code {e.returncode}: Parser failed"
            self.logger.error(f"Failed to process results for profile {profile}: {error_msg}")
            return False, error_msg
            
    def scan_profile(self, profile):
        """Scan a single profile"""
        # Track that we attempted this profile
        if profile not in self.scan_results['attempted']:
            self.scan_results['attempted'].append(profile)
            
        temp_base = self.create_temp_dir()
        output_dir = temp_base / profile
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            scan_success, scan_error = self.run_scout_scan(profile, output_dir)
            if scan_success:
                parse_success, parse_error = self.process_scan_results(output_dir, profile)
                if parse_success:
                    self.scan_results['successful'].append(profile)
                    return True
                else:
                    self.scan_results['failed_parse'].append({'profile': profile, 'error': parse_error})
                    return False
            else:
                self.scan_results['failed_scan'].append({'profile': profile, 'error': scan_error})
                return False
        finally:
            # Clean up individual profile directory after processing
            if output_dir.exists():
                try:
                    shutil.rmtree(output_dir)
                    self.logger.debug(f"Cleaned up profile directory: {output_dir}")
                except Exception as e:
                    self.logger.warning(f"Failed to cleanup profile directory {output_dir}: {e}")
            
    def send_failure_notification(self, subject, body, timeout=30):
        """Send email notification for failures"""
        if not os.getenv('ENABLE_EMAIL_NOTIFICATIONS', '').lower() == 'true':
            return
            
        recipients = os.getenv('EMAIL_RECIPIENTS', '').split(',')
        if not recipients or not recipients[0]:
            return
            
        try:
            # Try AWS SES first
            if os.getenv('AWS_REGION'):
                ses = boto3.client('ses', region_name=os.getenv('AWS_REGION'))
                ses.send_email(
                    Source=os.getenv('SMTP_FROM', 'scoutsuite-runner@localhost'),
                    Destination={'ToAddresses': recipients},
                    Message={
                        'Subject': {'Data': subject},
                        'Body': {'Html': {'Data': body}}
                    }
                )
            else:
                # Fallback to SMTP with timeout
                msg = MIMEMultipart()
                msg['From'] = os.getenv('SMTP_FROM', 'scoutsuite-runner@localhost')
                msg['To'] = ', '.join(recipients)
                msg['Subject'] = subject
                msg.attach(MIMEText(body, 'html'))
                
                server = smtplib.SMTP(os.getenv('SMTP_HOST'), int(os.getenv('SMTP_PORT', 587)), timeout=timeout)
                if os.getenv('SMTP_USE_TLS', '').lower() == 'true':
                    server.starttls()
                if os.getenv('SMTP_USER'):
                    server.login(os.getenv('SMTP_USER'), os.getenv('SMTP_PASSWORD'))
                server.send_message(msg)
                server.quit()
                
            self.logger.info("Failure notification sent")
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")
            raise  # Re-raise so caller can handle
    
    def generate_summary_report(self, interrupted=False):
        """Generate detailed summary report"""
        total = len(self.scan_results['successful']) + len(self.scan_results['failed_scan']) + len(self.scan_results['failed_parse'])
        
        summary = f"\n{'='*60}\n"
        if interrupted:
            summary += f"INTERRUPTED EXECUTION SUMMARY\n"
        else:
            summary += f"SCOUTSUITE RUNNER EXECUTION SUMMARY\n"
        summary += f"{'='*60}\n"
        summary += f"Execution Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        if interrupted and self.scan_results['attempted']:
            summary += f"Attempted Profiles: {len(self.scan_results['attempted'])}\n"
            summary += f"Total Completed: {total}\n"
        else:
            summary += f"Total Profiles: {total}\n"
            
        summary += f"Successful: {len(self.scan_results['successful'])}\n"
        summary += f"Failed Scans: {len(self.scan_results['failed_scan'])}\n"
        summary += f"Failed Parsing: {len(self.scan_results['failed_parse'])}\n"
        
        if interrupted and self.scan_results['attempted']:
            summary += f"\nATTEMPTED PROFILES:\n"
            for profile in self.scan_results['attempted']:
                if profile in self.scan_results['successful']:
                    summary += f"  ✓ {profile}\n"
                elif any(f['profile'] == profile for f in self.scan_results['failed_scan']):
                    summary += f"  ✗ {profile} (scan failed)\n"
                elif any(f['profile'] == profile for f in self.scan_results['failed_parse']):
                    summary += f"  ✗ {profile} (parse failed)\n"
                else:
                    summary += f"  ⏸ {profile} (interrupted)\n"
        
        if self.scan_results['successful']:
            summary += f"\nSUCCESSFUL PROFILES:\n"
            for profile in self.scan_results['successful']:
                summary += f"  ✓ {profile}\n"
        
        if self.scan_results['failed_scan']:
            summary += f"\nFAILED SCANS:\n"
            for failure in self.scan_results['failed_scan']:
                summary += f"  ✗ {failure['profile']}: {failure['error']}\n"
        
        if self.scan_results['failed_parse']:
            summary += f"\nFAILED PARSING:\n"
            for failure in self.scan_results['failed_parse']:
                summary += f"  ✗ {failure['profile']}: {failure['error']}\n"
        
        if self.scan_results['errors']:
            summary += f"\nOTHER ERRORS:\n"
            for error in self.scan_results['errors']:
                summary += f"  ✗ {error}\n"
        
        summary += f"{'='*60}\n"
        return summary
    
    def scan_all_profiles(self):
        """Scan all AWS profiles"""
        try:
            profiles = self.get_aws_profiles()
            if not profiles:
                error_msg = "No AWS profiles found"
                self.logger.error(error_msg)
                self.scan_results['errors'].append(error_msg)
                return
                
            self.logger.info(f"Found {len(profiles)} AWS profiles: {', '.join(profiles)}")
            
            for profile in profiles:
                self.logger.info(f"Processing profile {profile}...")
                # Track that we're attempting this profile
                if profile not in self.scan_results['attempted']:
                    self.scan_results['attempted'].append(profile)
                try:
                    self.scan_profile(profile)
                except KeyboardInterrupt:
                    # Don't re-raise here, let the signal handler deal with it
                    break
                except Exception as e:
                    error_msg = f"Unexpected error processing {profile}: {str(e)}"
                    self.logger.error(error_msg)
                    self.scan_results['errors'].append(error_msg)
            
            # Generate and display summary
            summary = self.generate_summary_report()
            print(summary)
            self.logger.info(summary.replace('\n', ' | '))
            
            # Send failure notification if there were any failures
            if (self.scan_results['failed_scan'] or self.scan_results['failed_parse'] or self.scan_results['errors']):
                html_summary = summary.replace('\n', '<br>').replace(' ', '&nbsp;')
                self.send_failure_notification(
                    f"ScoutSuite Runner Failures - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    f"<html><body><pre>{html_summary}</pre></body></html>"
                )
                
        except KeyboardInterrupt:
            # Don't re-raise here, let the signal handler deal with it
            pass
        except Exception as e:
            error_msg = f"Critical error in scan_all_profiles: {str(e)}"
            self.logger.error(error_msg)
            self.scan_results['errors'].append(error_msg)
            
            # Send critical failure notification
            self.send_failure_notification(
                f"ScoutSuite Runner Critical Failure - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"<html><body><h3>Critical Error</h3><p>{error_msg}</p></body></html>"
            )
        finally:
            # Ensure cleanup happens
            self.cleanup_temp_dir()

def main():
    parser = argparse.ArgumentParser(description='ScoutSuite Runner - Automated AWS security scanning')
    parser.add_argument('--account', help='Scan specific AWS profile only')
    parser.add_argument('--setup', action='store_true', help='Setup ScoutSuite environment')
    parser.add_argument('--healthcheck', action='store_true', help='Check virtual environment dependencies')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    runner = ScoutRunner(debug=args.debug)
    
    if args.setup:
        runner.install_system_deps()
        runner.setup_scoutsuite()
        return
        
    if args.healthcheck:
        runner.healthcheck()
        return
        
    # Ensure ScoutSuite is set up
    if not runner.scoutsuite_dir.exists() or not runner.venv_dir.exists():
        runner.logger.info("ScoutSuite not found, setting up...")
        runner.install_system_deps()
        runner.setup_scoutsuite()
        
    # Run healthcheck before scanning
    if not runner.healthcheck():
        runner.logger.error("Healthcheck failed. Please run --setup to fix dependencies.")
        return
        
    if args.account:
        profiles_to_scan = runner.resolve_account_parameter(args.account)
        if not profiles_to_scan:
            print("No profiles selected or found. Exiting.")
            return
            
        if len(profiles_to_scan) == 1:
            success = runner.scan_profile(profiles_to_scan[0])
        else:
            # Scan multiple profiles
            for profile in profiles_to_scan:
                runner.logger.info(f"Processing profile {profile}...")
                # Track that we're attempting this profile
                if profile not in runner.scan_results['attempted']:
                    runner.scan_results['attempted'].append(profile)
                try:
                    runner.scan_profile(profile)
                except KeyboardInterrupt:
                    # Let signal handler deal with it
                    break
                except Exception as e:
                    error_msg = f"Unexpected error processing {profile}: {str(e)}"
                    runner.logger.error(error_msg)
                    runner.scan_results['errors'].append(error_msg)
                    
        summary = runner.generate_summary_report()
        print(summary)
        if (runner.scan_results['failed_scan'] or runner.scan_results['failed_parse'] or runner.scan_results['errors']):
            html_summary = summary.replace('\n', '<br>').replace(' ', '&nbsp;')
            runner.send_failure_notification(
                f"ScoutSuite Runner Account Failure - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"<html><body><pre>{html_summary}</pre></body></html>"
            )
    else:
        runner.scan_all_profiles()

if __name__ == '__main__':
    main()