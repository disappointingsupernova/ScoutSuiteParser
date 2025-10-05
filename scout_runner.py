#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import tempfile
import shutil
import configparser
import logging
from pathlib import Path

class ScoutRunner:
    def __init__(self, debug=False):
        self.debug = debug
        self.setup_logging()
        self.script_dir = Path(__file__).parent
        self.scoutsuite_dir = self.script_dir / "ScoutSuite"
        self.venv_dir = self.script_dir / "scoutsuite_venv"
        
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
                'https://github.com/nccgroup/ScoutSuite.git',
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
            subprocess.run(cmd, check=True)
            self.logger.info(f"Scan completed for profile: {profile}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Scan failed for profile {profile}: {e}")
            return False
            
    def process_scan_results(self, output_dir, profile):
        """Process ScoutSuite results with the parser"""
        # Find the results JS file
        results_files = list(Path(output_dir).glob("**/scoutsuite_results_*.js"))
        if not results_files:
            self.logger.error(f"No results file found for profile {profile}")
            return False
            
        results_file = results_files[0]
        self.logger.info(f"Processing results: {results_file}")
        
        # Run the parser using venv python
        parser_path = self.script_dir / "scoutsuite_parser.py"
        python_path = self.venv_dir / "bin" / "python"
        cmd = [str(python_path), str(parser_path), str(results_file)]
        
        if self.debug:
            cmd.append('--debug')
            
        try:
            subprocess.run(cmd, check=True)
            self.logger.info(f"Results processed for profile: {profile}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to process results for profile {profile}: {e}")
            return False
            
    def scan_profile(self, profile):
        """Scan a single profile"""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / profile
            output_dir.mkdir(parents=True)
            
            if self.run_scout_scan(profile, output_dir):
                return self.process_scan_results(output_dir, profile)
            return False
            
    def scan_all_profiles(self):
        """Scan all AWS profiles"""
        profiles = self.get_aws_profiles()
        if not profiles:
            self.logger.error("No AWS profiles found")
            return
            
        self.logger.info(f"Found {len(profiles)} AWS profiles: {', '.join(profiles)}")
        
        success_count = 0
        for profile in profiles:
            self.logger.info(f"Processing profile {profile}...")
            if self.scan_profile(profile):
                success_count += 1
            else:
                self.logger.error(f"Failed to process profile {profile}")
                
        self.logger.info(f"Completed scanning. {success_count}/{len(profiles)} profiles processed successfully")

def main():
    parser = argparse.ArgumentParser(description='ScoutSuite Runner - Automated AWS security scanning')
    parser.add_argument('--account', help='Scan specific AWS profile only')
    parser.add_argument('--setup', action='store_true', help='Setup ScoutSuite environment')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    runner = ScoutRunner(debug=args.debug)
    
    if args.setup:
        runner.install_system_deps()
        runner.setup_scoutsuite()
        return
        
    # Ensure ScoutSuite is set up
    if not runner.scoutsuite_dir.exists() or not runner.venv_dir.exists():
        runner.logger.info("ScoutSuite not found, setting up...")
        runner.install_system_deps()
        runner.setup_scoutsuite()
        
    if args.account:
        runner.scan_profile(args.account)
    else:
        runner.scan_all_profiles()

if __name__ == '__main__':
    main()