#!/usr/bin/env python3
"""
Test script to verify CLI tool works with proper Python path
"""

import subprocess
import os
import sys

def test_cli_with_path():
    # Get the project root directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    cli_path = os.path.join(project_root, "main.py")
    
    print(f"Project root: {project_root}")
    print(f"CLI path: {cli_path}")
    print(f"CLI exists: {os.path.exists(cli_path)}")
    
    # Set up environment
    env = os.environ.copy()
    env['PYTHONPATH'] = project_root + os.pathsep + env.get('PYTHONPATH', '')
    
    print(f"PYTHONPATH: {env['PYTHONPATH']}")
    
    # Test command
    cmd = [
        sys.executable, cli_path,
        "--target", "127.0.0.1",
        "--scan-type", "ports",
        "--output", "json",
        "--report-name", "test_cli_path.json"
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    print(f"Working directory: {project_root}")
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            cwd=project_root, 
            env=env
        )
        
        print(f"Return code: {result.returncode}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        
        if result.returncode == 0:
            print("✅ CLI tool worked!")
            
            # Check if report was generated
            report_path = os.path.join(project_root, "reports", "html", "test_cli_path.json")
            if os.path.exists(report_path):
                print(f"✅ Report generated: {report_path}")
                with open(report_path, 'r') as f:
                    content = f.read()
                print(f"Report size: {len(content)} characters")
            else:
                print(f"❌ Report not found: {report_path}")
        else:
            print("❌ CLI tool failed!")
            
    except Exception as e:
        print(f"❌ Exception: {e}")

if __name__ == "__main__":
    test_cli_with_path() 