#!/usr/bin/env python3
import sys
import json
import subprocess
from datetime import datetime

def scan_image(image_name):
    """
    Scan a container image using Trivy and display results
    """
    try:
        # Run Trivy scan
        result = subprocess.run(
            ['trivy', 'image', '--format', 'json', image_name],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"Error scanning image: {result.stderr}")
            return
        
        # Parse and display results
        scan_results = json.loads(result.stdout)
        
        print(f"\nScan Results for {image_name}")
        print("=" * 50)
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\nVulnerabilities:")
        print("-" * 50)
        
        for result in scan_results:
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    print(f"\nSeverity: {vuln.get('Severity', 'UNKNOWN')}")
                    print(f"Package: {vuln.get('PkgName', 'N/A')}")
                    print(f"Version: {vuln.get('InstalledVersion', 'N/A')}")
                    print(f"Fixed Version: {vuln.get('FixedVersion', 'N/A')}")
                    print(f"Description: {vuln.get('Description', 'N/A')}")
                    print("-" * 30)
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: python local_scan.py <image-name>")
        sys.exit(1)
    
    image_name = sys.argv[1]
    scan_image(image_name)

if __name__ == "__main__":
    main() 