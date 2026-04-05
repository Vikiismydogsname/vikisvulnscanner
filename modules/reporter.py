"""
Reporter Module
Handles output formatting and report generation in various formats.
"""

import json
import csv
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime


class Reporter:
    
    def __init__(self, use_color: bool = True):
        self.use_color = use_color
        self.color_print = ColorPrint(use_color)
    
    def print_cli_summary(self, results: List[Dict[str, Any]]):
        cp = self.color_print
        
        cp.info("\n" + "="*80)
        cp.info("VULNERABILITY SCAN SUMMARY")
        cp.info("="*80)
        
        total_targets = len(results)
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results)
        total_ports = sum(len(r.get('ports', [])) for r in results)
        
        print(f"\nTargets Scanned: {total_targets}")
        print(f"Open Ports Found: {total_ports}")
        print(f"Total Issues Found: {total_vulns}")
        
        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for result in results:
            for vuln in result.get('vulnerabilities', []):
                sev = vuln.get('severity', 'INFO')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print("\nFindings by Severity:")
        if severity_counts['CRITICAL'] > 0:
            cp.critical(f"  🔴 CRITICAL: {severity_counts['CRITICAL']}")
        if severity_counts['HIGH'] > 0:
            cp.error(f"  🔴 HIGH: {severity_counts['HIGH']}")
        if severity_counts['MEDIUM'] > 0:
            cp.warning(f"  🟡 MEDIUM: {severity_counts['MEDIUM']}")
        if severity_counts['LOW'] > 0:
            cp.info(f"  🟢 LOW: {severity_counts['LOW']}")
        if severity_counts['INFO'] > 0:
            cp.success(f"  ℹ️  INFO: {severity_counts['INFO']}")
        
        # Detailed findings
        for result in results:
            target = result.get('target', 'Unknown')
            vulns = result.get('vulnerabilities', [])
            
            if not vulns:
                continue
            
            print(f"\n{'─'*80}")
            cp.info(f"\nTarget: {target} ({result.get('ip', 'N/A')})")
            print(f"Timestamp: {result.get('timestamp', 'N/A')}")
            
            # Group by severity
            by_severity = {}
            for vuln in vulns:
                sev = vuln.get('severity', 'INFO')
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(vuln)
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity not in by_severity:
                    continue
                
                print(f"\n  {severity} Severity Issues:")
                for vuln in by_severity[severity]:
                    vuln_type = vuln.get('type', 'Unknown')
                    desc = vuln.get('description', 'No description')
                    
                    if severity == 'CRITICAL':
                        cp.critical(f"    ├─ {vuln_type}: {desc}")
                    elif severity == 'HIGH':
                        cp.error(f"    ├─ {vuln_type}: {desc}")
                    elif severity == 'MEDIUM':
                        cp.warning(f"    ├─ {vuln_type}: {desc}")
                    elif severity == 'LOW':
                        cp.info(f"    ├─ {vuln_type}: {desc}")
                    else:
                        cp.success(f"    ├─ {vuln_type}: {desc}")
                    
                    if vuln.get('url'):
                        print(f"    │  URL: {vuln['url']}")
                    if vuln.get('details'):
                        print(f"    │  Details: {vuln['details']}")
                    if vuln.get('recommendation'):
                        print(f"    └─ Recommendation: {vuln['recommendation']}")
        
        print("\n" + "="*80)
    
    def export_json(self, results: Dict[str, Any], filepath: str):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
    
    def export_csv(self, results: List[Dict[str, Any]], filepath: str):
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Target',
                'IP',
                'Timestamp',
                'Severity',
                'Type',
                'Description',
                'URL',
                'Details',
                'Recommendation'
            ])
            
            # Data
            for result in results:
                target = result.get('target', '')
                ip = result.get('ip', '')
                timestamp = result.get('timestamp', '')
                
                for vuln in result.get('vulnerabilities', []):
                    writer.writerow([
                        target,
                        ip,
                        timestamp,
                        vuln.get('severity', ''),
                        vuln.get('type', ''),
                        vuln.get('description', ''),
                        vuln.get('url', ''),
                        vuln.get('details', ''),
                        vuln.get('recommendation', '')
                    ])
    
    def export_text(self, results: Dict[str, Any], filepath: str):
        with open(filepath, 'w', ecoding='utf-8') as f:
            f.write("VULNERABILITY SCAN REPORT\n")
            f.write("="*80 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            scan_results = results.get('scan_results', [])
            
            for result in scan_results:
                f.write("-"*80 + "\n")
                f.write(f"Target: {result.get('target', 'Unknown')}\n")
                f.write(f"IP: {result.get('ip', 'N/A')}\n")
                f.write(f"Scan Time: {result.get('timestamp', 'N/A')}\n\n")
                
                ports = result.get('ports', [])
                if ports:
                    f.write(f"Open Ports: {', '.join(str(p['port']) for p in ports)}\n\n")
                
                vulns = result.get('vulnerabilities', [])
                if vulns:
                    f.write(f"Vulnerabilities Found: {len(vulns)}\n\n")
                    
                    for idx, vuln in enumerate(vulns, 1):
                        f.write(f"  [{idx}] {vuln.get('type', 'Unknown')}\n")
                        f.write(f"      Severity: {vuln.get('severity', 'N/A')}\n")
                        f.write(f"      Description: {vuln.get('description', 'N/A')}\n")
                        if vuln.get('url'):
                            f.write(f"      URL: {vuln['url']}\n")
                        if vuln.get('details'):
                            f.write(f"      Details: {vuln['details']}\n")
                        if vuln.get('recommendation'):
                            f.write(f"      Recommendation: {vuln['recommendation']}\n")
                        f.write("\n")
                else:
                    f.write("No vulnerabilities detected.\n\n")
            
            f.write("="*80 + "\n")
    
    def export_html(self, results: Dict[str, Any], filepath: str):
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .timestamp {
            opacity: 0.9;
            margin-top: 10px;
        }
        .summary {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .summary-item {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .summary-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .target-section {
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .target-header {
            font-size: 1.5em;
            font-weight: bold;
            color: #333;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        .vulnerability {
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #ddd;
            background: #f8f9fa;
            border-radius: 4px;
        }
        .vuln-header {
            font-weight: bold;
            margin-bottom: 8px;
        }
        .vuln-detail {
            margin: 5px 0;
            padding-left: 10px;
        }
        .severity-CRITICAL {
            border-left-color: #dc3545;
            background: #ffe6e6;
        }
        .severity-HIGH {
            border-left-color: #fd7e14;
            background: #fff3e6;
        }
        .severity-MEDIUM {
            border-left-color: #ffc107;
            background: #fff9e6;
        }
        .severity-LOW {
            border-left-color: #28a745;
            background: #e6f9e6;
        }
        .severity-INFO {
            border-left-color: #17a2b8;
            background: #e6f7f9;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }
        .badge-CRITICAL { background-color: #dc3545; }
        .badge-HIGH { background-color: #fd7e14; }
        .badge-MEDIUM { background-color: #ffc107; color: #333; }
        .badge-LOW { background-color: #28a745; }
        .badge-INFO { background-color: #17a2b8; }
        .no-vulns {
            text-align: center;
            padding: 30px;
            color: #28a745;
            font-size: 1.2em;
        }
        .ports {
            margin: 15px 0;
            padding: 10px;
            background: #e9ecef;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Vulnerability Scan Report</h1>
        <div class="timestamp">Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</div>
    </div>
"""
        
        scan_results = results.get('scan_results', [])
        
        # Summary section
        total_targets = len(scan_results)
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in scan_results)
        total_ports = sum(len(r.get('ports', [])) for r in scan_results)
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for result in scan_results:
            for vuln in result.get('vulnerabilities', []):
                sev = vuln.get('severity', 'INFO')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        html += f"""
    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="summary-value">{total_targets}</div>
                <div>Targets Scanned</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{total_ports}</div>
                <div>Open Ports</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{total_vulns}</div>
                <div>Issues Found</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{severity_counts['CRITICAL'] + severity_counts['HIGH']}</div>
                <div>Critical/High</div>
            </div>
        </div>
    </div>
"""
        
        # Detailed results
        for result in scan_results:
            target = result.get('target', 'Unknown')
            ip = result.get('ip', 'N/A')
            timestamp = result.get('timestamp', 'N/A')
            ports = result.get('ports', [])
            vulns = result.get('vulnerabilities', [])
            
            html += f"""
    <div class="target-section">
        <div class="target-header">🎯 {target}</div>
        <div><strong>IP:</strong> {ip}</div>
        <div><strong>Scan Time:</strong> {timestamp}</div>
"""
            
            if ports:
                port_list = ', '.join(f"{p['port']} ({p.get('service', 'unknown')})" for p in ports)
                html += f"""
        <div class="ports">
            <strong>Open Ports:</strong> {port_list}
        </div>
"""
            
            if vulns:
                html += f"""
        <h3>Vulnerabilities ({len(vulns)})</h3>
"""
                for vuln in vulns:
                    severity = vuln.get('severity', 'INFO')
                    vuln_type = vuln.get('type', 'Unknown')
                    desc = vuln.get('description', 'No description')
                    
                    html += f"""
        <div class="vulnerability severity-{severity}">
            <div class="vuln-header">
                <span class="badge badge-{severity}">{severity}</span>
                {vuln_type}
            </div>
            <div class="vuln-detail"><strong>Description:</strong> {desc}</div>
"""
                    
                    if vuln.get('url'):
                        html += f"""
            <div class="vuln-detail"><strong>URL:</strong> <a href="{vuln['url']}">{vuln['url']}</a></div>
"""
                    
                    if vuln.get('details'):
                        html += f"""
            <div class="vuln-detail"><strong>Details:</strong> {vuln['details']}</div>
"""
                    
                    if vuln.get('recommendation'):
                        html += f"""
            <div class="vuln-detail"><strong>Recommendation:</strong> {vuln['recommendation']}</div>
"""
                    
                    html += """
        </div>
"""
            else:
                html += """
        <div class="no-vulns">✅ No vulnerabilities detected</div>
"""
            
            html += """
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)


class ColorPrint:
    """Helper class for colored terminal output."""
    
    # ANSI color codes
    COLORS = {
        'RESET': '\033[0m',
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'BOLD': '\033[1m',
    }
    
    def __init__(self, use_color: bool = True):
        self.use_color = use_color
    
    def _colorize(self, text: str, color: str) -> str:
        """Add color to text if enabled."""
        if not self.use_color:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['RESET']}"
    
    def critical(self, text: str):
        """Print critical message (red, bold)."""
        print(self._colorize(text, 'RED') if self.use_color else text)
    
    def error(self, text: str):
        """Print error message (red)."""
        print(self._colorize(text, 'RED'))
    
    def warning(self, text: str):
        """Print warning message (yellow)."""
        print(self._colorize(text, 'YELLOW'))
    
    def success(self, text: str):
        """Print success message (green)."""
        print(self._colorize(text, 'GREEN'))
    
    def info(self, text: str):
        """Print info message (cyan)."""
        print(self._colorize(text, 'CYAN'))
