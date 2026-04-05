#!/usr/bin/env python3

import argparse
import sys
import asyncio
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime, timezone

# Import our modules
from modules.target_handler import TargetHandler
from modules.port_scanner import PortScanner
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.reporter import Reporter
from modules.utils import setup_logging, print_banner, ColorPrint

__version__ = "1.0.1"


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Advanced Vulnerability Scanner - Authorized Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -p 1-1000
  %(prog)s -t example.com --full-scan
  %(prog)s -T targets.txt -o results.json --threads 20
  %(prog)s -t example.com --web-only --check-cve

Scan Types:
  --quick       Fast scan (top 100 ports, basic checks)
  --full-scan   Comprehensive scan (all features enabled)
  --web-only    Web application security checks only
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Single target (IP or domain)')
    target_group.add_argument('-T', '--target-file', help='File containing list of targets')
    
    # Port scanning options
    parser.add_argument('-p', '--ports', default='1-1000',
                       help='Port range to scan (e.g., "80,443" or "1-1000"). Default: 1-1000')
    parser.add_argument('--top-ports', type=int, metavar='N',
                       help='Scan top N most common ports')
    parser.add_argument('--all-ports', action='store_true',
                       help='Scan all 65535 ports (slow)')
    
    # Scan type presets
    parser.add_argument('--quick', action='store_true',
                       help='Quick scan (top 100 ports, basic checks)')
    parser.add_argument('--full-scan', action='store_true',
                       help='Full comprehensive scan')
    parser.add_argument('--web-only', action='store_true',
                       help='Web application checks only')
    
    # Vulnerability check options
    parser.add_argument('--check-headers', action='store_true',
                       help='Check security headers')
    parser.add_argument('--check-ssl', action='store_true',
                       help='Check SSL/TLS configuration')
    parser.add_argument('--check-cve', action='store_true',
                       help='Query CVE database for known vulnerabilities')
    parser.add_argument('--check-files', action='store_true',
                       help='Check for exposed sensitive files')
    parser.add_argument('--check-cms', action='store_true',
                       help='Detect and check CMS (WordPress, Joomla, etc.)')
    
    # Performance options
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5,
                       help='Connection timeout in seconds (default: 5)')
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file (supports .json, .csv, .txt)')
    parser.add_argument('--json', help='Export results to JSON file')
    parser.add_argument('--csv', help='Export results to CSV file')
    parser.add_argument('--html', help='Export results to HTML report')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    # Misc options
    parser.add_argument('--user-agent', default='VulnScanner/1.0',
                       help='Custom User-Agent string')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    # Handle scan presets
    if args.quick:
        args.top_ports = 100
        args.check_headers = True
        args.check_ssl = True
    elif args.full_scan:
        args.all_ports = True
        args.check_headers = True
        args.check_ssl = True
        args.check_cve = True
        args.check_files = True
        args.check_cms = True
    elif args.web_only:
        args.ports = '80,443,8080,8443'
        args.check_headers = True
        args.check_ssl = True
        args.check_files = True
        args.check_cms = True
    
    return args


async def run_scan(args: argparse.Namespace) -> Dict[str, Any]:
    """Main scanning."""
    
    # Initialize components
    target_handler = TargetHandler()
    port_scanner = PortScanner(timeout=args.timeout, max_workers=args.threads)
    vuln_scanner = VulnerabilityScanner(
        timeout=args.timeout,
        user_agent=args.user_agent,
        delay=args.delay
    )
    
    # Load targets
    cp = ColorPrint(not args.no_color)
    if args.target:
        targets = [args.target]
    else:
        cp.info(f"Loading targets from {args.target_file}...")
        targets = target_handler.load_targets(args.target_file)
    
    cp.success(f"Loaded {len(targets)} target(s)")
    
    all_results = []
    
    # Process each target
    for idx, target in enumerate(targets, 1):
        cp.info(f"\n[{idx}/{len(targets)}] Scanning target: {target}")
        
        # Validate and resolve target
        cp.info("Validating target...")
        if not target_handler.validate_target(target):
            cp.error(f"Invalid target: {target}")
            continue
        
        resolved_ip = target_handler.resolve_target(target)
        if not resolved_ip:
            cp.error(f"Could not resolve target: {target}")
            continue
        
        cp.success(f"Resolved to: {resolved_ip}")
        
        # Check if host is up
        cp.info("Checking if host is up...")
        if not await target_handler.is_host_up(resolved_ip, args.timeout):
            cp.warning(f"Host appears to be down or filtered: {target}")
            continue
        
        cp.success("Host is up")
        
        result = {
            'target': target,
            'ip': resolved_ip,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'ports': [],
            'vulnerabilities': []
        }
        
        # Determine port list
        if args.all_ports:
            port_list = range(1, 65536)
        elif args.top_ports:
            port_list = port_scanner.get_top_ports(args.top_ports)
        else:
            port_list = port_scanner.parse_port_string(args.ports)
        
        # Port scanning
        cp.info(f"Scanning {len(port_list)} ports...")
        open_ports = await port_scanner.scan_ports(resolved_ip, port_list)
        cp.success(f"Found {len(open_ports)} open port(s): {sorted(open_ports)}")
        
        # Banner grabbing
        if open_ports:
            cp.info("Grabbing banners from open ports...")
            for port in open_ports:
                banner_info = await port_scanner.grab_banner(resolved_ip, port, args.timeout)
                result['ports'].append(banner_info)
                if args.verbose and banner_info.get('banner'):
                    cp.info(f"  Port {port}: {banner_info['banner'][:80]}")
        
        # Vulnerability scanning
        cp.info("\nRunning vulnerability checks...")
        
        # Web-based checks (if web ports are open)
        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8000]]
        
        if web_ports:
            for port in web_ports:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
                
                if args.check_headers:
                    cp.info(f"  Checking security headers on {url}...")
                    headers_result = await vuln_scanner.check_security_headers(url)
                    if headers_result:
                        result['vulnerabilities'].extend(headers_result)
                
                if args.check_files:
                    cp.info(f"  Checking for exposed files on {url}...")
                    files_result = await vuln_scanner.check_exposed_files(url)
                    if files_result:
                        result['vulnerabilities'].extend(files_result)
                
                if args.check_cms:
                    cp.info(f"  Detecting CMS on {url}...")
                    cms_result = await vuln_scanner.detect_cms(url)
                    if cms_result:
                        result['vulnerabilities'].extend(cms_result)
        
        # SSL/TLS checks
        if args.check_ssl:
            ssl_ports = [p for p in open_ports if p in [443, 8443, 465, 993, 995, 3389]]
            for port in ssl_ports:
                cp.info(f"  Checking SSL/TLS on port {port}...")
                ssl_result = await vuln_scanner.check_ssl_tls(resolved_ip, port)
                if ssl_result:
                    result['vulnerabilities'].extend(ssl_result)
        
        # CVE database queries
        if args.check_cve:
            cp.info("  Querying CVE database...")
            for port_info in result['ports']:
                if port_info.get('service') and port_info.get('version'):
                    cve_results = await vuln_scanner.query_cve_database(
                        port_info['service'],
                        port_info['version']
                    )
                    if cve_results:
                        result['vulnerabilities'].extend(cve_results)
        
        all_results.append(result)
        
        # Print summary for this target
        vuln_count = len(result['vulnerabilities'])
        if vuln_count > 0:
            severities = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            for vuln in result['vulnerabilities']:
                sev = vuln.get('severity', 'INFO')
                severities[sev] = severities.get(sev, 0) + 1
            
            cp.info(f"\nFound {vuln_count} issue(s):")
            if severities['CRITICAL'] > 0:
                cp.critical(f"  CRITICAL: {severities['CRITICAL']}")
            if severities['HIGH'] > 0:
                cp.error(f"  HIGH: {severities['HIGH']}")
            if severities['MEDIUM'] > 0:
                cp.warning(f"  MEDIUM: {severities['MEDIUM']}")
            if severities['LOW'] > 0:
                cp.info(f"  LOW: {severities['LOW']}")
            if severities['INFO'] > 0:
                cp.success(f"  INFO: {severities['INFO']}")
        else:
            cp.success("No vulnerabilities detected")
   
    try:
        return {'scan_results': all_results, 'scan_config': vars(args)}
    finally:
        await vuln_scanner.close_session()

def main():
    """Main entry point."""
    
    if sys.platform == 'win32':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except AttributeError:
            # Python < 3.7
            import codecs
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    
    # Print banner
    print_banner(__version__)
    
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Legal warning
    cp = ColorPrint(not args.no_color)
    cp.warning("\n⚠️  LEGAL WARNING ⚠️")
    cp.warning("Please don't use this tool unless you have the authorization 💔")
 
    print()
    
    try:
        # Run the scan
        results = asyncio.run(run_scan(args))
        
        # Generate reports
        reporter = Reporter(not args.no_color)
        
        # CLI summary
        print("\n" + "="*80)
        reporter.print_cli_summary(results['scan_results'])
        
        # Export results
        if args.output:
            ext = Path(args.output).suffix.lower()
            if ext == '.json':
                reporter.export_json(results, args.output)
            elif ext == '.csv':
                reporter.export_csv(results['scan_results'], args.output)
            elif ext == '.txt':
                reporter.export_text(results, args.output)
            else:
                cp.warning(f"Unknown file extension: {ext}, defaulting to JSON")
                reporter.export_json(results, args.output)
            
            cp.success(f"\nResults saved to: {args.output}")
        
        if args.json:
            reporter.export_json(results, args.json)
            cp.success(f"JSON report saved to: {args.json}")
        
        if args.csv:
            reporter.export_csv(results['scan_results'], args.csv)
            cp.success(f"CSV report saved to: {args.csv}")
        
        if args.html:
            reporter.export_html(results, args.html)
            cp.success(f"HTML report saved to: {args.html}")
        
        cp.success("\nScan completed successfully!")
        
    except KeyboardInterrupt:
        cp.warning("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        cp.error(f"\nFatal error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
