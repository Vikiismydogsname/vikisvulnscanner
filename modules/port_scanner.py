"""
Port Scanner Module
Handles concurrent port scanning and service banner grabbing.
"""

import asyncio
import socket
from typing import List, Dict, Set, Union


class PortScanner:
    # Top 100 most common ports
    TOP_100_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        20, 69, 123, 137, 138, 161, 162, 389, 636, 514,
        515, 587, 1025, 1433, 1434, 1521, 2049, 2082, 2083, 2086,
        2087, 2095, 2096, 3128, 5432, 5800, 5901, 6379, 7001, 8008,
        8081, 8443, 8888, 9090, 9100, 9200, 9418, 10000, 27017, 50000,
        465, 548, 554, 1080, 1194, 1337, 1900, 3000, 3268, 3269,
        4443, 5222, 5269, 5353, 5432, 5631, 5672, 5984, 6000, 6001,
        6379, 7000, 8000, 8009, 8181, 8291, 8834, 9009, 9043, 9050,
        9051, 9418, 9999, 11211, 27017, 27018, 27019, 28017, 49152, 49153
    ]
    
    # Common service signatures
    SERVICE_SIGNATURES = {
        'SSH': [b'SSH-', b'OpenSSH'],
        'HTTP': [b'HTTP/', b'Server:'],
        'FTP': [b'220', b'FTP'],
        'SMTP': [b'220', b'SMTP', b'ESMTP'],
        'MySQL': [b'mysql', b'MariaDB'],
        'PostgreSQL': [b'PostgreSQL'],
        'Redis': [b'redis_version'],
        'MongoDB': [b'MongoDB'],
        'Telnet': [b'Telnet'],
        'POP3': [b'+OK'],
        'IMAP': [b'* OK'],
    }
    
    def __init__(self, timeout: int = 3, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)
    
    def parse_port_string(self, port_string: str) -> List[int]:
        ports = set()
        
        for part in port_string.split(','):
            part = part.strip()
            
            if '-' in part:
                # Port range
                try:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end + 1))
                except ValueError:
                    print(f"Warning: Invalid port range: {part}")
            else:
                # Single port
                try:
                    ports.add(int(part))
                except ValueError:
                    print(f"Warning: Invalid port: {part}")
        
        return sorted([p for p in ports if 1 <= p <= 65535])
    
    def get_top_ports(self, n: int = 100) -> List[int]:
        return self.TOP_100_PORTS[:min(n, len(self.TOP_100_PORTS))]
    
    async def scan_port(self, host: str, port: int) -> bool:
        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return False
    
    async def scan_ports(self, host: str, ports: List[int]) -> Set[int]:
        tasks = [self.scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = {port for port, is_open in zip(ports, results) if is_open}
        return open_ports
    
    async def grab_banner(self, host: str, port: int, timeout: int = 5) -> Dict[str, Union[str, int]]:
        result = {
            'port': port,
            'state': 'open',
            'service': self.guess_service(port),
            'banner': None,
            'version': None
        }
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Try to read initial banner (some services send it automatically)
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                if banner:
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                # No automatic banner, try sending a probe
                pass
            
            # If no banner yet, send HTTP probe for web servers
            if not result['banner'] and port in [80, 443, 8080, 8443, 8000]:
                writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
                await writer.drain()
                try:
                    response = await asyncio.wait_for(reader.read(1024), timeout=2)
                    if response:
                        result['banner'] = response.decode('utf-8', errors='ignore').strip()
                except asyncio.TimeoutError:
                    pass
            
            # If still no banner, send generic probe
            if not result['banner']:
                writer.write(b'\r\n')
                await writer.drain()
                try:
                    response = await asyncio.wait_for(reader.read(1024), timeout=2)
                    if response:
                        result['banner'] = response.decode('utf-8', errors='ignore').strip()
                except asyncio.TimeoutError:
                    pass
            
            writer.close()
            await writer.wait_closed()
            
            # Extract service and version from banner
            if result['banner']:
                service, version = self.parse_banner(result['banner'])
                if service:
                    result['service'] = service
                if version:
                    result['version'] = version
            
        except Exception:
            pass
        
        return result
    
    def guess_service(self, port: int) -> str:
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
        }
        return common_services.get(port, 'Unknown')
    
    def parse_banner(self, banner: str) -> tuple:
        service = None
        version = None
        
        banner_lower = banner.lower()
        
        # SSH
        if 'ssh-' in banner_lower:
            service = 'SSH'
            if 'openssh' in banner_lower:
                import re
                match = re.search(r'openssh[_\s]?([\d.]+\w*)', banner_lower)
                if match:
                    version = match.group(1)
        
        # HTTP Server
        elif 'server:' in banner_lower:
            service = 'HTTP'
            import re
            match = re.search(r'server:\s*([^\r\n]+)', banner_lower)
            if match:
                server_line = match.group(1).strip()
                # Try to extract version
                version_match = re.search(r'(apache|nginx|iis|lighttpd)[/\s]?([\d.]+)', server_line)
                if version_match:
                    version = f"{version_match.group(1)}/{version_match.group(2)}"
        
        # FTP
        elif banner.startswith('220') and 'ftp' in banner_lower:
            service = 'FTP'
            import re
            match = re.search(r'(\w+)\s+ftp[^\d]*([\d.]+)', banner_lower)
            if match:
                version = f"{match.group(1)}/{match.group(2)}"
        
        # SMTP
        elif banner.startswith('220') and ('smtp' in banner_lower or 'esmtp' in banner_lower):
            service = 'SMTP'
        
        # MySQL
        elif 'mysql' in banner_lower or 'mariadb' in banner_lower:
            service = 'MySQL'
            import re
            match = re.search(r'(mysql|mariadb)[^\d]*([\d.]+)', banner_lower)
            if match:
                version = f"{match.group(1)}/{match.group(2)}"
        
        return service, version
