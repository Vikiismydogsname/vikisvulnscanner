"""
Target Handler Module
Handles target validation, resolution, and host availability checking.
"""

import socket
import re
import asyncio
from typing import List, Optional
from ipaddress import ip_address, IPv4Address, IPv6Address
from pathlib import Path


class TargetHandler:
    """Handles target validation and basic reconnaissance."""
    
    # Regex patterns
    IPV4_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    def __init__(self):
        """Initialize the target handler."""
        pass
    
    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        
        target = target.strip()
        
        # Check if it's a valid IP address
        try:
            ip_address(target)
            return True
        except ValueError:
            pass
        
        # Check if it's a valid domain name
        if self.DOMAIN_PATTERN.match(target):
            return True
        
        return False
    
    def resolve_target(self, target: str) -> Optional[str]:
        try:
            # Check if it's already an IP
            ip_address(target)
            return target
        except ValueError:
            pass
        
        # Try to resolve domain name
        try:
            ip = socket.gethostbyname(target)
            return ip
        except socket.gaierror:
            return None
    
    def load_targets(self, filepath: str) -> List[str]:
        targets = []
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"Target file not found: {filepath}")
        
        with open(path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                # Remove comments and whitespace
                line = line.split('#')[0].strip()
                
                if not line:
                    continue
                
                if self.validate_target(line):
                    targets.append(line)
                else:
                    print(f"Warning: Invalid target on line {line_num}: {line}")
        
        return targets
    
    async def is_host_up(self, target: str, timeout: int = 5) -> bool:
        common_ports = [80, 443, 22, 21, 25, 3389, 8080]
        
        async def check_port(port: int) -> bool:
            """Try to connect to a single port."""
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return False
        
        # Try all common ports concurrently
        tasks = [check_port(port) for port in common_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # If any port responded, the host is up
        return any(r is True for r in results)
    
    def reverse_dns(self, ip: str) -> Optional[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return None
    
    def get_ip_info(self, target: str) -> dict:
        info = {
            'original': target,
            'valid': False,
            'ip': None,
            'hostname': None,
            'ip_version': None
        }
        
        if not self.validate_target(target):
            return info
        
        info['valid'] = True
        
        # Resolve to IP
        ip = self.resolve_target(target)
        if not ip:
            return info
        
        info['ip'] = ip
        
        # Determine IP version
        try:
            ip_obj = ip_address(ip)
            if isinstance(ip_obj, IPv4Address):
                info['ip_version'] = 4
            elif isinstance(ip_obj, IPv6Address):
                info['ip_version'] = 6
        except ValueError:
            pass
        
        # Reverse DNS if target was an IP
        if target == ip:
            info['hostname'] = self.reverse_dns(ip)
        else:
            info['hostname'] = target
        
        return info
