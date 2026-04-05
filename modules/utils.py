"""
Utilities Module
Helper functions and utilities for the vulnerability scanner.
"""

import logging
import sys
from typing import Optional


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)


def print_banner(version: str):
    banner = f"""
╔═════════════════════════════════════════════════════════════════════════╗
║                                                                         ║
║██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██║
║██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
║██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
║╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
║ ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
║  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╣
║                                                                         ║
║                 Vikis Vulnerability Scanner v{version:<10}                 ║
║                                                                         ║
║                                                                         ║
╚═════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


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
        colored = self._colorize(f"[CRITICAL] {text}", 'RED')
        if self.use_color:
            colored = f"{self.COLORS['BOLD']}{colored}"
        print(colored)
    
    def error(self, text: str):
        """Print error message (red)."""
        print(self._colorize(f"[ERROR] {text}", 'RED'))
    
    def warning(self, text: str):
        """Print warning message (yellow)."""
        print(self._colorize(f"[WARNING] {text}", 'YELLOW'))
    
    def success(self, text: str):
        """Print success message (green)."""
        print(self._colorize(f"[SUCCESS] {text}", 'GREEN'))
    
    def info(self, text: str):
        """Print info message (cyan)."""
        print(self._colorize(f"[INFO] {text}", 'CYAN'))


def format_bytes(bytes_size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def validate_port(port: int) -> bool:
    return 1 <= port <= 65535


def is_private_ip(ip: str) -> bool:
    from ipaddress import ip_address, IPv4Address
    
    try:
        ip_obj = ip_address(ip)
        if isinstance(ip_obj, IPv4Address):
            return ip_obj.is_private
        return False
    except ValueError:
        return False
