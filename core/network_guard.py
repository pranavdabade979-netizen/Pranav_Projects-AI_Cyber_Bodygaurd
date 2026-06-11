"""
Network Guard Module
Monitors network connections for unauthorized or suspicious activity
"""
import psutil
from logger import get_logger

log = get_logger("network_guard")

# Trusted IP ranges and known safe IPs (customize as needed)
TRUSTED_RANGES = [
    "192.168.",     # Private network
    "127.",         # Localhost
    "10.",          # Private network
    "172.16.",      # Private network (172.16-172.31)
    "172.17.",      # Docker
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
]

# Known safe IPs (DNS, CDNs, etc.)
KNOWN_SAFE_IPS = {
    "8.8.8.8",      # Google DNS
    "8.8.4.4",      # Google DNS
    "1.1.1.1",      # Cloudflare DNS
    "1.0.0.1",      # Cloudflare DNS
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",  # OpenDNS
    "9.9.9.9",      # Quad9 DNS
    "149.112.112.112", # Quad9 DNS
    # Add more as needed
}

# Suspicious ports commonly used by malware
SUSPICIOUS_PORTS = {
    21,    # FTP
    23,    # Telnet
    25,    # SMTP
    53,    # DNS (but DNS is usually safe)
    80,    # HTTP (common)
    110,   # POP3
    135,   # RPC
    137,   # NetBIOS
    138,   # NetBIOS
    139,   # NetBIOS
    143,   # IMAP
    161,   # SNMP
    389,   # LDAP
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    1434,  # MSSQL
    1521,  # Oracle
    3306,  # MySQL
    3389,  # RDP
    4444,  # Common backdoor
    6667,  # IRC
    8080,  # HTTP proxy
    8443,  # HTTPS alt
    9999,  # Common malware
}


def check_network():
    """
    Check network connections for unknown/suspicious IPs.
    
    Returns:
        list: List of suspicious external IP addresses
    """
    try:
        conns = psutil.net_connections()
        suspicious = []

        for c in conns:
            if not c.raddr:
                continue
            
            ip = str(c.raddr.ip)
            
            # Check if IP is in trusted ranges or known safe
            is_trusted = any(ip.startswith(trusted) for trusted in TRUSTED_RANGES) or ip in KNOWN_SAFE_IPS
            
            # Only flag as suspicious if not trusted AND using suspicious port
            if not is_trusted and c.raddr.port in SUSPICIOUS_PORTS and ip not in suspicious:
                suspicious.append(ip)
                log.warning(f"Suspicious network connection detected: {ip}:{c.raddr.port} (suspicious port)")

        return suspicious
    except Exception as e:
        log.error(f"Error checking network connections: {str(e)}")
        return []