import socket
import ipaddress
from urllib.parse import urlparse
from config import Config

class URLValidator:
    @staticmethod
    def validate_url(url: str) -> tuple[bool, str]:
        if not url:
            return False, "URL cannot be empty."

        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False, "Only http and https protocols are supported."

        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL hostname."

        try:
            addr_info = socket.getaddrinfo(hostname, None)
            ip_addresses = [info[4][0] for info in addr_info]
        except socket.gaierror:
            return False, f"Failed to resolve host '{hostname}'."

        allowed_networks = [ipaddress.ip_network(net) for net in Config.ALLOWED_IP_NETWORKS]

        for ip_str in ip_addresses:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                return False, f"Invalid IP address format: {ip_str}"

            is_allowed = any(ip_obj in net for net in allowed_networks)
            if not is_allowed:
                return False, f"Access restricted: Target IP '{ip_str}' is outside allowed loopback/private subnets."

        return True, "URL validated successfully."
