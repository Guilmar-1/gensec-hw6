import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-dev-key-security-scanner')
    DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')
    SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')
    
    # Scanner Limits
    HTTP_TIMEOUT = 5.0  # seconds
    MAX_RESPONSE_SIZE = 2 * 1024 * 1024  # 2 MB limit
    MAX_REDIRECTS = 3
    DEFAULT_TARGET = "http://127.0.0.1:3000"
    
    # Allowed private subnets and loopback addresses
    ALLOWED_IP_NETWORKS = [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ]
