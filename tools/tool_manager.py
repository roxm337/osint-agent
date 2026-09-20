"""Tool Manager — auto-detect, install, and interface with external pentesting tools."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ToolInfo:
    name: str
    description: str
    categories: list[str] = field(default_factory=list)
    install_cmd: str = ""
    min_version: str = ""
    available: bool = False
    version: str = ""
    path: str = ""


SCOUT = "brew"


TOOL_DEFINITIONS: list[ToolInfo] = [
    # Web application scanners
    ToolInfo("nuclei", "Fast vulnerability scanner based on YAML templates",
             categories=["web", "cve", "vuln-scan"],
             install_cmd=f"{SCOUT} install nuclei" if SCOUT == "brew" else "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ToolInfo("httpx", "HTTP probing toolkit",
             categories=["web", "probe"],
             install_cmd=f"{SCOUT} install httpx" if SCOUT == "brew" else "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ToolInfo("ffuf", "Fast web fuzzer",
             categories=["web", "fuzzing"],
             install_cmd=f"{SCOUT} install ffuf" if SCOUT == "brew" else "go install github.com/ffuf/ffuf/v2@latest"),
    ToolInfo("dalfox", "XSS scanning and parameter analysis",
             categories=["web", "xss"],
             install_cmd="go install github.com/hahwul/dalfox/v2@latest"),
    ToolInfo("katana", "Web crawler and spider",
             categories=["web", "crawl"],
             install_cmd="go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ToolInfo("gau", "Get All URLs — fetch known URLs from AlienVault, WayBack, etc.",
             categories=["web", "recon"],
             install_cmd="go install github.com/lc/gau/v2/cmd/gau@latest"),
    ToolInfo("hakrawler", "Fast web crawler",
             categories=["web", "crawl"],
             install_cmd="go install github.com/hakluke/hakrawler@latest"),
    ToolInfo("arjun", "HTTP parameter discovery",
             categories=["web", "param"],
             install_cmd="pipx install arjun"),
    ToolInfo("paramspider", "Parameter discovery from archives",
             categories=["web", "param"],
             install_cmd="pipx install paramspider"),
    ToolInfo("wpscan", "WordPress vulnerability scanner",
             categories=["web", "cms", "wordpress"],
             install_cmd=f"{SCOUT} install wpscan" if SCOUT == "brew" else "gem install wpscan"),
    ToolInfo("whatweb", "Web technology fingerprinting",
             categories=["web", "fingerprint"],
             install_cmd=f"{SCOUT} install whatweb" if SCOUT == "brew" else "gem install whatweb"),
    ToolInfo("nikto", "Web server scanner",
             categories=["web", "vuln-scan"],
             install_cmd=f"{SCOUT} install nikto" if SCOUT == "brew" else "git clone https://github.com/sullo/nikto"),
    ToolInfo("smuggler", "HTTP request smuggling tool",
             categories=["web", "smuggling"],
             install_cmd="pipx install smuggler"),
    ToolInfo("corsy", "CORS misconfiguration scanner",
             categories=["web", "cors"],
             install_cmd="pipx install corsy"),
    ToolInfo("openredirex", "Open redirect scanner",
             categories=["web", "redirect"],
             install_cmd="go install github.com/theblackturtle/openredirex@latest"),
    # SQL / Injection
    ToolInfo("sqlmap", "Automatic SQL injection and database takeover tool",
             categories=["web", "sqli", "database"],
             install_cmd=f"{SCOUT} install sqlmap" if SCOUT == "brew" else "pipx install sqlmap"),
    ToolInfo("commix", "Command injection exploitation tool",
             categories=["web", "cmd-injection"],
             install_cmd="pipx install commix"),
    # DNS / Network
    ToolInfo("subfinder", "Passive subdomain discovery",
             categories=["dns", "subdomain"],
             install_cmd=f"{SCOUT} install subfinder" if SCOUT == "brew" else "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ToolInfo("dnsx", "DNS probing toolkit",
             categories=["dns", "probe"],
             install_cmd="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ToolInfo("naabu", "Fast port scanner",
             categories=["network", "port-scan"],
             install_cmd=f"{SCOUT} install naabu" if SCOUT == "brew" else "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ToolInfo("nmap", "Network discovery and security scanning",
             categories=["network", "port-scan"],
             install_cmd=f"{SCOUT} install nmap"),
    ToolInfo("masscan", "Mass IP port scanner",
             categories=["network", "port-scan"],
             install_cmd=f"{SCOUT} install masscan"),
    # Recon
    ToolInfo("amass", "In-depth subdomain discovery and enumeration",
             categories=["recon", "subdomain"],
             install_cmd=f"{SCOUT} install amass"),
    ToolInfo("gowitness", "Web screenshot utility",
             categories=["recon", "visual"],
             install_cmd=f"{SCOUT} install gowitness" if SCOUT == "brew" else "go install github.com/sensepost/gowitness@latest"),
    ToolInfo("gitleaks", "Git repository secret scanning",
             categories=["recon", "secrets"],
             install_cmd=f"{SCOUT} install gitleaks" if SCOUT == "brew" else "go install github.com/gitleaks/gitleaks/v8@latest"),
    ToolInfo("trufflehog", "Secret discovery across sources",
             categories=["recon", "secrets"],
             install_cmd=f"{SCOUT} install trufflehog" if SCOUT == "brew" else "pipx install trufflehog"),
    ToolInfo("theHarvester", "Email, subdomain, and name enumeration",
             categories=["recon", "osint"],
             install_cmd="pipx install theHarvester"),
    ToolInfo("maigret", "Username search across social networks",
             categories=["recon", "osint"],
             install_cmd="pipx install maigret"),
    ToolInfo("holehe", "Email account registration check",
             categories=["recon", "email"],
             install_cmd="pipx install holehe"),
    # TLS / Crypto
    ToolInfo("testssl.sh", "TLS/SSL security testing",
             categories=["tls", "crypto"],
             install_cmd=f"{SCOUT} install testssl" if SCOUT == "brew" else "git clone https://github.com/drwetter/testssl.sh.git"),
    # CMS
    ToolInfo("joomscan", "Joomla vulnerability scanner",
             categories=["web", "cms", "joomla"],
             install_cmd="git clone https://github.com/OWASP/joomscan.git"),
    ToolInfo("droopescan", "Drupal/Joomla/WordPress scanner",
             categories=["web", "cms"],
             install_cmd="pipx install droopescan"),
    ToolInfo("cmseek", "CMS detection and vulnerability scanner",
             categories=["web", "cms"],
             install_cmd="pipx install cmseek"),
    # Exploit
    ToolInfo("searchsploit", "Exploit-DB command-line search",
             categories=["exploit", "reference"],
             install_cmd=f"{SCOUT} install exploit-db" if SCOUT == "brew" else "git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb"),
]

# macOS default install — check for brew
if shutil.which("brew"):
    INSTALLER = "brew"
else:
    INSTALLER = "go"


class ToolManager:
    """Detect, install, and manage external pentesting tools."""

    def __init__(self):
        self.tools: dict[str, ToolInfo] = {}
        self._scanned = False

    def scan(self) -> dict[str, ToolInfo]:
        """Scan for available tools."""
        for tool in TOOL_DEFINITIONS:
            path = shutil.which(tool.name)
            tool.available = path is not None
            tool.path = path or ""
            if path:
                tool.version = self._get_version(tool.name)
            self.tools[tool.name] = tool
        self._scanned = True
        return self.tools

    def available_tools(self, category: Optional[str] = None) -> list[ToolInfo]:
        if not self._scanned:
            self.scan()
        tools = list(self.tools.values())
        if category:
            tools = [t for t in tools if category in t.categories]
        return [t for t in tools if t.available]

    def missing_tools(self, category: Optional[str] = None) -> list[ToolInfo]:
        if not self._scanned:
            self.scan()
        tools = list(self.tools.values())
        if category:
            tools = [t for t in tools if category in t.categories]
        return [t for t in tools if not t.available]

    async def install_tool(self, name: str) -> dict:
        """Attempt to install a tool."""
        tool = self.tools.get(name)
        if not tool:
            return {"success": False, "error": f"Unknown tool: {name}"}
        if tool.available:
            return {"success": True, "message": f"{name} already installed"}

        install_cmd = tool.install_cmd
        if not install_cmd:
            return {"success": False, "error": f"No install command for {name}"}

        try:
            process = await asyncio.create_subprocess_shell(
                install_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            success = process.returncode == 0
            tool.available = success
            return {
                "success": success,
                "message": f"Installed {name}" if success else f"Failed: {stderr.decode()[:200]}",
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": f"Installation timed out for {name}"}

    async def install_missing(self, category: Optional[str] = None) -> list[dict]:
        """Install all missing tools, optionally filtered by category."""
        missing = self.missing_tools(category)
        results = []
        for tool in missing:
            result = await self.install_tool(tool.name)
            results.append(result)
        return results

    def summary(self) -> dict:
        if not self._scanned:
            self.scan()
        available = [t for t in self.tools.values() if t.available]
        missing = [t for t in self.tools.values() if not t.available]
        return {
            "total": len(self.tools),
            "available": len(available),
            "missing": len(missing),
            "available_tools": [t.name for t in available],
            "missing_tools": [t.name for t in missing],
            "installer": INSTALLER,
        }

    def _get_version(self, name: str) -> str:
        try:
            result = subprocess.run(
                [name, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip()[:100] or result.stderr.strip()[:100]
        except Exception:
            return ""
