"""Wrappers for optional external pentest tools."""

import asyncio
import json
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qsl, urlparse
from typing import List, Optional


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def tools_available() -> dict:
    """Return availability status of all known external tools."""
    tools = [
        "nmap", "naabu", "masscan", "nuclei", "ffuf", "httpx",
        "subfinder", "amass", "dnsx", "gau", "katana",
        "searchsploit", "trufflehog", "testssl.sh", "wpscan",
        "nikto", "whatweb", "gobuster", "feroxbuster",
        "hakrawler", "arjun", "paramspider", "gowitness",
        "dalfox", "sqlmap", "corsy", "smuggler", "openredirex",
    ]
    return {t: shutil.which(t) is not None for t in tools}

async def run_command(args: List[str], timeout: int = 120,
                      stdin_data: str = "") -> dict:
    """Run a command without shell interpolation."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_data else None,
        )
        stdin_bytes = stdin_data.encode() if stdin_data else None
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes), timeout
        )
        return {
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode or 0,
            "error": None,
        }
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {"stdout": "", "stderr": "timeout", "exit_code": -1, "error": "timeout"}
    except Exception as exc:
        return {"stdout": "", "stderr": str(exc), "exit_code": -1, "error": str(exc)}


def parse_searchsploit_json(text: str, limit: int = 20) -> List[dict]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []

    results = data.get("RESULTS_EXPLOIT", [])
    parsed = []
    for item in results[:limit]:
        parsed.append({
            "title": item.get("Title", ""),
            "edb_id": str(item.get("EDB-ID", "")),
            "date": item.get("Date", ""),
            "author": item.get("Author", ""),
            "type": item.get("Type", ""),
            "platform": item.get("Platform", ""),
            "path": item.get("Path", ""),
        })
    return parsed


async def searchsploit(term: str, limit: int = 20) -> dict:
    if not tool_available("searchsploit"):
        return {"available": False, "term": term, "results": [], "error": "missing"}

    result = await run_command(["searchsploit", "--json", term], timeout=60)
    return {
        "available": True,
        "term": term,
        "results": parse_searchsploit_json(result["stdout"], limit=limit),
        "raw": result["stdout"][:10000],
        "stderr": result["stderr"][:2000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_ffuf_json(text: str) -> List[dict]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []

    parsed = []
    for item in data.get("results", []):
        parsed.append({
            "url": item.get("url", ""),
            "status": item.get("status", 0),
            "length": item.get("length", 0),
            "words": item.get("words", 0),
            "lines": item.get("lines", 0),
            "content_type": item.get("content-type", ""),
            "redirectlocation": item.get("redirectlocation", ""),
            "duration": item.get("duration", 0),
        })
    return parsed


def parse_nuclei_jsonl(text: str) -> List[dict]:
    parsed = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info", {})
        parsed.append({
            "template_id": item.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": str(info.get("severity", "info")).upper(),
            "type": item.get("type", ""),
            "matched_at": item.get("matched-at", item.get("host", "")),
            "matcher_name": item.get("matcher-name", ""),
            "extracted_results": item.get("extracted-results", []),
            "tags": info.get("tags", []),
            "reference": info.get("reference", []),
            "curl_command": item.get("curl-command", ""),
            "ip": item.get("ip", ""),
        })
    return parsed


async def ffuf(url_template: str, wordlist: str, output_file: str,
               rate: Optional[int] = None,
               timeout: int = 240,
               extra_args: Optional[List[str]] = None) -> dict:
    if not tool_available("ffuf"):
        return {"available": False, "results": [], "error": "missing"}

    args = [
        "ffuf",
        "-u", url_template,
        "-w", wordlist,
        "-of", "json",
        "-o", output_file,
        "-mc", "200,204,301,302,307,308,401,403,405",
        "-t", "20",
        "-timeout", "8",
        "-s",
        "-fc", "404",
    ]
    if rate:
        args.extend(["-rate", str(rate)])
    if extra_args:
        args.extend(extra_args)

    result = await run_command(args, timeout=timeout)
    return {
        "available": True,
        "stdout": result["stdout"][:5000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def nuclei_scan(target_url: str,
                      rate_limit: int = 10,
                      timeout: int = 600,
                      tags: Optional[List[str]] = None,
                      severity: Optional[List[str]] = None,
                      templates: Optional[str] = None) -> dict:
    if not tool_available("nuclei"):
        return {"available": False, "results": [], "error": "missing"}

    args = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-rate-limit", str(rate_limit),
        "-timeout", "8",
        "-retries", "2",
        "-stats",
    ]
    if tags:
        args.extend(["-tags", ",".join(tags)])
    if severity:
        args.extend(["-severity", ",".join(severity)])
    if templates:
        args.extend(["-t", templates])

    result = await run_command(args, timeout=timeout)
    return {
        "available": True,
        "results": parse_nuclei_jsonl(result["stdout"]),
        "raw": result["stdout"][:50000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def nuclei_multi(targets: list,
                       rate_limit: int = 10,
                       timeout: int = 600,
                       tags: Optional[List[str]] = None,
                       severity: Optional[List[str]] = None) -> dict:
    """Run nuclei against multiple targets."""
    if not tool_available("nuclei"):
        return {"available": False, "results": [], "error": "missing"}

    targets_input = "\n".join(targets)
    args = [
        "nuclei",
        "-jsonl", "-silent", "-no-color",
        "-rate-limit", str(rate_limit),
        "-timeout", "8",
        "-retries", "2",
    ]
    if tags:
        args.extend(["-tags", ",".join(tags)])
    if severity:
        args.extend(["-severity", ",".join(severity)])

    result = await run_command(args, timeout=timeout, stdin_data=targets_input)
    return {
        "available": True,
        "results": parse_nuclei_jsonl(result["stdout"]),
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def httpx_probe(targets: list,
                      timeout: int = 10,
                      follow_redirects: bool = True) -> List[dict]:
    """Probe HTTP services with httpx for status, title, tech."""
    if not tool_available("httpx"):
        return []

    targets_input = "\n".join(targets)
    args = [
        "httpx",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-json",
        "-follow-redirects" if follow_redirects else "",
        "-timeout", str(timeout),
        "-threads", "20",
    ]
    args = [a for a in args if a]

    result = await run_command(args, timeout=120, stdin_data=targets_input)
    probed = []
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            probed.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return probed


async def katana_crawl(target: str,
                       depth: int = 2,
                       timeout: int = 120) -> List[str]:
    """Crawl a target with katana to find URLs."""
    if not tool_available("katana"):
        return []

    args = [
        "katana",
        "-u", target,
        "-d", str(depth),
        "-silent",
        "-jc",
        "-timeout", "5",
    ]
    result = await run_command(args, timeout=timeout)
    return [u.strip() for u in result["stdout"].split("\n") if u.strip()]


async def hakrawler_crawl(target: str,
                          depth: int = 2,
                          timeout: int = 120) -> List[str]:
    """Crawl a target with hakrawler to find URLs."""
    if not tool_available("hakrawler"):
        return []

    args = ["hakrawler", "-d", str(depth), "-subs"]
    result = await run_command(args, timeout=timeout, stdin_data=target)
    return [u.strip() for u in result["stdout"].split("\n") if u.strip()]


def extract_parameters_from_urls(urls: List[str]) -> List[dict]:
    """Extract query parameters from URLs into stable structured records."""
    records = {}
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        base = parsed._replace(query="", fragment="").geturl()
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            key = (base, name)
            item = records.setdefault(
                key,
                {
                    "url": base,
                    "parameter": name,
                    "example_value": value,
                    "sources": [],
                },
            )
            if url not in item["sources"] and len(item["sources"]) < 5:
                item["sources"].append(url)
    return list(records.values())


def parse_arjun_json(text: str) -> List[dict]:
    """Parse common Arjun JSON outputs."""
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []

    parsed = []
    if isinstance(data, dict):
        for url, params in data.items():
            if isinstance(params, dict):
                params = params.get("params", params.get("parameters", []))
            for param in params or []:
                parsed.append({"url": url, "parameter": str(param), "source": "arjun"})
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            url = item.get("url", "")
            for param in item.get("params", item.get("parameters", [])) or []:
                parsed.append({"url": url, "parameter": str(param), "source": "arjun"})
    return parsed


async def arjun_scan(target: str, output_file: str,
                     timeout: int = 240) -> dict:
    """Run Arjun hidden parameter discovery."""
    if not tool_available("arjun"):
        return {"available": False, "results": [], "error": "missing"}

    args = ["arjun", "-u", target, "-oJ", output_file, "--stable"]
    result = await run_command(args, timeout=timeout)
    output_text = Path(output_file).read_text() if Path(output_file).exists() else result["stdout"]
    return {
        "available": True,
        "results": parse_arjun_json(output_text),
        "stdout": result["stdout"][:5000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def paramspider_scan(domain: str, timeout: int = 180) -> dict:
    """Run ParamSpider for archived parameterized URLs."""
    if not tool_available("paramspider"):
        return {"available": False, "urls": [], "error": "missing"}

    result = await run_command(
        ["paramspider", "-d", domain, "--exclude", "png,jpg,gif,css,woff,svg"],
        timeout=timeout,
    )
    urls = [line.strip() for line in result["stdout"].splitlines() if line.startswith("http")]
    return {
        "available": True,
        "urls": urls,
        "parameters": extract_parameters_from_urls(urls),
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def gowitness_scan(targets: List[str], output_dir: str,
                         timeout: int = 300) -> dict:
    """Run gowitness screenshots against a list of URLs."""
    if not tool_available("gowitness"):
        return {"available": False, "screenshots": [], "error": "missing"}

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    args = ["gowitness", "scan", "file", "-", "--screenshot-path", output_dir, "--write-jsonl"]
    result = await run_command(args, timeout=timeout, stdin_data="\n".join(targets))
    screenshots = []
    for line in result["stdout"].splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        screenshots.append(item)
    return {
        "available": True,
        "screenshots": screenshots,
        "output_dir": output_dir,
        "stdout": result["stdout"][:10000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_dalfox_jsonl(text: str) -> List[dict]:
    """Parse Dalfox JSON/JSONL output."""
    findings = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append({
            "type": item.get("type", item.get("poc_type", "")),
            "url": item.get("data", item.get("url", "")),
            "payload": item.get("payload", ""),
            "evidence": item.get("evidence", item.get("poc", "")),
        })
    return findings


async def dalfox_scan(urls: List[str], timeout: int = 600) -> dict:
    """Run Dalfox in conservative pipe mode."""
    if not tool_available("dalfox"):
        return {"available": False, "results": [], "error": "missing"}

    args = [
        "dalfox", "pipe",
        "--silence",
        "--format", "json",
        "--skip-bav",
        "--only-poc", "v",
    ]
    result = await run_command(args, timeout=timeout, stdin_data="\n".join(urls))
    return {
        "available": True,
        "results": parse_dalfox_jsonl(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_sqlmap_text(text: str) -> List[dict]:
    """Extract high-signal SQLMap vulnerability lines."""
    findings = []
    current_url = ""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if "testing connection to the target URL" in stripped:
            current_url = ""
        if "GET parameter" in stripped or "POST parameter" in stripped:
            findings.append({"url": current_url, "evidence": stripped})
        elif "is vulnerable" in stripped.lower():
            findings.append({"url": current_url, "evidence": stripped})
    return findings


async def sqlmap_scan(url: str, timeout: int = 900) -> dict:
    """Run sqlmap with conservative risk/level defaults."""
    if not tool_available("sqlmap"):
        return {"available": False, "results": [], "error": "missing"}

    args = [
        "sqlmap", "-u", url,
        "--batch",
        "--risk", "1",
        "--level", "1",
        "--threads", "1",
        "--smart",
        "--flush-session",
    ]
    result = await run_command(args, timeout=timeout)
    return {
        "available": True,
        "results": parse_sqlmap_text(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_corsy_json(text: str) -> List[dict]:
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    items = data if isinstance(data, list) else data.get("results", [])
    return [item for item in items if isinstance(item, dict)]


async def corsy_scan(target: str, timeout: int = 180) -> dict:
    """Run Corsy against a target URL."""
    if not tool_available("corsy"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["corsy", "-u", target, "-j"], timeout=timeout)
    return {
        "available": True,
        "results": parse_corsy_json(result["stdout"]),
        "stdout": result["stdout"][:10000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def openredirex_scan(urls: List[str], timeout: int = 300) -> dict:
    """Run openredirex against URL candidates."""
    if not tool_available("openredirex"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["openredirex", "-p", "FUZZ"], timeout=timeout, stdin_data="\n".join(urls))
    hits = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    return {
        "available": True,
        "results": hits,
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def smuggler_scan(target: str, timeout: int = 300) -> dict:
    """Run smuggler against one URL."""
    if not tool_available("smuggler"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["smuggler", "-u", target], timeout=timeout)
    hits = [
        line.strip() for line in result["stdout"].splitlines()
        if "potential" in line.lower() or "vulnerable" in line.lower()
    ]
    return {
        "available": True,
        "results": hits,
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def maigret_scan(username: str, timeout: int = 240) -> dict:
    """Run maigret for username presence checks."""
    if not tool_available("maigret"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(
        ["maigret", username, "--json", "-", "--no-progressbar"],
        timeout=timeout,
    )
    return {
        "available": True,
        "results": parse_maigret_json(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_maigret_json(text: str) -> List[dict]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []
    results = []
    items = data.values() if isinstance(data, dict) else data
    for item in items:
        if not isinstance(item, dict):
            continue
        status = item.get("status", {})
        if isinstance(status, dict) and status.get("status") in ("Claimed", "Found"):
            results.append({
                "site": item.get("name", item.get("site_name", "")),
                "url": item.get("url_user", item.get("url", "")),
                "status": status.get("status"),
            })
    return results


async def holehe_scan(email: str, timeout: int = 180) -> dict:
    """Run holehe for account-registration checks."""
    if not tool_available("holehe"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["holehe", email, "--no-color"], timeout=timeout)
    hits = [
        line.strip() for line in result["stdout"].splitlines()
        if "[+]" in line or "exists" in line.lower()
    ]
    return {
        "available": True,
        "results": hits,
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def theharvester_scan(domain: str, timeout: int = 240) -> dict:
    """Run theHarvester for domain identity OSINT."""
    if not tool_available("theHarvester"):
        return {"available": False, "emails": [], "hosts": [], "error": "missing"}
    result = await run_command(
        ["theHarvester", "-d", domain, "-b", "bing,duckduckgo,crtsh"],
        timeout=timeout,
    )
    emails = sorted(set(re.findall(r"[\w.+-]+@" + re.escape(domain), result["stdout"], re.I)))
    hosts = sorted(set(re.findall(r"(?:[a-z0-9_-]+\.)+" + re.escape(domain), result["stdout"], re.I)))
    return {
        "available": True,
        "emails": emails,
        "hosts": hosts,
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def gitleaks_scan_path(path: str, timeout: int = 240) -> dict:
    """Run gitleaks detect against a local path."""
    if not tool_available("gitleaks"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(
        ["gitleaks", "detect", "--no-git", "--source", path, "--report-format", "json", "--no-banner"],
        timeout=timeout,
    )
    try:
        findings = json.loads(result["stdout"] or "[]")
    except json.JSONDecodeError:
        findings = []
    return {
        "available": True,
        "results": findings if isinstance(findings, list) else [],
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def joomscan_scan(target: str, timeout: int = 300) -> dict:
    """Run joomscan against a Joomla target."""
    if not tool_available("joomscan"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["joomscan", "-u", target, "--no-report"], timeout=timeout)
    return {
        "available": True,
        "results": parse_cms_text_findings(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def droopescan_scan(target: str, cms: str = "", timeout: int = 300) -> dict:
    """Run droopescan against Drupal/Joomla/WordPress targets."""
    if not tool_available("droopescan"):
        return {"available": False, "results": [], "error": "missing"}
    args = ["droopescan", "scan", "drupal", "-u", target, "--output", "json"]
    if cms:
        args[2] = cms.lower()
    result = await run_command(args, timeout=timeout)
    try:
        data = json.loads(result["stdout"] or "{}")
    except json.JSONDecodeError:
        data = {}
    return {
        "available": True,
        "results": data,
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def cmseek_scan(target: str, timeout: int = 300) -> dict:
    """Run CMSeek for CMS detection/vulnerability hints."""
    if not tool_available("cmseek"):
        return {"available": False, "results": {}, "error": "missing"}
    result = await run_command(["cmseek", "-u", target, "--batch", "--random-agent"], timeout=timeout)
    return {
        "available": True,
        "results": parse_cms_text_findings(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_cms_text_findings(text: str) -> List[dict]:
    findings = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if any(token in lowered for token in ("vulnerab", "outdated", "version", "cve-", "admin")):
            findings.append({"evidence": stripped})
    return findings[:100]


async def wpscan(target: str, api_token: str = "",
                 timeout: int = 300) -> dict:
    """Run WPScan for WordPress vulnerability detection."""
    if not tool_available("wpscan"):
        return {"available": False, "results": [], "error": "missing"}

    args = ["wpscan", "--url", target, "--no-banner",
            "--format", "json", "--random-user-agent"]
    if api_token:
        args.extend(["--api-token", api_token])

    result = await run_command(args, timeout=timeout)
    try:
        data = json.loads(result["stdout"])
        return {"available": True, "results": data, "exit_code": result["exit_code"]}
    except json.JSONDecodeError:
        return {"available": True, "results": {}, "raw": result["stdout"][:10000],
                "exit_code": result["exit_code"]}


async def whatweb_scan(target: str, timeout: int = 60) -> dict:
    """Run whatweb for technology fingerprinting."""
    if not tool_available("whatweb"):
        return {"available": False, "results": {}, "error": "missing"}

    result = await run_command(
        ["whatweb", "--color=never", "--log-json=-", target],
        timeout=timeout
    )
    try:
        data = json.loads(result["stdout"])
        if isinstance(data, list) and data:
            return {"available": True, "results": data[0]}
    except (json.JSONDecodeError, IndexError):
        pass
    return {"available": True, "results": {}, "raw": result["stdout"][:5000]}


async def nikto_scan(target: str, timeout: int = 300) -> dict:
    """Run nikto web server scanner."""
    if not tool_available("nikto"):
        return {"available": False, "results": [], "error": "missing"}

    result = await run_command(
        ["nikto", "-h", target, "-Format", "json", "-output", "/dev/stdout",
         "-nointeractive", "-Tuning", "013479"],
        timeout=timeout
    )
    try:
        data = json.loads(result["stdout"])
        return {"available": True, "results": data}
    except json.JSONDecodeError:
        return {"available": True, "results": {}, "raw": result["stdout"][:10000]}


async def naabu_scan(target: str, ports: str = "top-1000",
                     timeout: int = 300) -> List[dict]:
    """Fast port scan with naabu."""
    if not tool_available("naabu"):
        return []

    port_arg = f"-top-ports {ports}" if ports.startswith("top") else f"-p {ports}"
    result = await run_command(
        ["naabu", "-host", target, "-silent", "-json"] + port_arg.split(),
        timeout=timeout
    )
    ports_found = []
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            ports_found.append({"host": data.get("host", ""), "port": data.get("port", 0)})
        except json.JSONDecodeError:
            if ":" in line:
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[1].isdigit():
                    ports_found.append({"host": parts[0], "port": int(parts[1])})
    return ports_found

