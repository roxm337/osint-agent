"""Async tool wrappers for DNS, HTTP, WHOIS, port scanning, etc."""

import asyncio
import subprocess
import json
import re
import time
import base64
import tempfile
import os
from typing import Optional
from urllib.parse import quote, urlencode

# Global cookie jar for stateful web sessions across requests
_COOKIE_JAR: str | None = None
_HTTP_SESSION_HEADERS: dict[str, str] = {}

def _get_cookie_jar() -> str:
    global _COOKIE_JAR
    if _COOKIE_JAR is None or not os.path.exists(_COOKIE_JAR):
        _COOKIE_JAR = os.path.join(tempfile.gettempdir(), "osint_agent_cookies.txt")
    return _COOKIE_JAR

def reset_cookie_jar():
    global _COOKIE_JAR
    if _COOKIE_JAR and os.path.exists(_COOKIE_JAR):
        try:
            os.remove(_COOKIE_JAR)
        except OSError:
            pass
    _COOKIE_JAR = None


def configure_http_session(config: Optional[dict] = None):
    """Configure headers/cookies applied to all wrapper HTTP requests."""
    global _HTTP_SESSION_HEADERS
    auth = (config or {}).get("auth", {}) or {}
    headers = {
        str(k): str(v)
        for k, v in (auth.get("headers") or {}).items()
        if k and v is not None and str(v) != ""
    }

    bearer = auth.get("bearer_token") or auth.get("token")
    if bearer and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {bearer}"

    cookie_header = auth.get("cookie") or auth.get("cookie_header")
    cookies = auth.get("cookies") or {}
    if isinstance(cookies, dict) and cookies:
        cookie_header = "; ".join(
            f"{k}={v}" for k, v in cookies.items()
            if k and v is not None and str(v) != ""
        )
    if cookie_header and "Cookie" not in headers:
        headers["Cookie"] = str(cookie_header)

    _HTTP_SESSION_HEADERS = headers


def _merge_session_headers(headers: Optional[dict] = None) -> dict:
    merged = dict(_HTTP_SESSION_HEADERS)
    if headers:
        merged.update({str(k): str(v) for k, v in headers.items() if v is not None})
    return merged


class RateLimiter:
    """Async rate limiter with concurrency and per-minute caps."""

    def __init__(self, max_concurrent: int = 5, max_per_minute: int = 60):
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._max_per_minute = max_per_minute
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        await self._semaphore.acquire()
        async with self._lock:
            now = time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < 60]
            if len(self._timestamps) >= self._max_per_minute:
                wait = self._timestamps[0] + 60 - now
                if wait > 0:
                    await asyncio.sleep(wait)
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < 60]
            self._timestamps.append(now)
        return self

    async def __aexit__(self, *args):
        self._semaphore.release()


_http_limiter = RateLimiter(max_concurrent=5, max_per_minute=60)


def configure_http_limiter(max_concurrent: int = 5, max_per_minute: int = 60):
    global _http_limiter
    _http_limiter = RateLimiter(max_concurrent, max_per_minute)


async def bash(command: str, timeout: int = 120) -> dict:
    """Execute a shell command with timeout. Returns {stdout, stderr, exit_code}."""
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
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
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "exit_code": -1, "error": str(e)}


async def curl(url: str, method: str = "GET",
              headers: Optional[dict] = None,
              data: Optional[str] = None,
              http1_0: bool = False,
              output: str = "status",
              follow_redirects: bool = True,
              timeout: int = 10) -> dict:
    """HTTP request via curl. Returns status code + optional body/headers."""
    async with _http_limiter:
        cmd = ["curl", "-s", "--max-time", str(timeout), "--connect-timeout", "5"]

        # Enable cookie persistence for stateful web sessions
        cmd.extend(["-b", _get_cookie_jar(), "-c", _get_cookie_jar()])

        if follow_redirects:
            cmd.append("-L")

        if output == "status":
            cmd.extend(["-o", "/dev/null", "-w", "%{http_code}"])
        elif output == "headers":
            cmd.extend(["-D", "-", "-o", "/dev/null"])
        elif output == "body":
            cmd.extend(["-w", ""])
        elif output == "full":
            cmd.extend(["-D", "-"])

        if http1_0:
            cmd.append("--http1.0")
        if method != "GET":
            cmd.extend(["-X", method])
        merged_headers = _merge_session_headers(headers)
        if merged_headers:
            for k, v in merged_headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if data:
            cmd.extend(["-d", data])

        cmd.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout + 5)
            out = stdout.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            return {"status": 0, "body": "", "error": "timeout"}
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e)}

        if output == "status":
            try:
                return {"status": int(out), "body": ""}
            except ValueError:
                return {"status": 0, "body": out, "error": "non-numeric status"}
        elif output == "headers":
            status = 0
            for line in out.split("\n"):
                m = re.match(r"HTTP/[\d.]+ (\d+)", line)
                if m:
                    status = int(m.group(1))
            return {"status": status, "body": out}
        elif output == "full":
            parts = out.split("\r\n\r\n", 1) if "\r\n\r\n" in out else out.split("\n\n", 1)
            header_part = parts[0] if parts else ""
            body_part = parts[1] if len(parts) > 1 else ""
            status = 0
            for line in header_part.split("\n"):
                m = re.match(r"HTTP/[\d.]+ (\d+)", line)
                if m:
                    status = int(m.group(1))
            return {"status": status, "body": body_part, "headers": header_part}
        else:
            return {"status": 0, "body": out}


async def curl_with_status(url: str, **kwargs) -> dict:
    """Fetch URL and return both status code and body."""
    async with _http_limiter:
        timeout = int(kwargs.get("timeout", 10) or 10)
        cmd = [
            "curl", "-s", "-L",
            "--max-time", str(timeout), "--connect-timeout", str(min(timeout, 5)),
            "-w", "\n__STATUS__%{http_code}",
            url,
        ]
        merged_headers = _merge_session_headers(kwargs.get("headers"))
        if merged_headers:
            for k, v in merged_headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout + 5)
            out = stdout.decode("utf-8", errors="replace")
            if "__STATUS__" in out:
                body, status_str = out.rsplit("__STATUS__", 1)
                try:
                    return {"status": int(status_str.strip()), "body": body}
                except ValueError:
                    pass
        except Exception:
            pass
        return {"status": 0, "body": ""}


async def curl_json(url: str, **kwargs) -> Optional[dict]:
    """Fetch URL and parse as JSON."""
    result = await curl(url, output="body", **kwargs)
    body = result.get("body", "").strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


async def curl_json_with_status(url: str, **kwargs) -> tuple:
    """Fetch URL and return (status, parsed_json_or_None)."""
    result = await curl_with_status(url, **kwargs)
    status = result.get("status", 0)
    body = result.get("body", "").strip()
    try:
        data = json.loads(body) if body else None
    except json.JSONDecodeError:
        data = None
    return status, data


async def dig(record_type: str, domain: str,
              server: str = "", follow_cname: bool = False) -> dict:
    """DNS lookup. Returns list of answers."""
    if follow_cname:
        cmd = f"dig {record_type} {domain}"
    else:
        cmd = f"dig +short {record_type} {domain}"
    if server:
        cmd += f" @{server}"
    result = await bash(cmd)
    answers = []
    for line in result["stdout"].split("\n"):
        line = line.strip().strip('"').strip("'").strip('“').strip('”')
        if line and not line.startswith(";") and not line.startswith(";;"):
            answers.append(line)
    return {
        "domain": domain,
        "type": record_type,
        "answers": answers,
        "raw": result["stdout"],
    }


async def dig_all(domain: str) -> dict:
    """Fetch all DNS record types for a domain in parallel."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "PTR"]
    tasks = {rtype: dig(rtype, domain) for rtype in record_types}
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    records = {}
    for rtype, result in zip(tasks.keys(), results):
        if not isinstance(result, Exception) and result.get("answers"):
            records[rtype] = result["answers"]
    return records


async def dig_bulk(hostnames: list, record_type: str = "A",
                   concurrency: int = 20) -> dict:
    """Bulk DNS resolution for a list of hostnames. Returns {hostname: [answers]}."""
    sem = asyncio.Semaphore(concurrency)

    async def _resolve(host):
        async with sem:
            result = await dig(record_type, host)
            return host, result.get("answers", [])

    pairs = await asyncio.gather(*[_resolve(h) for h in hostnames])
    return {h: answers for h, answers in pairs}


async def whois_lookup(query: str) -> dict:
    """WHOIS lookup for domain or IP."""
    result = await bash(f"whois {query}")
    text = result["stdout"]
    fields = {}
    for line in text.split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            val = val.strip()
            if key and val and key not in fields:
                fields[key] = val
    return {
        "query": query,
        "fields": fields,
        "raw": text[:3000],
    }


async def rdap_lookup(domain: str) -> dict:
    """RDAP lookup — structured JSON alternative to WHOIS."""
    result = await bash(
        f"curl -s 'https://rdap.org/domain/{domain}' "
        f"--max-time 10 -H 'Accept: application/json' 2>/dev/null || true"
    )
    try:
        data = json.loads(result["stdout"])
        registrar = ""
        registrant = ""
        created = ""
        expires = ""
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [[], []])
            if "registrar" in roles and vcard:
                for field in vcard[1]:
                    if field[0] == "fn":
                        registrar = field[3]
            if "registrant" in roles and vcard:
                for field in vcard[1]:
                    if field[0] == "fn":
                        registrant = field[3]
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                created = event.get("eventDate", "")
            if event.get("eventAction") == "expiration":
                expires = event.get("eventDate", "")
        return {
            "domain": domain,
            "registrar": registrar,
            "registrant": registrant,
            "created": created,
            "expires": expires,
            "status": data.get("status", []),
            "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])],
            "raw": data,
        }
    except (json.JSONDecodeError, KeyError, TypeError):
        return {"domain": domain, "raw": {}}


async def crtsh(domain: str) -> list:
    """Query certificate transparency logs via crt.sh."""
    result = await bash(
        f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' "
        f"--max-time 20"
    )
    try:
        data = json.loads(result["stdout"])
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, TypeError):
        pass
    return []


async def otx_passive_dns(domain: str) -> list:
    """Query OTX AlienVault for passive DNS/subdomain data."""
    result = await bash(
        f"curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns' "
        f"--max-time 15 -H 'User-Agent: Mozilla/5.0' 2>/dev/null || true"
    )
    try:
        data = json.loads(result["stdout"])
        return data.get("passive_dns", [])
    except (json.JSONDecodeError, TypeError):
        return []


async def urlscan_search(domain: str, api_key: str = "") -> list:
    """Query urlscan.io for domain-related URLs."""
    headers_str = ""
    if api_key:
        headers_str = f" -H 'API-Key: {api_key}'"
    result = await bash(
        f"curl -s 'https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200' "
        f"{headers_str} --max-time 15 2>/dev/null || true"
    )
    try:
        data = json.loads(result["stdout"])
        return data.get("results", [])
    except (json.JSONDecodeError, TypeError):
        return []


async def hackertarget_hostsearch(domain: str) -> list:
    """HackerTarget host search API (free tier)."""
    result = await bash(
        f"curl -s 'https://api.hackertarget.com/hostsearch/?q={domain}' "
        f"--max-time 15 2>/dev/null || true"
    )
    output = result.get("stdout", "").strip()
    if not output or "error" in output.lower() or "API count" in output:
        return []
    hosts = []
    for line in output.split("\n"):
        line = line.strip()
        if line and "," in line:
            parts = line.split(",")
            if len(parts) >= 1:
                hosts.append({"hostname": parts[0].strip(), "ip": parts[1].strip() if len(parts) > 1 else ""})
    return hosts


def _host_matches_domain(hostname: str, domain: str) -> bool:
    host = hostname.strip().lower().strip(".")
    root = domain.strip().lower().strip(".")
    return host == root or host.endswith(f".{root}")


def _extract_domain_hosts(text: str, domain: str) -> list:
    pattern = re.compile(
        rf"(?i)\b(?:[a-z0-9_-]+\.)+{re.escape(domain.strip().lower())}\b"
    )
    hosts = {
        match.group(0).lower().strip(".")
        for match in pattern.finditer(text or "")
        if _host_matches_domain(match.group(0), domain)
    }
    return sorted(hosts)


async def rapiddns(domain: str) -> list:
    """RapidDNS passive subdomain source. Returns hostnames only."""
    result = await curl(
        f"https://rapiddns.io/subdomain/{quote(domain)}?full=1",
        output="body",
        timeout=20,
    )
    return _extract_domain_hosts(result.get("body", ""), domain)


async def anubisdb(domain: str) -> list:
    """AnubisDB passive subdomain source."""
    data = await curl_json(
        f"https://jldc.me/anubis/subdomains/{quote(domain)}",
        timeout=20,
    )
    if not isinstance(data, list):
        return []
    hosts = {
        str(host).lower().replace("*.", "").strip(".")
        for host in data
        if _host_matches_domain(str(host).replace("*.", ""), domain)
    }
    return sorted(hosts)


async def certspotter(domain: str) -> list:
    """Cert Spotter CT source. Returns certificate DNS names."""
    query = urlencode({
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names",
    })
    data = await curl_json(
        f"https://api.certspotter.com/v1/issuances?{query}",
        timeout=20,
    )
    if not isinstance(data, list):
        return []
    hosts = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        for name in item.get("dns_names", []) or []:
            clean = str(name).lower().replace("*.", "").strip(".")
            if _host_matches_domain(clean, domain):
                hosts.add(clean)
    return sorted(hosts)


async def bgpview_asn(asn: str) -> dict:
    """BGPView ASN prefix lookup."""
    clean_asn = str(asn).upper().replace("AS", "").strip()
    if not clean_asn.isdigit():
        return {"asn": asn, "ipv4_prefixes": [], "ipv6_prefixes": [], "raw": {}}
    data = await curl_json(
        f"https://api.bgpview.io/asn/{clean_asn}/prefixes",
        timeout=20,
    )
    if not isinstance(data, dict):
        return {"asn": f"AS{clean_asn}", "ipv4_prefixes": [], "ipv6_prefixes": [], "raw": {}}
    payload = data.get("data", {}) if isinstance(data.get("data", {}), dict) else {}
    return {
        "asn": f"AS{clean_asn}",
        "name": payload.get("name", ""),
        "description": payload.get("description_short", ""),
        "ipv4_prefixes": payload.get("ipv4_prefixes", []) or [],
        "ipv6_prefixes": payload.get("ipv6_prefixes", []) or [],
        "raw": data,
    }


async def epss_score(cves: list[str]) -> dict:
    """FIRST EPSS scores keyed by CVE."""
    cleaned = sorted({
        str(cve).upper().strip()
        for cve in cves
        if str(cve).upper().startswith("CVE-")
    })
    if not cleaned:
        return {}
    query = urlencode({"cve": ",".join(cleaned)})
    data = await curl_json(
        f"https://api.first.org/data/v1/epss?{query}",
        timeout=20,
    )
    if not isinstance(data, dict):
        return {}
    scores = {}
    for item in data.get("data", []) or []:
        cve = str(item.get("cve", "")).upper()
        try:
            scores[cve] = {
                "epss": float(item.get("epss", 0.0)),
                "percentile": float(item.get("percentile", 0.0)),
                "date": item.get("date", ""),
            }
        except (TypeError, ValueError):
            continue
    return scores


async def osv_query(package: str, ecosystem: str = "") -> dict:
    """Query OSV for package vulnerabilities."""
    payload = {"package": {"name": package}}
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem
    data = await curl_json(
        "https://api.osv.dev/v1/query",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def urlhaus_host(host: str) -> dict:
    """URLHaus host reputation lookup."""
    data = await curl_json(
        "https://urlhaus-api.abuse.ch/v1/host/",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urlencode({"host": host}),
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def threatfox_ioc(ioc: str) -> dict:
    """ThreatFox IOC search."""
    data = await curl_json(
        "https://threatfox-api.abuse.ch/api/v1/",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"query": "search_ioc", "search_term": ioc}),
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def ip_api(query: str) -> dict:
    """ip-api.com geo/ASN fallback."""
    fields = (
        "status,message,country,countryCode,regionName,city,isp,org,as,asname,"
        "reverse,query"
    )
    data = await curl_json(
        f"http://ip-api.com/json/{quote(query)}?{urlencode({'fields': fields})}",
        timeout=10,
    )
    return data if isinstance(data, dict) else {}


async def virustotal_domain(domain: str, api_key: str) -> dict:
    """VirusTotal domain enrichment."""
    if not api_key:
        return {}
    data = await curl_json(
        f"https://www.virustotal.com/api/v3/domains/{quote(domain)}",
        headers={"x-apikey": api_key},
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def virustotal_domain_subdomains(domain: str, api_key: str, limit: int = 40) -> list:
    """VirusTotal domain subdomains."""
    if not api_key:
        return []
    query = urlencode({"limit": min(max(limit, 1), 40)})
    data = await curl_json(
        f"https://www.virustotal.com/api/v3/domains/{quote(domain)}/subdomains?{query}",
        headers={"x-apikey": api_key},
        timeout=20,
    )
    if not isinstance(data, dict):
        return []
    hosts = []
    for item in data.get("data", []) or []:
        host = str(item.get("id", "")).lower().strip(".")
        if _host_matches_domain(host, domain):
            hosts.append(host)
    return sorted(set(hosts))


async def virustotal_ip(ip: str, api_key: str) -> dict:
    """VirusTotal IP enrichment."""
    if not api_key:
        return {}
    data = await curl_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{quote(ip)}",
        headers={"x-apikey": api_key},
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def virustotal_url(url: str, api_key: str) -> dict:
    """VirusTotal URL enrichment."""
    if not api_key:
        return {}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = await curl_json(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": api_key},
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def greynoise_ip(ip: str, api_key: str) -> dict:
    """GreyNoise Community IP context."""
    if not api_key:
        return {}
    data = await curl_json(
        f"https://api.greynoise.io/v3/community/{quote(ip)}",
        headers={"key": api_key, "Accept": "application/json"},
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def abuseipdb_check(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    """AbuseIPDB IP reputation check."""
    if not api_key:
        return {}
    query = urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
    data = await curl_json(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def chaos_subdomains(domain: str, api_key: str) -> list:
    """ProjectDiscovery Chaos subdomains."""
    if not api_key:
        return []
    data = await curl_json(
        f"https://dns.projectdiscovery.io/dns/{quote(domain)}/subdomains",
        headers={"Authorization": api_key},
        timeout=20,
    )
    if not isinstance(data, dict):
        return []
    hosts = {
        f"{str(item).strip().lower()}.{domain}".strip(".")
        for item in data.get("subdomains", []) or []
        if str(item).strip()
    }
    return sorted(host for host in hosts if _host_matches_domain(host, domain))


async def hunter_domain(domain: str, api_key: str, limit: int = 50) -> dict:
    """Hunter.io domain search."""
    if not api_key:
        return {}
    query = urlencode({"domain": domain, "api_key": api_key, "limit": limit})
    data = await curl_json(
        f"https://api.hunter.io/v2/domain-search?{query}",
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def ssllabs_scan(host: str, publish: bool = False, from_cache: bool = True) -> dict:
    """Qualys SSL Labs analysis status/result."""
    query = urlencode({
        "host": host,
        "publish": "on" if publish else "off",
        "fromCache": "on" if from_cache else "off",
        "all": "done",
    })
    data = await curl_json(
        f"https://api.ssllabs.com/api/v3/analyze?{query}",
        timeout=30,
    )
    return data if isinstance(data, dict) else {}


async def securitytrails_subdomains(domain: str, api_key: str) -> list:
    """SecurityTrails subdomain source."""
    if not api_key:
        return []
    data = await curl_json(
        f"https://api.securitytrails.com/v1/domain/{quote(domain)}/subdomains",
        headers={"APIKEY": api_key, "Accept": "application/json"},
        timeout=20,
    )
    if not isinstance(data, dict):
        return []
    hosts = {
        f"{str(item).strip().lower()}.{domain}".strip(".")
        for item in data.get("subdomains", []) or []
        if str(item).strip()
    }
    return sorted(host for host in hosts if _host_matches_domain(host, domain))


async def securitytrails_history_dns(domain: str, api_key: str, record_type: str = "A") -> dict:
    """SecurityTrails historical DNS records."""
    if not api_key:
        return {}
    data = await curl_json(
        f"https://api.securitytrails.com/v1/history/{quote(domain)}/dns/{quote(record_type)}",
        headers={"APIKEY": api_key, "Accept": "application/json"},
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def vulners_search(query_text: str, api_key: str = "", limit: int = 20) -> dict:
    """Vulners search API."""
    payload = {"query": query_text, "size": limit}
    if api_key:
        payload["apiKey"] = api_key
    data = await curl_json(
        "https://vulners.com/api/v3/search/lucene/",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=20,
    )
    return data if isinstance(data, dict) else {}


async def nmap_scan(target: str, ports: str = "--top-ports 1000",
                    version_detect: bool = False,
                    scripts: str = "") -> dict:
    """Run nmap scan. HIGH detectability."""
    flags = "-sV" if version_detect else ""
    script_flag = f"--script={scripts}" if scripts else ""
    result = await bash(
        f"nmap {flags} {script_flag} {ports} {target} 2>/dev/null",
        timeout=600
    )
    return parse_nmap_output(result["stdout"])


def parse_nmap_output(text: str) -> dict:
    """Parse nmap output into structured data."""
    result = {
        "hosts": [],
        "raw": text[:10000],
    }
    current_host = {}
    for line in text.split("\n"):
        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            if current_host.get("hostname") or current_host.get("ports"):
                result["hosts"].append(current_host)
            current_host = {"hostname": host_match.group(1), "ports": []}
        port_match = re.match(r"(\d+)/tcp\s+(\w+)\s+(\S+)\s*(.*)", line)
        if port_match and current_host:
            current_host["ports"].append({
                "port": int(port_match.group(1)),
                "state": port_match.group(2),
                "service": port_match.group(3),
                "version": port_match.group(4).strip(),
            })
    if current_host.get("hostname") or current_host.get("ports"):
        result["hosts"].append(current_host)
    return result


async def cert_info(host: str, port: int = 443) -> dict:
    """Get TLS certificate info via openssl."""
    result = await bash(
        f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null "
        f"| openssl x509 -noout -subject -dates -issuer -serial -fingerprint -ext subjectAltName 2>/dev/null"
    )
    info = {}
    for line in result["stdout"].split("\n"):
        if "=" in line:
            key, _, val = line.partition("=")
            info[key.strip().lower()] = val.strip()
    # Also get SANs
    san_result = await bash(
        f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null "
        f"| openssl x509 -noout -ext subjectAltName 2>/dev/null"
    )
    sans = re.findall(r"DNS:([\w.*-]+)", san_result["stdout"])
    info["san"] = sans
    return info


async def tls_protocols(host: str, port: int = 443) -> dict:
    """Check supported TLS protocols and detect weak ones."""
    protocols = {}
    for proto in ["ssl2", "ssl3", "tls1", "tls1_1", "tls1_2", "tls1_3"]:
        result = await bash(
            f"echo | timeout 5 openssl s_client -{proto} -connect {host}:{port} "
            f"-servername {host} 2>&1 | head -3"
        )
        out = result["stdout"].lower()
        if "handshake failure" in out or "unknown option" in out or "no protocols" in out:
            protocols[proto] = False
        elif "connected" in out or "verify return" in out:
            protocols[proto] = True
        else:
            protocols[proto] = None
    return protocols


async def wayback_cdx(domain: str, limit: int = 5000,
                       output_fields: str = "timestamp,original,statuscode,mimetype") -> list:
    """Query Wayback Machine CDX API for historical URLs."""
    result = await bash(
        f"curl -s 'https://web.archive.org/cdx/search/cdx?url={domain}/*"
        f"&output=json&limit={limit}&fl={output_fields}&collapse=urlkey' "
        f"--max-time 45"
    )
    try:
        data = json.loads(result["stdout"])
        if isinstance(data, list) and len(data) > 1:
            fields = output_fields.split(",")
            return [dict(zip(fields, row)) for row in data[1:]]
    except (json.JSONDecodeError, IndexError, TypeError):
        pass
    return []


async def ssl_scan(host: str, port: int = 443) -> dict:
    """TLS configuration check using openssl and testssl.sh if available."""
    import shutil
    cert = await cert_info(host, port)
    protocols = await tls_protocols(host, port)

    result = {"host": host, "port": port, "certificate": cert, "protocols": protocols}

    if shutil.which("testssl.sh"):
        ts = await bash(
            f"testssl.sh --quiet --color 0 --jsonfile /dev/stdout {host}:{port} 2>/dev/null",
            timeout=120
        )
        try:
            result["testssl"] = json.loads(ts["stdout"])
        except json.JSONDecodeError:
            result["testssl_raw"] = ts["stdout"][:5000]

    return result


async def check_host(host: str, port: int = 443) -> dict:
    """Check if host is alive on given port."""
    result = await curl(
        f"https://{host}:{port}" if port == 443 else f"http://{host}:{port}"
    )
    return {
        "host": host,
        "port": port,
        "alive": result.get("status", 0) not in (0,),
        "status": result.get("status", 0),
    }


async def httpx_probe(targets: list, timeout: int = 10) -> list:
    """Probe targets with httpx for HTTP service fingerprinting."""
    import shutil
    if not shutil.which("httpx"):
        return []
    targets_str = "\n".join(targets)
    result = await bash(
        f"echo '{targets_str}' | httpx -silent -status-code -title -tech-detect "
        f"-json -timeout {timeout} 2>/dev/null",
        timeout=120
    )
    probed = []
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            probed.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return probed


async def gau_urls(domain: str, timeout: int = 60) -> list:
    """Get All URLs via gau (GetAllUrls) — scrapes Wayback, OTX, CommonCrawl."""
    import shutil
    if not shutil.which("gau"):
        return []
    result = await bash(
        f"gau --subs {domain} --threads 5 --timeout 30 2>/dev/null",
        timeout=timeout
    )
    return [u.strip() for u in result["stdout"].split("\n") if u.strip()]


async def subfinder_scan(domain: str, timeout: int = 60) -> list:
    """Run subfinder passive subdomain enumeration."""
    import shutil
    if not shutil.which("subfinder"):
        return []
    result = await bash(
        f"subfinder -d {domain} -silent -all 2>/dev/null",
        timeout=timeout
    )
    return [s.strip() for s in result["stdout"].split("\n")
            if s.strip() and "." in s]


async def amass_passive(domain: str, timeout: int = 120) -> list:
    """Run amass passive subdomain enumeration."""
    import shutil
    if not shutil.which("amass"):
        return []
    result = await bash(
        f"amass enum -passive -d {domain} -nocolor 2>/dev/null",
        timeout=timeout
    )
    return [s.strip() for s in result["stdout"].split("\n")
            if s.strip() and domain in s]


async def dnsx_resolve(hostnames: list, timeout: int = 60) -> dict:
    """Bulk DNS resolution via dnsx — faster than dig for large lists."""
    import shutil
    if not shutil.which("dnsx"):
        return {}
    input_str = "\n".join(hostnames)
    result = await bash(
        f"echo '{input_str}' | dnsx -silent -a -resp -json 2>/dev/null",
        timeout=timeout
    )
    resolved = {}
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "")
            ips = data.get("a", [])
            if host and ips:
                resolved[host] = ips
        except json.JSONDecodeError:
            pass
    return resolved


async def trufflehog_scan(target: str, timeout: int = 120) -> list:
    """Run trufflehog for secret scanning against a URL or filesystem path."""
    import shutil
    if not shutil.which("trufflehog"):
        return []
    result = await bash(
        f"trufflehog git --repo={target} --json --no-update 2>/dev/null || "
        f"trufflehog filesystem {target} --json 2>/dev/null",
        timeout=timeout
    )
    findings = []
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return findings


async def shodan_host(ip: str, api_key: str) -> dict:
    """Query Shodan host info API."""
    if not api_key:
        return {}
    result = await bash(
        f"curl -s 'https://api.shodan.io/shodan/host/{ip}?key={api_key}' "
        f"--max-time 10 2>/dev/null || true"
    )
    try:
        return json.loads(result["stdout"])
    except (json.JSONDecodeError, TypeError):
        return {}


async def asn_lookup(ip: str) -> dict:
    """Look up ASN info for an IP using multiple sources."""
    # Primary: ipinfo.io (no key needed for basic)
    result = await bash(
        f"curl -s 'https://ipinfo.io/{ip}/json' --max-time 10 2>/dev/null || true"
    )
    try:
        data = json.loads(result["stdout"])
        return {
            "ip": ip,
            "asn": data.get("org", "").split(" ")[0],
            "org": " ".join(data.get("org", "").split(" ")[1:]),
            "country": data.get("country", ""),
            "city": data.get("city", ""),
            "hostname": data.get("hostname", ""),
            "raw": data,
        }
    except (json.JSONDecodeError, TypeError):
        pass
    # Fallback: whois radb
    result2 = await bash(f"whois -h whois.radb.net {ip} 2>/dev/null | grep -i origin")
    asn = ""
    for line in result2["stdout"].split("\n"):
        if "origin" in line.lower():
            asn = line.split(":")[-1].strip()
            break
    return {"ip": ip, "asn": asn}
