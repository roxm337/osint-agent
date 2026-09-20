"""Stage 3: Port Scan — naabu/nmap with service detection and risk scoring."""

import re
from modules.base import BaseModule
from tools.wrappers import bash
from tools.external import naabu_scan, tool_available


HIGH_RISK_PORT_FINDINGS = {
    21:    ("FTP Server Exposed", "HIGH",
            "FTP transmits credentials in cleartext. Brute-force and sniffing risk."),
    22:    ("SSH Server Exposed", "MEDIUM",
            "SSH exposed. Verify key-only auth is enforced."),
    23:    ("Telnet Exposed", "CRITICAL",
            "Telnet transmits all data including credentials in cleartext."),
    25:    ("SMTP Port Exposed", "MEDIUM",
            "SMTP open. Test for open relay and user enumeration (VRFY/EXPN)."),
    445:   ("SMB Port Exposed", "HIGH",
            "SMB exposed. Risk of EternalBlue/MS17-010 if unpatched."),
    1433:  ("MSSQL Exposed", "HIGH",
            "Microsoft SQL Server port exposed. Restrict to internal networks."),
    1521:  ("Oracle DB Exposed", "HIGH",
            "Oracle database port exposed. Restrict to internal networks."),
    2049:  ("NFS Exposed", "HIGH",
            "NFS mount service exposed. May allow unauthenticated filesystem access."),
    2375:  ("Docker API Exposed (Unencrypted)", "CRITICAL",
            "Docker daemon API exposed without TLS. Full container takeover possible."),
    2376:  ("Docker TLS API Exposed", "HIGH",
            "Docker TLS API exposed. Validate client certificate requirements."),
    2379:  ("etcd Exposed", "CRITICAL",
            "etcd cluster port exposed. May allow read/write to all Kubernetes secrets."),
    3306:  ("MySQL Exposed", "HIGH",
            "MySQL database port exposed. Restrict to internal networks."),
    3389:  ("RDP Exposed", "HIGH",
            "RDP exposed. High risk for brute-force and BlueKeep (CVE-2019-0708)."),
    4848:  ("GlassFish Admin Console Exposed", "HIGH",
            "GlassFish Admin Console may have default credentials."),
    5432:  ("PostgreSQL Exposed", "HIGH",
            "PostgreSQL database port exposed. Restrict to internal networks."),
    5601:  ("Kibana Exposed", "HIGH",
            "Kibana dashboard exposed. May allow read access to all Elasticsearch indices."),
    5900:  ("VNC Exposed", "HIGH",
            "VNC remote desktop exposed. Often has weak authentication."),
    5984:  ("CouchDB Exposed", "HIGH",
            "CouchDB exposed. Check for unauthenticated access to /_all_dbs."),
    6379:  ("Redis Exposed (No Auth)", "CRITICAL",
            "Redis exposed without authentication. Full data access and potential RCE."),
    6443:  ("Kubernetes API Server Exposed", "CRITICAL",
            "Kubernetes API server exposed. May allow cluster access."),
    7001:  ("WebLogic Exposed", "HIGH",
            "WebLogic server exposed. Multiple critical deserialization CVEs (CVE-2019-2725, etc.)"),
    8009:  ("AJP Port Exposed (Ghostcat)", "CRITICAL",
            "Apache AJP port exposed. Vulnerable to CVE-2020-1938 (Ghostcat) file read."),
    8080:  ("HTTP Alternative Port Open", "MEDIUM",
            "HTTP service on 8080. Often runs dev/test apps without proper hardening."),
    8443:  ("HTTPS Alternative Port Open", "MEDIUM",
            "HTTPS service on 8443. Verify TLS configuration and exposed application."),
    8888:  ("Jupyter Notebook Exposed", "CRITICAL",
            "Jupyter Notebook typically allows unauthenticated code execution."),
    9000:  ("PHP-FPM / MinIO Exposed", "HIGH",
            "Port 9000 may expose PHP-FPM (CVE-2019-11043) or MinIO storage."),
    9090:  ("Prometheus / Cockpit Exposed", "HIGH",
            "Prometheus metrics may expose internal infrastructure data. Cockpit allows remote management."),
    9200:  ("Elasticsearch Exposed", "CRITICAL",
            "Elasticsearch HTTP API exposed. Often unauthenticated with full data access."),
    9300:  ("Elasticsearch Transport Exposed", "HIGH",
            "Elasticsearch internal transport port exposed."),
    10250: ("Kubelet API Exposed", "CRITICAL",
            "Kubernetes Kubelet API exposed. May allow unauthenticated pod listing and exec."),
    11211: ("Memcached Exposed", "HIGH",
            "Memcached exposed. No authentication, full cache access and DDoS amplification."),
    15672: ("RabbitMQ Management UI Exposed", "HIGH",
            "RabbitMQ management interface. Default credentials often set (guest/guest)."),
    27017: ("MongoDB Exposed", "CRITICAL",
            "MongoDB exposed. Often unauthenticated in older versions — full data access."),
    27018: ("MongoDB Shard Port Exposed", "HIGH",
            "MongoDB shard port exposed. Restrict to internal networks."),
    50000: ("Jenkins Agent Port Exposed", "HIGH",
            "Jenkins JNLP agent port. May allow remote code execution via agent."),
    50070: ("Hadoop NameNode Exposed", "HIGH",
            "Hadoop NameNode HTTP UI exposed. May disclose cluster topology and data paths."),
}


class PortScan(BaseModule):
    id = "port_scan"
    name = "Port Scan"
    stage = 3
    detectability = "high"
    depends_on = ["subdomain_enum"]
    requires_auth = True

    async def run(self) -> str:
        ips = self.state.get_assets_by_type("ip")
        targets = [ip["value"] for ip in ips
                   if ip.get("confidence") in ("FIRM", "CONFIRMED")]

        if not targets:
            self.log("No IPs to scan.")
            self.state.skip_module(self.id, "no IPs")
            return "skipped"

        # Deduplicate and limit to reasonable count
        targets = list(dict.fromkeys(targets))[:30]
        self.log(f"Scanning {len(targets)} IPs...")

        for target_ip in targets:
            self.log(f"  Scanning {target_ip}...")
            ports_found = await self._scan_ip(target_ip)

            for port_info in ports_found:
                port = port_info["port"]
                service = port_info.get("service", "unknown")
                version = port_info.get("version", "")
                state = port_info.get("state", "open")

                if state not in ("open", ""):
                    continue

                self.state.add_asset(
                    "port",
                    f"port:{target_ip}:{port}",
                    f"{target_ip}:{port}",
                    confidence="CONFIRMED",
                    sources=["port scan"],
                    attrs={
                        "ip": target_ip,
                        "port": port,
                        "service": service,
                        "version": version,
                    },
                )
                self.state.add_edge(
                    f"ip:{target_ip}",
                    f"port:{target_ip}:{port}",
                    "HAS_PORT",
                )

                if port in HIGH_RISK_PORT_FINDINGS:
                    title, severity, desc = HIGH_RISK_PORT_FINDINGS[port]
                    detail = f" ({service} {version})" if version else f" ({service})"
                    self.state.add_finding(
                        title=f"{title}: {target_ip}:{port}",
                        severity=severity,
                        confidence="CONFIRMED",
                        category="Network Exposure",
                        description=f"{desc}{detail}",
                        evidence=[f"IP: {target_ip}:{port}", f"Service: {service} {version}"],
                        remediation=self._remediation(port),
                        asset_keys=[f"port:{target_ip}:{port}"],
                    )

        self.state.complete_module(self.id)
        return "done"

    async def _scan_ip(self, target_ip: str) -> list:
        """Scan a single IP — naabu first, then nmap with -sV."""
        # Try naabu for fast port discovery
        naabu_results = await naabu_scan(target_ip, ports="top-1000", timeout=180)
        if naabu_results:
            ports_open = [r["port"] for r in naabu_results if r.get("port")]
            if ports_open:
                # Run nmap -sV on discovered ports only for version detection
                port_list = ",".join(str(p) for p in ports_open)
                result = await bash(
                    f"nmap -sV -p {port_list} {target_ip} 2>/dev/null",
                    timeout=180
                )
                parsed = self._parse_nmap(result["stdout"])
                if parsed:
                    return parsed
            return [{"port": r["port"], "service": "unknown", "state": "open"}
                    for r in naabu_results]

        # Fallback to full nmap -sV top-1000
        result = await bash(
            f"nmap -sV --top-ports 1000 {target_ip} 2>/dev/null",
            timeout=300,
        )
        return self._parse_nmap(result["stdout"])

    def _parse_nmap(self, text: str) -> list:
        ports = []
        for line in text.split("\n"):
            m = re.match(r"(\d+)/tcp\s+(\w+)\s+(\S+)\s*(.*)", line.strip())
            if m:
                ports.append({
                    "port": int(m.group(1)),
                    "state": m.group(2),
                    "service": m.group(3),
                    "version": m.group(4).strip(),
                })
        return ports

    def _remediation(self, port: int) -> str:
        generic = "Restrict this port to internal networks or VPN access only."
        remediations = {
            21: "Disable FTP; use SFTP or FTPS instead.",
            22: "Enforce key-based authentication only; disable password auth.",
            23: "Disable Telnet immediately; use SSH.",
            2375: "Never expose Docker API publicly. Enable TLS mutual auth.",
            2379: "Restrict etcd access to localhost and Kubernetes master nodes only.",
            6379: "Enable Redis AUTH and bind to localhost or internal VLAN only.",
            8009: "Disable AJP connector or upgrade to Tomcat 9.0.31+/8.5.51+.",
            8888: "Enable Jupyter password/token authentication; restrict to VPN.",
            9200: "Enable Elasticsearch security (X-Pack) or restrict via firewall.",
            10250: "Restrict Kubelet API to cluster-internal traffic only.",
            27017: "Enable MongoDB authentication and bind to localhost.",
        }
        return remediations.get(port, generic)
