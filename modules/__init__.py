"""Module registry — all modules discoverable here."""

from .seed import SeedDiscovery
from .subdomain import SubdomainEnum
from .asn_expansion import ASNExpansion
from .keyed_subdomains import KeyedSubdomains
from .wayback import WaybackMachine
from .email_harvest import EmailHarvest
from .tech_detect import TechDetection
from .threat_intel import ThreatIntel
from .vt_enrich import VirusTotalEnrich
from .reputation_enrich import ReputationEnrich
from .exploit_lookup import ExploitLookup
from .email_security_module import EmailSecurity
from .tls_audit import TLSAudit
from .port_scan_module import PortScan
from .sitemap import SitemapExploit
from .rest_api import RestAPIAudit
from .waf_module import WAFMapping
from .login_enum import LoginEnum
from .misconfig import MisconfigProbes
from .fast_exposure_scan import FastExposureScan
from .cloud_enum import CloudEnum
from .dns_takeover import DNSTakeover
from .content_discovery import ContentDiscovery
from .nuclei_scan import NucleiScan
from .social import SocialMedia
from .breach import BreachCheck
from .js_analysis import JSAnalysis
from .graphql_module import GraphQLAudit
from .origin_discovery import OriginDiscovery
from .risk_prioritization import RiskPrioritization
from .deep_crawl import DeepCrawl
from .browser_crawl import BrowserCrawl
from .parameter_discovery import ParameterDiscovery
from .visual_recon import VisualRecon
from .mobile_assets import MobileAssets
from .social_osint import SocialOSINT
from .git_exposure import GitExposure
from .secret_validation import SecretValidation
from .xss_scan import XSSScan
from .sqli_scan import SQLiScan
from .cors_audit import CORSAudit
from .open_redirect import OpenRedirectScan
from .http_smuggling import HTTPSmuggling
from .cms_deep_scan import CMSDeepScan
from .bounty_submission import BountySubmission
from .attack_planner import LLMAttackPlanner
from .report import Reporting

STAGE_ORDER = [1, 2, 3, 4, 5, 6]

MODULE_REGISTRY = {
    # Stage 1: Seed
    "seed_discovery": {
        "class": SeedDiscovery,
        "stage": 1,
        "detectability": "low",
        "depends_on": [],
        "requires_auth": False,
    },
    # Stage 2: Asset Expansion
    "subdomain_enum": {
        "class": SubdomainEnum,
        "stage": 2,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "wayback_machine": {
        "class": WaybackMachine,
        "stage": 2,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "email_harvest": {
        "class": EmailHarvest,
        "stage": 2,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "asn_expansion": {
        "class": ASNExpansion,
        "stage": 2,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "keyed_subdomains": {
        "class": KeyedSubdomains,
        "stage": 2,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    # Stage 3: Enrichment
    "tech_detection": {
        "class": TechDetection,
        "stage": 3,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "tls_audit": {
        "class": TLSAudit,
        "stage": 3,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "email_security": {
        "class": EmailSecurity,
        "stage": 3,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "threat_intel": {
        "class": ThreatIntel,
        "stage": 3,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "vt_enrich": {
        "class": VirusTotalEnrich,
        "stage": 3,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "reputation_enrich": {
        "class": ReputationEnrich,
        "stage": 3,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "exploit_lookup": {
        "class": ExploitLookup,
        "stage": 3,
        "detectability": "low",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "port_scan": {
        "class": PortScan,
        "stage": 3,
        "detectability": "high",
        "depends_on": ["subdomain_enum"],
        "requires_auth": True,
    },
    "social_media": {
        "class": SocialMedia,
        "stage": 3,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    # Stage 4: Exposure Analysis
    "sitemap_exploit": {
        "class": SitemapExploit,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "rest_api_audit": {
        "class": RestAPIAudit,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "graphql_audit": {
        "class": GraphQLAudit,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "waf_mapping": {
        "class": WAFMapping,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "login_enum": {
        "class": LoginEnum,
        "stage": 4,
        "detectability": "medium",
        "depends_on": ["tech_detection", "email_harvest"],
        "requires_auth": False,
    },
    "misconfig_probes": {
        "class": MisconfigProbes,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "fast_exposure_scan": {
        "class": FastExposureScan,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "cloud_enum": {
        "class": CloudEnum,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["seed_discovery"],
        "requires_auth": False,
    },
    "dns_takeover": {
        "class": DNSTakeover,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["subdomain_enum"],
        "requires_auth": False,
    },
    "js_analysis": {
        "class": JSAnalysis,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["wayback_machine", "tech_detection"],
        "requires_auth": False,
    },
    "origin_discovery": {
        "class": OriginDiscovery,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["seed_discovery", "tech_detection"],
        "requires_auth": False,
    },
    "deep_crawl": {
        "class": DeepCrawl,
        "stage": 4,
        "detectability": "medium",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "browser_crawl": {
        "class": BrowserCrawl,
        "stage": 4,
        "detectability": "medium",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "parameter_discovery": {
        "class": ParameterDiscovery,
        "stage": 4,
        "detectability": "medium",
        "depends_on": ["wayback_machine"],
        "requires_auth": False,
    },
    "visual_recon": {
        "class": VisualRecon,
        "stage": 4,
        "detectability": "medium",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "mobile_assets": {
        "class": MobileAssets,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "social_osint": {
        "class": SocialOSINT,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["email_harvest"],
        "requires_auth": False,
    },
    "git_exposure": {
        "class": GitExposure,
        "stage": 4,
        "detectability": "medium",
        "depends_on": ["tech_detection"],
        "requires_auth": False,
    },
    "secret_validation": {
        "class": SecretValidation,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["js_analysis"],
        "requires_auth": False,
    },
    "breach_check": {
        "class": BreachCheck,
        "stage": 4,
        "detectability": "low",
        "depends_on": ["email_harvest"],
        "requires_auth": False,
    },
    # Stage 5: Active Vulnerability Testing
    "content_discovery": {
        "class": ContentDiscovery,
        "stage": 5,
        "detectability": "high",
        "depends_on": ["tech_detection"],
        "requires_auth": True,
    },
    "nuclei_scan": {
        "class": NucleiScan,
        "stage": 5,
        "detectability": "high",
        "depends_on": ["tech_detection"],
        "requires_auth": True,
    },
    "xss_scan": {
        "class": XSSScan,
        "stage": 5,
        "detectability": "high",
        "depends_on": ["parameter_discovery"],
        "requires_auth": True,
    },
    "sqli_scan": {
        "class": SQLiScan,
        "stage": 5,
        "detectability": "high",
        "depends_on": ["parameter_discovery"],
        "requires_auth": True,
    },
    "cors_audit": {
        "class": CORSAudit,
        "stage": 5,
        "detectability": "medium",
        "depends_on": ["tech_detection"],
        "requires_auth": True,
    },
    "open_redirect": {
        "class": OpenRedirectScan,
        "stage": 5,
        "detectability": "medium",
        "depends_on": ["parameter_discovery"],
        "requires_auth": True,
    },
    "http_smuggling": {
        "class": HTTPSmuggling,
        "stage": 5,
        "detectability": "high",
        "depends_on": ["tech_detection"],
        "requires_auth": True,
    },
    "cms_deep_scan": {
        "class": CMSDeepScan,
        "stage": 5,
        "detectability": "high",
        "depends_on": ["tech_detection"],
        "requires_auth": True,
    },
    # Stage 6: Prioritization and Reporting
    "risk_prioritization": {
        "class": RiskPrioritization,
        "stage": 6,
        "detectability": "low",
        "depends_on": [],
        "requires_auth": False,
    },
    "bounty_submission": {
        "class": BountySubmission,
        "stage": 6,
        "detectability": "low",
        "depends_on": ["risk_prioritization"],
        "requires_auth": False,
    },
    "attack_planner": {
        "class": LLMAttackPlanner,
        "stage": 6,
        "detectability": "low",
        "depends_on": ["risk_prioritization"],
        "requires_auth": False,
    },
    "reporting": {
        "class": Reporting,
        "stage": 6,
        "detectability": "low",
        "depends_on": ["risk_prioritization", "attack_planner"],
        "requires_auth": False,
    },
}


def get_module(module_id: str):
    """Get module class by ID."""
    entry = MODULE_REGISTRY.get(module_id)
    if entry:
        return entry["class"]
    return None


def get_modules_by_stage(stage: int) -> list:
    """Get all module IDs for a given stage."""
    return [
        mid for mid, m in MODULE_REGISTRY.items()
        if m["stage"] == stage and not m.get("replaced_by")
    ]


def get_all_module_ids() -> list:
    """Get all module IDs in stage order."""
    result = []
    for stage in STAGE_ORDER:
        result.extend(get_modules_by_stage(stage))
    return result
