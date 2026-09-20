"""Payload library — ready-to-use attack payloads organized by category.

Every payload set exports:
  - name: short label
  - payloads: list of payload strings
  - description: when to use this set
  - risk: SAFE | LOW | MEDIUM | HIGH (based on detectability)
"""

from . import sqli, xss, ssti, lfi, cmd_injection, ssrf, xxe, jwt, api

ALL_CATEGORIES = {
    "sqli": sqli,
    "xss": xss,
    "ssti": ssti,
    "lfi": lfi,
    "cmd_injection": cmd_injection,
    "ssrf": ssrf,
    "xxe": xxe,
    "jwt": jwt,
    "api": api,
}


def get_payloads(category: str) -> list[str]:
    """Get payloads for a specific attack category."""
    module = ALL_CATEGORIES.get(category)
    if module:
        return getattr(module, "PAYLOADS", [])
    return []


def get_all_categories() -> dict:
    """Return all payload categories with metadata."""
    result = {}
    for name, mod in ALL_CATEGORIES.items():
        result[name] = {
            "name": getattr(mod, "NAME", name),
            "count": len(getattr(mod, "PAYLOADS", [])),
            "description": getattr(mod, "DESCRIPTION", ""),
            "risk": getattr(mod, "RISK", "MEDIUM"),
        }
    return result
