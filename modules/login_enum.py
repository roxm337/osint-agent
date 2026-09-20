"""Stage 4: Login Enumeration — user enumeration via login pages."""

import asyncio

from modules.base import BaseModule
from tools.wrappers import curl


class LoginEnum(BaseModule):
    id = "login_enum"
    name = "Login Enumeration"
    stage = 4
    detectability = "medium"
    depends_on = ["tech_detection", "email_harvest"]

    async def run(self) -> str:
        if self.is_blocked():
            self.state.block_module(self.id, "WAF active")
            return "blocked"

        base_url = f"https://{self.domain}"
        self.log("Testing login user enumeration...")
        self._auth_probe_blocked = False

        # Get known emails from state
        emails = self.state.get_assets_by_type("email")
        valid_email = None
        for e in emails:
            val = e.get("value", "")
            if "@" in val:
                valid_email = val
                break

        if not valid_email:
            valid_email = f"admin@{self.domain}"

        invalid_email = f"nonexistentuser123@{self.domain}"

        # 1. WordPress wp-login.php
        self.log("  Testing wp-login.php...")
        wp_valid = await self._auth_probe(
            f"{base_url}/wp-login.php",
            method="POST",
            data=f"log={valid_email}&pwd=wrongpassword",
            output="headers",
        )
        wp_invalid = await self._auth_probe(
            f"{base_url}/wp-login.php",
            method="POST",
            data=f"log={invalid_email}&pwd=wrongpassword",
            output="headers",
        )

        # Compare responses
        valid_body = wp_valid.get("body", "")
        invalid_body = wp_invalid.get("body", "")

        if valid_body != invalid_body and len(valid_body) > 0 and len(invalid_body) > 0:
            self.state.add_finding(
                title="WordPress User Enumeration via Email Login",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="Information Disclosure",
                description=f"wp-login.php reveals whether an email corresponds "
                            f"to a valid user by returning different responses.",
                evidence=[f"Valid email ({valid_email}): different response",
                          f"Invalid email ({invalid_email}): different response"],
                remediation="Upgrade WP, disable email login, use WPS Hide Login.",
                asset_keys=[f"webapp:{base_url}/wp-login.php"],
            )

        # 2. WP author ID enumeration
        self.log("  Testing author ID enumeration...")
        valid_ids = []
        for uid in range(1, 11):
            if self._auth_probe_blocked:
                break
            result = await self._auth_probe(
                f"{base_url}/?author={uid}",
                output="headers",
            )
            status = result.get("status", 0)
            # 200 = valid author, 301/302 = redirect (valid), 404 = invalid
            if status in (200, 301, 302):
                valid_ids.append(uid)

        if len(valid_ids) > 1:
            self.state.add_finding(
                title="WordPress Author ID Enumeration",
                severity="LOW",
                confidence="CONFIRMED",
                category="Information Disclosure",
                description=f"{len(valid_ids)} WP user IDs are enumerable via "
                            f"?author=N parameter.",
                evidence=[f"Valid user IDs: {valid_ids}"],
                remediation="Consider using a plugin to block author enumeration.",
                asset_keys=[f"webapp:{base_url}"],
            )

        # 3. XML-RPC check
        xmlrpc = await self._auth_probe(
            f"{base_url}/xmlrpc.php",
            method="POST",
            data='<?xml version="1.0"?><methodCall>'
                 '<methodName>system.listMethods</methodName></methodCall>',
            output="status",
        )
        status = xmlrpc.get("status", 0)
        if status == 200:
            self.state.add_finding(
                title="XML-RPC Accessible",
                severity="LOW",
                confidence="CONFIRMED",
                category="Attack Surface",
                description="XML-RPC endpoint is accessible. May allow brute-force "
                            "and pingback attacks.",
                evidence=["POST to xmlrpc.php returns 200"],
                remediation="Disable XML-RPC if not needed.",
                asset_keys=[f"webapp:{base_url}/xmlrpc.php"],
            )

        # Store valid WP user IDs
        if valid_ids:
            self.state.add_asset(
                "wp_users",
                f"wp_users:{self.domain}",
                self.domain,
                confidence="CONFIRMED",
                sources=["login enumeration"],
                attrs={"valid_user_ids": valid_ids},
            )

        self.state.complete_module(self.id)
        return "done"

    async def _auth_probe(self, url: str, **kwargs) -> dict:
        if self._auth_probe_blocked:
            return {"status": 0, "body": "", "error": "auth probe rate-limited"}

        result = await curl(url, **kwargs)
        status = result.get("status", 0)
        body = str(result.get("body", "")).lower()
        lockout_signals = (
            "too many attempts",
            "account locked",
            "temporarily locked",
            "try again later",
            "rate limit",
            "captcha",
        )
        if status == 429 or any(signal in body for signal in lockout_signals):
            self._auth_probe_blocked = True
            self.state.record_waf_block(url, status or 429)
            backoff = float(
                self.config.get("auth", {}).get(
                    "probe_backoff_seconds",
                    self.waf_config.get("backoff_seconds", 10),
                )
            )
            self.log(f"  Rate-limit/lockout signal detected; backing off for {backoff:g}s")
            if backoff > 0:
                await asyncio.sleep(backoff)
        return result
