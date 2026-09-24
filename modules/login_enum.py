"""Stage 4: Login Enumeration — WordPress-only, verified signals."""

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
        # Gate: only run against confirmed WordPress targets.
        webapps = self.state.get_assets_by_type("webapp")
        is_wordpress = any(
            "wordpress" in str(a.get("attrs", {}).get("cms", "")).lower()
            or "wp-content" in str(a.get("value", "")).lower()
            for a in webapps
        )
        if not is_wordpress:
            self.state.skip_module(self.id, "target is not WordPress")
            return "skipped"

        if self.is_blocked():
            self.state.block_module(self.id, "WAF active")
            return "blocked"

        base_url = f"https://{self.domain}"
        self.log("Testing login user enumeration...")
        self._auth_probe_blocked = False

        emails = self.state.get_assets_by_type("email")
        valid_email = next(
            (e.get("value", "") for e in emails if "@" in e.get("value", "")),
            None,
        )
        if not valid_email:
            valid_email = f"admin@{self.domain}"
        invalid_email = f"nonexistentuser123@{self.domain}"

        # 1. wp-login differential — require error-message difference
        self.log("  Testing wp-login.php for email enumeration...")
        wp_valid = await self._auth_probe(
            f"{base_url}/wp-login.php", method="POST",
            data=f"log={valid_email}&pwd=wrongpassword", output="body",
        )
        wp_invalid = await self._auth_probe(
            f"{base_url}/wp-login.php", method="POST",
            data=f"log={invalid_email}&pwd=wrongpassword", output="body",
        )
        valid_body = wp_valid.get("body", "") or ""
        invalid_body = wp_invalid.get("body", "") or ""

        # Real enumeration shows distinct error markers, not template noise.
        markers = {
            "unknown_user": "unknown email",
            "wrong_password": "incorrect",
            "invalid_username": "invalid username",
        }
        valid_has = [k for k, m in markers.items() if m in valid_body.lower()]
        invalid_has = [k for k, m in markers.items() if m in invalid_body.lower()]
        distinguishing = bool(valid_has) and bool(invalid_has) and set(valid_has) != set(invalid_has)

        if distinguishing:
            self.state.add_finding(
                title="WordPress Email Enumeration via wp-login.php",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="Information Disclosure",
                description=(
                    "wp-login.php returns different error markers for valid vs "
                    "invalid emails. An attacker can confirm registered users."
                ),
                evidence=[
                    f"Valid email marker: {valid_has}",
                    f"Invalid email marker: {invalid_has}",
                ],
                remediation="Uniform error messages; disable email login; use WPS Hide Login.",
                asset_keys=[f"webapp:{base_url}/wp-login.php"],
                verified=True,
                verification={"method": "differential_error_marker",
                              "valid_markers": valid_has,
                              "invalid_markers": invalid_has},
            )

        # 2. Author ID enumeration — require slug or username, not bare 200
        self.log("  Testing author ID enumeration...")
        confirmed_ids = []
        for uid in range(1, 11):
            if self._auth_probe_blocked:
                break
            result = await self._auth_probe(
                f"{base_url}/?author={uid}", output="full",
            )
            status = result.get("status", 0)
            headers = result.get("headers", "") or ""
            body = result.get("body", "") or ""

            # Real enumeration: either a redirect to /author/<slug>/ or the
            # author slug/display name present in the body.
            slug = None
            if status in (301, 302):
                for line in headers.splitlines():
                    if line.lower().startswith("location:") and "/author/" in line:
                        slug = line.split("/author/", 1)[1].strip().split("/")[0]
                        break
            if not slug and status == 200:
                import re
                m = re.search(r'/author/([a-zA-Z0-9_-]{2,})/', body)
                if m:
                    slug = m.group(1)

            if slug:
                confirmed_ids.append({"id": uid, "slug": slug})

        if len(confirmed_ids) >= 2:
            slugs = [c["slug"] for c in confirmed_ids]
            self.state.add_finding(
                title=f"WordPress Author Enumeration: {len(confirmed_ids)} usernames",
                severity="LOW",
                confidence="CONFIRMED",
                category="Information Disclosure",
                description=(
                    f"{len(confirmed_ids)} WordPress usernames enumerated via "
                    f"/?author=N. Usernames feed credential attacks."
                ),
                evidence=[
                    f"User ID {c['id']} → slug '{c['slug']}'"
                    for c in confirmed_ids
                ],
                remediation="Block /?author= routing or use usernames that aren't email-local-parts.",
                asset_keys=[f"webapp:{base_url}"],
                verified=True,
                verification={"method": "slug_extraction", "slugs": slugs},
            )
            self.state.add_asset(
                "wp_users", f"wp_users:{self.domain}", self.domain,
                confidence="CONFIRMED", sources=["login enumeration"],
                attrs={"users": confirmed_ids},
            )

        # 3. XML-RPC — only flag if callable and returns method list
        xmlrpc = await self._auth_probe(
            f"{base_url}/xmlrpc.php", method="POST",
            data='<?xml version="1.0"?><methodCall>'
                 '<methodName>system.listMethods</methodName></methodCall>',
            output="body",
        )
        xmlrpc_body = xmlrpc.get("body", "") or ""
        if "methodResponse" in xmlrpc_body and "wp.getUsersBlogs" in xmlrpc_body:
            self.state.add_finding(
                title="WordPress XML-RPC Enabled",
                severity="LOW",
                confidence="CONFIRMED",
                category="Attack Surface",
                description="XML-RPC is enabled and returns the full method list, "
                            "including wp.getUsersBlogs (brute-force vector).",
                evidence=["system.listMethods returned method list"],
                remediation="Disable XML-RPC if not needed.",
                asset_keys=[f"webapp:{base_url}/xmlrpc.php"],
                verified=True,
                verification={"method": "xmlrpc_method_list"},
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
            "too many attempts", "account locked", "temporarily locked",
            "try again later", "rate limit", "captcha",
        )
        if status == 429 or any(s in body for s in lockout_signals):
            self._auth_probe_blocked = True
            self.state.record_waf_block(url, status or 429)
            backoff = float(
                self.config.get("auth", {}).get(
                    "probe_backoff_seconds",
                    self.waf_config.get("backoff_seconds", 10),
                )
            )
            self.log(f"  Lockout signal; backing off {backoff:g}s")
            if backoff > 0:
                await asyncio.sleep(backoff)
        return result