"""Verification Agent — drives the deterministic oracle to confirm PoCs."""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs

from agents.base_agent import BaseAgent
from agents.blackboard import AgentRole, Hypothesis
from core.verification_oracle import (
    VerificationOracle, DifferentialAnalyzer, TimingOracle,
    ReproducibilityChecker, InteractshClient,
    Confidence, Verdict,
    _inject_param,
)


class VerificationAgent(BaseAgent):
    role = AgentRole.VERIFICATION

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.oracle = VerificationOracle()

    def _extract_target_url(self, hypothesis: Hypothesis) -> tuple[str, str]:
        """Extract (url_with_params, param_name) from hypothesis or config."""
        params = hypothesis.params or {}
        url = params.get("url", "") or hypothesis.target or ""
        param = params.get("param", "")

        # If no param in hypothesis params, parse from target URL
        if not param and url and "?" in url:
            parsed = urlparse(url)
            qs_params = parse_qs(parsed.query)
            if qs_params:
                param = list(qs_params.keys())[0]
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                # Rebuild URL with a param placeholder for the oracle
                url = _inject_param(url, param, "test")

        # Fallback: use raw_url from config
        if not url:
            url = self.config.get("target", {}).get("raw_url", "")
            if url and "?" in url:
                parsed = urlparse(url)
                qs_params = parse_qs(parsed.query)
                if qs_params:
                    param = list(qs_params.keys())[0]
                    url = _inject_param(url, param, "test")

        return url, param

    async def verify_finding(self, hypothesis: Hypothesis) -> dict:
        """Verify a hypothesis using the composite oracle."""
        self.log(f"Verifying: {hypothesis.title}")

        technique = hypothesis.technique.lower()
        url, param = self._extract_target_url(hypothesis)

        if "sqli" in technique:
            return await self._verify_sqli(url, param, hypothesis)
        elif "xss" in technique:
            return await self._verify_xss(url, param, hypothesis)
        elif "ssrf" in technique:
            return await self._verify_ssrf(url, param, hypothesis)
        else:
            # Generic differential verification
            return await self._verify_generic(url, hypothesis)

    async def _verify_sqli(self, url: str, param: str,
                           hypothesis: Hypothesis) -> dict:
        # Try differential first
        payload = "' OR '1'='1"
        test_url = _inject_param(url, param, payload)
        base_url = _inject_param(url, param, "1")

        base = await self.oracle.differential.baseline(base_url)
        test = await self.oracle.differential.test(test_url)
        verdict = self.oracle.differential.compare(base, test)

        if verdict.confidence.value in ("FIRM", "CONFIRMED"):
            # Reproducibility check
            repro = await self.oracle.reproducibility.check(
                lambda: self.oracle.differential.test(test_url)
            )
            final_conf = "CONFIRMED" if repro.confidence.value == "CONFIRMED" else "FIRM"

            self.bb.send(self.role, AgentRole.SUPERVISOR,
                         "verification_result", payload={
                "hypothesis_id": hypothesis.id,
                "status": final_conf,
                "evidence": {**verdict.evidence, **repro.evidence},
            })

            hypothesis.status = "confirmed" if final_conf == "CONFIRMED" else "testing"
            return {"status": final_conf, "verdict": verdict, "repro": repro, "success": final_conf == "CONFIRMED"}

        hypothesis.status = "rejected"
        return {"status": "rejected", "verdict": verdict, "success": False}

    async def _verify_xss(self, url: str, param: str,
                          hypothesis: Hypothesis) -> dict:
        payload = "<script>alert(1)</script>"
        verdict = await self.oracle.verify_xss(url, param, payload)

        if verdict.confidence.value == "CONFIRMED":
            hypothesis.status = "confirmed"
        else:
            hypothesis.status = "rejected"

        return {"status": verdict.confidence.value, "verdict": verdict,
                "success": verdict.confidence.value == "CONFIRMED"}

    async def _verify_ssrf(self, url: str, param: str,
                           hypothesis: Hypothesis) -> dict:
        interactsh = InteractshClient()
        corr_id = await interactsh.register_callback(f"verify-{hypothesis.id}")
        oob_url = f"http://{corr_id}.burpcollaborator.net/verify"

        test_url = _inject_param(url, param, oob_url)
        await __import__("tools.wrappers", fromlist=["curl"]).curl(test_url)

        verdict = await interactsh.verify(f"verify-{hypothesis.id}", poll=True)

        if verdict.confidence.value == "CONFIRMED":
            hypothesis.status = "confirmed"
        else:
            hypothesis.status = "rejected"

        return {"status": verdict.confidence.value, "verdict": verdict,
                "success": verdict.confidence.value == "CONFIRMED"}

    async def _verify_generic(self, url: str,
                              hypothesis: Hypothesis) -> dict:
        """Composite verification for general findings."""
        base = await self.oracle.differential.baseline(url)
        test = await self.oracle.differential.test(url)
        diff_v = self.oracle.differential.compare(base, test)

        repro_v = await self.oracle.reproducibility.check(
            lambda: self.oracle.differential.test(url)
        )

        if repro_v.confidence == Confidence.CONFIRMED:
            hypothesis.status = "confirmed"
            return {"status": "CONFIRMED", "differential": diff_v, "repro": repro_v, "success": True}
        elif diff_v.confidence in (Confidence.FIRM, Confidence.CONFIRMED):
            hypothesis.status = "testing"
            return {"status": "FIRM", "differential": diff_v, "success": True}
        else:
            hypothesis.status = "rejected"
            return {"status": "REJECTED", "differential": diff_v, "success": False}
