"""Stage 4: Screenshot-based visual reconnaissance."""

from modules.base import BaseModule
from tools.external import gowitness_scan, tool_available


class VisualRecon(BaseModule):
    id = "visual_recon"
    name = "Visual Recon"
    stage = 4
    detectability = "medium"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        if not tool_available("gowitness"):
            self.state.skip_module(self.id, "gowitness not installed")
            return "skipped"

        targets = self._targets()
        if not targets:
            targets = [f"https://{self.domain}"]

        in_scope = [target for target in targets if self.scope.check(target).allowed]
        if not in_scope:
            self.state.block_module(self.id, "no in-scope visual targets")
            return "blocked"

        output_dir = self.state.state_dir / "screenshots"
        result = await gowitness_scan(in_scope[:50], str(output_dir), timeout=300)
        if not result.get("available", True):
            self.state.skip_module(self.id, "gowitness not installed")
            return "skipped"

        evidence_id = self.state.add_evidence(
            self.id,
            "screenshots",
            self.domain,
            {
                "targets": in_scope[:50],
                "output_dir": str(output_dir.relative_to(self.state.output_dir)),
                "screenshots": result.get("screenshots", []),
                "exit_code": result.get("exit_code"),
                "stderr": result.get("stderr", ""),
            },
        )

        for target in in_scope[:50]:
            self.state.add_asset(
                "screenshot_target",
                f"screenshot:{target}",
                target,
                confidence="FIRM",
                sources=[self.id],
                attrs={"output_dir": str(output_dir), "evidence_ref": evidence_id},
            )

        self.state.complete_module(self.id)
        self.log(f"Screenshot targets: {len(in_scope[:50])}")
        return "done"

    def _targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")) and value not in targets:
                    targets.append(value)
        return targets
