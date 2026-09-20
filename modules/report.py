"""Stage 6: Reporting — writes structured report artifacts."""

from core.reporting import write_report_bundle
from modules.base import BaseModule


class Reporting(BaseModule):
    id = "reporting"
    name = "Reporting"
    stage = 6
    detectability = "low"
    depends_on = []  # Runs after all others

    async def run(self) -> str:
        self.log("Generating report...")

        target = self.domain
        paths = write_report_bundle(self.state, target)

        self.log(f"Report written to {paths['report']}")
        self.state.complete_module(self.id)
        return "done"
