"""Budget Manager — enforces engagement-level resource caps.

Caps:
  - max_requests: total HTTP requests across all actions
  - max_wall_clock_seconds: total runtime before forced stop
  - max_llm_calls: total LLM inference calls
  - max_concurrent_actions: actions running at the same time
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class BudgetState:
    requests_used: int = 0
    llm_calls_used: int = 0
    actions_used: int = 0
    wall_start: float = 0.0
    wall_end: float = 0.0
    errored: bool = False
    exceeded: list[str] = field(default_factory=list)


class BudgetExceededError(Exception):
    pass


class BudgetManager:
    """Per-engagement budget enforcement."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        limits = cfg.get("budget_limits", {})

        self.max_requests = limits.get("max_requests", 0) or 10000
        self.max_wall_clock = limits.get("max_wall_clock_seconds", 0) or 3600
        self.max_llm_calls = limits.get("max_llm_calls", 0) or 200
        self.max_concurrent_actions = limits.get("max_concurrent_actions", 0) or 5

        self.state = BudgetState(wall_start=time.time())
        self._lock = Lock()
        self._semaphore = None

    @property
    def semaphore(self):
        if self._semaphore is None:
            from asyncio import Semaphore
            self._semaphore = Semaphore(self.max_concurrent_actions)
        return self._semaphore

    def check(self) -> bool:
        """Returns True if budget allows continuing. Raises if exceeded."""
        now = time.time()
        exceeded = []

        if self.state.requests_used >= self.max_requests:
            exceeded.append(f"requests ({self.state.requests_used}/{self.max_requests})")
        if now - self.state.wall_start >= self.max_wall_clock:
            exceeded.append(f"wall clock ({now - self.state.wall_start:.0f}s/{self.max_wall_clock}s)")
        if self.state.llm_calls_used >= self.max_llm_calls:
            exceeded.append(f"LLM calls ({self.state.llm_calls_used}/{self.max_llm_calls})")

        if exceeded:
            self.state.exceeded = exceeded
            self.state.errored = True
            raise BudgetExceededError(f"Budget exceeded: {', '.join(exceeded)}")

        return True

    def record_request(self, count: int = 1):
        with self._lock:
            self.state.requests_used += count

    def record_llm_call(self):
        with self._lock:
            self.state.llm_calls_used += 1

    def record_action(self):
        with self._lock:
            self.state.actions_used += 1

    def elapsed(self) -> float:
        return time.time() - self.state.wall_start

    def summary(self) -> dict:
        return {
            "requests": f"{self.state.requests_used}/{self.max_requests}",
            "wall_clock": f"{self.elapsed():.0f}s/{self.max_wall_clock}s",
            "llm_calls": f"{self.state.llm_calls_used}/{self.max_llm_calls}",
            "actions": self.state.actions_used,
            "errored": self.state.errored,
            "exceeded": self.state.exceeded,
        }
