"""Structured application errors with stable API error codes (SRS 7.4)."""

from __future__ import annotations

from .models import ErrorCode


class AgentCrashError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        resource_id: str | None = None,
        retryable: bool = False,
        status_code: int = 400,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.resource_id = resource_id
        self.retryable = retryable
        self.status_code = status_code

    def to_dict(self) -> dict[str, object]:
        return {
            "error": {
                "code": self.code.value,
                "message": self.message,
                "resource_id": self.resource_id,
                "retryable": self.retryable,
            }
        }


class SandboxUnavailable(AgentCrashError):
    def __init__(self, message: str = "Sandbox chain is unavailable") -> None:
        super().__init__(
            ErrorCode.SANDBOX_UNAVAILABLE, message, retryable=True, status_code=503
        )


class ReplayStateMismatch(AgentCrashError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.REPLAY_STATE_MISMATCH, message, status_code=409)
