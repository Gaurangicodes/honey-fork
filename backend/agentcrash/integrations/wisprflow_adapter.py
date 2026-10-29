"""Wispr Flow voice-command adapter (FR-INT-04, SRS section 25).

Wispr Flow is a desktop/mobile dictation product. It has **no public API**
(checked against https://docs.wisprflow.ai — the help centre documents a
hotkey-driven "Command Mode" that inserts text into the focused field; there is
no documented HTTP endpoint to submit audio or fetch a transcript). The
integration is therefore a *guarded input source*: the recognised command text
arrives from the client, is displayed, and must be confirmed by the user.

FR-INT-04 is a security requirement as much as a feature, so it is enforced
here rather than left to the UI:

* voice input **cannot** approve a policy, sign a transaction or authorise funds
  movement — those phrases are refused, not merely discouraged;
* every recognised command requires explicit confirmation before it runs;
* only a fixed allowlist of operations can be composed, so a transcript cannot
  smuggle in an arbitrary action.

The ``unsupported`` state is reported when no transcription source is
configured, which is the honest default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import AdapterResult, Integration, IntegrationState, SetupStep


class VoiceCommandRefused(Exception):
    """Raised when a transcript tries to do something voice must never do."""

    def __init__(self, reason: str, matched: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.matched = matched


@dataclass(frozen=True)
class VoiceOperation:
    """One allowlisted thing a voice command may compose."""

    key: str
    label: str
    # True when the operation must still show a confirmation before running.
    # Every operation is confirm-required; the flag exists so the UI can render
    # the requirement explicitly rather than inferring it.
    confirm_required: bool = True
    # Whether the operation is destructive enough to need a typed confirmation.
    destructive: bool = False


# The complete set of operations voice may compose. Anything not listed is
# refused. Note what is absent: apply_policy, sign, transfer, approve.
VOICE_OPERATIONS: dict[str, VoiceOperation] = {
    "start_scan": VoiceOperation("start_scan", "Start a security scan"),
    "open_report": VoiceOperation("open_report", "Open the latest proof report"),
    "open_run": VoiceOperation("open_run", "Open a run"),
    "reset_sandbox": VoiceOperation(
        "reset_sandbox", "Reset the sandbox", destructive=True
    ),
    "show_attack": VoiceOperation("show_attack", "Show an attack"),
}

# Word sets used by the operation matcher. Matching is whole-word: a phrase
# matches when it contains one word from each required set. Synonyms are listed
# so common demo phrasings ("run a security test") map without loosening the
# match into substrings.
_START_WORDS = frozenset({"start", "run", "launch", "begin", "kick"})
_SCAN_WORDS = frozenset({"scan", "test", "suite", "scanning"})
_RESET_WORDS = frozenset({"reset", "restore", "clear"})
_SANDBOX_WORDS = frozenset({"sandbox", "environment", "state"})
_SHOW_WORDS = frozenset({"show", "open", "display", "view"})

# Phrases that must never be honoured by voice. These are refused with an
# explanation instead of being silently unmatched, so a demo can show the
# refusal (FR-INT-04).
FORBIDDEN_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(apply|approve|accept|confirm)\b.{0,20}\b(fix|policy|rule|change)\b",
     "voice cannot approve or apply a policy"),
    (r"\b(sign|submit|send|broadcast|execute|authorise|authorize)\b.{0,20}\b(transaction|tx|transfer|payment|funds)\b",
     "voice cannot sign or submit a transaction"),
    (r"\b(transfer|send|move|withdraw|approve)\b.{0,20}\b(funds|eth|tokens?|usdc|money|balance)\b",
     "voice cannot authorise funds movement"),
    (r"\b(raise|increase|lift|remove|disable|bypass)\b.{0,20}\b(limit|cap|allowlist|policy|guard)\b",
     "voice cannot change or disable an enforcement policy"),
    (r"\b(private key|seed phrase|mnemonic|secret key)\b",
     "voice must never be used to handle key material"),
)


class WisprFlowIntegration(Integration):
    name = "wisprflow"
    priority = "P1"
    docs_url = "https://docs.wisprflow.ai/articles/4816967992-how-to-use-command-mode"
    # No credential is strictly required because the transcript can arrive from
    # the browser; the adapter is `unsupported` unless a source is configured.
    required_config: tuple[str, ...] = ()
    role = "Optional voice-to-command input"
    acceptance = (
        "Recognized command is displayed and user-confirmed; voice cannot approve "
        "policies or transactions."
    )

    def setup(self) -> list[SetupStep]:
        return [
            SetupStep(
                "Wispr Flow has no public API. Dictate into the command box with the "
                "Wispr Flow hotkey; the recognised text is posted to the API below."
            ),
            SetupStep("Enable the adapter", self.flag_name, "1"),
            SetupStep(
                "Optional: choose how the transcript reaches the API",
                "WISPRFLOW_SOURCE",
                "client",
            ),
        ]

    @property
    def source(self) -> str:
        return self._environ.get("WISPRFLOW_SOURCE", "client")

    def state(self) -> IntegrationState:
        state = super().state()
        if state is not IntegrationState.OK:
            return state
        if self.source not in ("client", "manual"):
            return IntegrationState.UNSUPPORTED
        return IntegrationState.OK

    # -- capability ----------------------------------------------------------

    def parse(self, transcript: str) -> AdapterResult:
        """FR-INT-04: turn a transcript into a proposed, unconfirmed operation.

        Never executes anything. Returns the recognised command and the single
        allowlisted operation it maps to, with ``confirm_required`` set. A
        transcript that tries to approve, sign or move funds is refused.
        """
        if self.state() is not IntegrationState.OK:
            return self.unavailable()
        text = " ".join((transcript or "").split())
        if not text:
            return AdapterResult(
                adapter=self.name,
                state=IntegrationState.OK,
                detail="Empty transcript.",
                meta={"recognized": "", "operation": None, "confirmed": False},
            )

        lowered = text.lower()
        for pattern, reason in FORBIDDEN_PATTERNS:
            match = re.search(pattern, lowered)
            if match:
                return AdapterResult(
                    adapter=self.name,
                    state=IntegrationState.OK,
                    detail=f"Refused: {reason}.",
                    reason=reason,
                    error_code="VOICE_ACTION_REFUSED",
                    meta={
                        "recognized": text,
                        "operation": None,
                        "refused": True,
                        "matched": match.group(0),
                        "confirmed": False,
                    },
                )

        operation = self._match_operation(lowered)
        if operation is None:
            return AdapterResult(
                adapter=self.name,
                state=IntegrationState.OK,
                detail="No allowlisted operation matched; nothing was run.",
                meta={
                    "recognized": text,
                    "operation": None,
                    "confirmed": False,
                    "allowlisted": list(VOICE_OPERATIONS),
                },
            )

        # A confirmation token is only accepted when it is explicitly passed to
        # execute(); parse() itself never authorises anything.
        return AdapterResult(
            adapter=self.name,
            state=IntegrationState.OK,
            detail=f"Recognised: {operation.label}. Confirmation required.",
            findings=[
                {
                    "kind": "voice_command",
                    "recognized": text,
                    "operation": operation.key,
                    "label": operation.label,
                    "confirm_required": operation.confirm_required,
                    "destructive": operation.destructive,
                    "confirmed": False,
                    "source": "wisprflow",
                }
            ],
            meta={"recognized": text, "operation": operation.key, "confirmed": False},
        )

    @staticmethod
    def _match_operation(lowered: str) -> VoiceOperation | None:
        # Whole-word matching. Substring tests misfire in both directions: a
        # scan phrase like "run a security test" shares no substring with
        # "scan", while "running late" contains "run". Each word is compared
        # whole so synonyms match and incidental substrings do not.
        words = set(re.findall(r"[a-z0-9]+", lowered))
        if words & _RESET_WORDS and words & _SANDBOX_WORDS:
            return VOICE_OPERATIONS["reset_sandbox"]
        if words & _START_WORDS and words & _SCAN_WORDS:
            return VOICE_OPERATIONS["start_scan"]
        if "report" in words:
            return VOICE_OPERATIONS["open_report"]
        if "run" in words and "open" in words:
            return VOICE_OPERATIONS["open_run"]
        if "attack" in words and words & _SHOW_WORDS:
            return VOICE_OPERATIONS["show_attack"]
        return None

    def execute(self, transcript: str, *, confirmed: bool) -> AdapterResult:
        """Return the operation to run, but only with an explicit confirmation.

        This is the only path that marks a command runnable, and it cannot
        approve a policy or authorise a transfer because no such operation
        exists in :data:`VOICE_OPERATIONS`.
        """
        parsed = self.parse(transcript)
        if parsed.error_code == "VOICE_ACTION_REFUSED" or not parsed.findings:
            return parsed
        if not confirmed:
            parsed.meta["confirmed"] = False
            parsed.detail = "Awaiting user confirmation; nothing was run."
            parsed.findings[0]["confirmed"] = False
            return parsed
        parsed.meta["confirmed"] = True
        parsed.findings[0]["confirmed"] = True
        parsed.detail = f"Confirmed: {parsed.findings[0]['label']}."
        return parsed
