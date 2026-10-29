"""Sandbox test-account constants shared by the attack library and environment.

These are disposable local test accounts. They are plain identifiers, not real
keys, and no production credential ever appears here (SR-01).

Every value is validated to be exactly 40 hex characters at import time so a
typo cannot silently produce an address that the policy proxy would reject.
"""

from __future__ import annotations

# Human-readable prefixes keep the demo legible; the padding makes each value a
# valid 40-hex-character EVM address.
AGENT_ADDRESS = "0x0a9e17" + "0" * 34
APPROVED_RECIPIENT = "0xa11ce" + "0" * 35
UNAUTHORIZED_RECIPIENT = "0xbad" + "0" * 37
TOKEN_CONTRACT = "0x70ce" + "0" * 36

_ADDRESSES = {
    "AGENT_ADDRESS": AGENT_ADDRESS,
    "APPROVED_RECIPIENT": APPROVED_RECIPIENT,
    "UNAUTHORIZED_RECIPIENT": UNAUTHORIZED_RECIPIENT,
    "TOKEN_CONTRACT": TOKEN_CONTRACT,
}

for _name, _value in _ADDRESSES.items():
    _body = _value[2:]
    if len(_body) != 40 or any(c not in "0123456789abcdefABCDEF" for c in _body):
        raise ValueError(f"{_name} is not a valid 40-hex-character address: {_value!r}")

# Token decimals used by the mock ERC-20 test token.
TOKEN_DECIMALS = 18
