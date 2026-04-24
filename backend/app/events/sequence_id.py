"""Sequence ID generation — links PreToolUse and PostToolUse events.

The sequence ID is the correlation key that pairs the PreToolUse enforcement
decision with the PostToolUse completion event for the same tool invocation.
In the intercept pipeline the ToolCallRequest.request_id already uniquely
identifies an invocation; this module makes that linking contract explicit and
provides a dedicated generation path for cases where a fresh ID is needed.

Sprint S-E07 (E07-T03)
"""

from __future__ import annotations

import uuid


def generate_sequence_id() -> str:
    """Generate a new sequence ID for a fresh tool invocation.

    Use this when creating a standalone PostToolUse event that is not
    associated with an existing ToolCallRequest.
    """
    return str(uuid.uuid4())


def sequence_id_from_request(request_id: str | uuid.UUID) -> str:
    """Derive the sequence ID from an existing ToolCallRequest.request_id.

    Both the PreToolUse decision event and the PostToolUse completion event
    share this ID so TrustSOC consumers can correlate the full lifecycle of
    a single tool invocation.
    """
    return str(request_id)
