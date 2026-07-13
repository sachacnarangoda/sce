"""Sealed Continuation Envelope (SCE) -- fail-closed, committing, version-binding seal for portable AI inference state."""

from .core import (
    ModelManifest,
    compute_memh,
    seal_state,
    unseal_state,
    describe_envelope,
    explain_mismatch,
    SCEError,
    StateSealMismatch,
    MalformedEnvelope,
    SEAL_COUNT_CEILING_PER_KEY,
)
from .stream import (
    seal_state_chunked,
    unseal_state_chunked,
    describe_stream,
    DEFAULT_SEGMENT_SIZE,
)

__version__ = "0.4.4"

__all__ = [
    "ModelManifest",
    "compute_memh",
    "seal_state",
    "unseal_state",
    "describe_envelope",
    "explain_mismatch",
    "seal_state_chunked",
    "unseal_state_chunked",
    "describe_stream",
    "DEFAULT_SEGMENT_SIZE",
    "SCEError",
    "StateSealMismatch",
    "MalformedEnvelope",
    "SEAL_COUNT_CEILING_PER_KEY",
    "__version__",
]
