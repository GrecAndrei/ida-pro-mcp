from __future__ import annotations


class CapsuleError(Exception):
    """Base error for capsule operations."""


class CapsuleNotInitializedError(CapsuleError):
    """Raised when a capsule DB is missing required schema/meta."""


class CapsuleValidationError(CapsuleError):
    """Raised when capsule data fails validation constraints."""


class CapsuleVerificationError(CapsuleError):
    """Raised when integrity/verification checks fail."""
