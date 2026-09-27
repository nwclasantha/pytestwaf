"""Utility functions for placeholders."""

from __future__ import annotations

import os


def random_hex(n: int) -> str:
    """Generate a random hex string of n bytes.

    Args:
        n: Number of random bytes (output string will be 2*n chars).

    Returns:
        Hex-encoded random string.
    """
    return os.urandom(n).hex()
