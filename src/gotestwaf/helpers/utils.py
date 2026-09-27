"""Generic utility functions."""

from __future__ import annotations

import copy
from typing import TypeVar

K = TypeVar("K")
V = TypeVar("V")


def deep_copy_map(original: dict[K, V]) -> dict[K, V]:
    """Create a deep copy of a dictionary.

    Args:
        original: The dictionary to copy.

    Returns:
        A new dictionary with recursively copied values.
    """
    return copy.deepcopy(original)
