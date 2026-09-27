"""Random value generation helpers for OpenAPI template filling."""

from __future__ import annotations

import random
import string

DEFAULT_PLACEHOLDER_SIZE = 16
DEFAULT_MAX_INT = 10000
DEFAULT_STRING_SIZE = 16

LETTER_RUNES = string.ascii_letters


def gen_random_int(
    min_val: float | None = None,
    max_val: float | None = None,
    exclusive_min: bool = False,
    exclusive_max: bool = False,
) -> int:
    """Generate a random integer within bounds."""
    min_value = 0 if min_val is None else int(min_val)
    max_value = DEFAULT_MAX_INT if max_val is None else int(max_val)

    if exclusive_min:
        min_value += 1
    if exclusive_max:
        max_value -= 1

    if max_value < min_value:
        return min_value

    return random.randint(min_value, max_value)


def gen_random_float(
    min_val: float | None = None,
    max_val: float | None = None,
    exclusive_min: bool = False,
    exclusive_max: bool = False,
) -> float:
    """Generate a random float within bounds."""
    min_value = 0.0 if min_val is None else min_val
    max_value = float(DEFAULT_MAX_INT) if max_val is None else max_val

    if exclusive_min:
        min_value += 1
    if exclusive_max:
        max_value -= 1

    if max_value <= min_value:
        return min_value

    return random.uniform(min_value, max_value)


def gen_random_string(min_length: int, max_length: int) -> str:
    """Generate a random string within [min_length, max_length].

    Honors the caller's max_length constraint (matters for OpenAPI schemas
    with short-string fields like 2-char country codes). Only pads min_length
    up to DEFAULT_STRING_SIZE when max_length has room for it.
    """
    if min_length < 0:
        min_length = 0
    if max_length < min_length:
        max_length = min_length

    # Pad min_length up to the default size only when max_length allows.
    if min_length < DEFAULT_STRING_SIZE <= max_length:
        min_length = DEFAULT_STRING_SIZE
    # Otherwise: respect the caller's bounds exactly.

    if max_length <= 0:
        return ""

    rand_length = random.randint(min_length, max_length)
    return "".join(random.choice(LETTER_RUNES) for _ in range(rand_length))


def gen_random_placeholder() -> str:
    """Generate a random placeholder with fixed size."""
    return gen_random_string(DEFAULT_PLACEHOLDER_SIZE, DEFAULT_PLACEHOLDER_SIZE)
