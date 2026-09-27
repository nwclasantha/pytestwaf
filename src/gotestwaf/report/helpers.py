"""Report helper utilities."""

from __future__ import annotations


def is_api_test(set_name: str) -> bool:
    """Check if a set of tests has the API category."""
    return "api" in set_name


NA_MARK = "N/A"
MAX_UNTRUNCATED_PAYLOAD_LENGTH = 1100
TRUNCATED_PARTS_LENGTH = 150

# Grade lookup table: (min_percentage, mark, css_class_suffix)
_GRADE_TABLE: list[tuple[float, str, str]] = [
    (97.0, "A+", "a"),
    (93.0, "A", "a"),
    (90.0, "A-", "a"),
    (87.0, "B+", "b"),
    (83.0, "B", "b"),
    (80.0, "B-", "b"),
    (77.0, "C+", "c"),
    (73.0, "C", "c"),
    (70.0, "C-", "c"),
    (67.0, "D+", "d"),
    (63.0, "D", "d"),
    (60.0, "D-", "d"),
    (0.0, "F", "f"),
]


def truncate_payload(payload: str) -> str:
    """Replace the middle part of long payloads with a truncation marker."""
    payload_length = len(payload)
    if payload_length <= MAX_UNTRUNCATED_PAYLOAD_LENGTH:
        return payload

    truncated_length = payload_length - 2 * TRUNCATED_PARTS_LENGTH
    return (
        f"{payload[:TRUNCATED_PARTS_LENGTH]}"
        f" \u2026 truncated {truncated_length} symbols \u2026 "
        f"{payload[payload_length - TRUNCATED_PARTS_LENGTH:]}"
    )


def get_grade(percentage: float, na: bool = False) -> dict[str, object]:
    """Calculate letter grade from percentage using lookup table.

    Args:
        percentage: Score percentage (0-100).
        na: Whether the score is not applicable.

    Returns:
        Dict with percentage, mark, and css_class_suffix.
    """
    if na:
        return {"percentage": 0.0, "mark": NA_MARK, "css_class_suffix": "na"}

    grade: dict[str, object] = {"percentage": percentage}

    # No rescaling needed — percentage values are already in 0-100 range
    # from calculate_percentage(). Rescaling values <= 1 would break
    # legitimate low scores (e.g. 0.5% would incorrectly become 50%).

    for min_pct, mark, css in _GRADE_TABLE:
        if percentage >= min_pct:
            grade["mark"] = mark
            grade["css_class_suffix"] = css
            return grade

    grade["mark"] = "F"
    grade["css_class_suffix"] = "f"
    return grade
