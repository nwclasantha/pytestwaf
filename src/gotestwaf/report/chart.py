"""Chart data generation for HTML/PDF reports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gotestwaf.db.helpers import calculate_percentage, is_api_test

if TYPE_CHECKING:
    from gotestwaf.db.statistics import Statistics, TestDetails

EMPTY_INDICATOR = "-"


class Pair:
    """Counter pair for blocked/bypassed."""

    __slots__ = ("blocked", "bypassed")

    def __init__(self) -> None:
        self.blocked = 0
        self.bypassed = 0


def update_counters(
    t: TestDetails,
    counters: dict[str, dict[str, Pair]],
    is_blocked: bool,
) -> None:
    """Count tests by category (api/app) and type."""
    category = "api" if is_api_test(t.test_set) else "app"
    typ = t.type.lower() if t.type else "unknown"

    counters.setdefault(category, {})
    counters[category].setdefault(typ, Pair())

    if is_blocked:
        counters[category][typ].blocked += 1
    else:
        counters[category][typ].bypassed += 1


def get_indicators_and_items(
    counters: dict[str, dict[str, Pair]],
    category: str,
) -> tuple[list[str], list[float]]:
    """Return indicators and percentage values for charts."""
    if category not in counters:
        return [], []

    indicators: list[str] = []
    items: list[float] = []

    for test_type, val in counters[category].items():
        total = val.blocked + val.bypassed
        percentage = float(calculate_percentage(val.blocked, total))
        indicators.append(f"{test_type} ({percentage:.1f}%)")
        items.append(percentage)

    # Pad to minimum chart points
    match len(indicators):
        case 0:
            return [], []
        case 1:
            indicators = [indicators[0], EMPTY_INDICATOR, EMPTY_INDICATOR,
                         EMPTY_INDICATOR, EMPTY_INDICATOR, EMPTY_INDICATOR]
            items = [items[0], 0.0, 0.0, 0.0, 0.0, 0.0]
        case 2:
            indicators = [EMPTY_INDICATOR, indicators[0], EMPTY_INDICATOR,
                         EMPTY_INDICATOR, indicators[1], EMPTY_INDICATOR]
            items = [0.0, items[0], 0.0, 0.0, items[1], 0.0]
        case 3:
            indicators = [indicators[0], EMPTY_INDICATOR, indicators[1],
                         EMPTY_INDICATOR, indicators[2], EMPTY_INDICATOR]
            items = [items[0], 0.0, items[1], 0.0, items[2], 0.0]
        case 4:
            indicators = [EMPTY_INDICATOR, indicators[0], EMPTY_INDICATOR, indicators[1],
                         EMPTY_INDICATOR, indicators[2], EMPTY_INDICATOR, indicators[3]]
            items = [0.0, items[0], 0.0, items[1], 0.0, items[2], 0.0, items[3]]
        case _:
            # 5+ data points: pad to even count with empty spacers for chart symmetry
            padded_indicators: list[str] = []
            padded_items: list[float] = []
            for idx in range(len(indicators)):
                padded_indicators.append(indicators[idx])
                padded_items.append(items[idx])
                if idx < len(indicators) - 1:
                    padded_indicators.append(EMPTY_INDICATOR)
                    padded_items.append(0.0)
            indicators = padded_indicators
            items = padded_items

    return indicators, items


def generate_chart_data(s: Statistics) -> tuple[list[str], list[float], list[str], list[float]]:
    """Generate chart indicators and values.

    Returns:
        Tuple of (api_indicators, api_items, app_indicators, app_items).
    """
    counters: dict[str, dict[str, Pair]] = {}

    for t in s.true_positive_tests.blocked:
        update_counters(t, counters, is_blocked=True)
    for t in s.true_positive_tests.bypasses:
        update_counters(t, counters, is_blocked=False)

    contains_api = "api" in counters

    if contains_api:
        if not s.is_grpc_available:
            counters["api"].setdefault("grpc", Pair())
        if not s.is_graphql_available:
            counters["api"].setdefault("graphql", Pair())

    api_indicators, api_items = get_indicators_and_items(counters, "api")
    app_indicators, app_items = get_indicators_and_items(counters, "app")

    if contains_api:
        for i, label in enumerate(api_indicators):
            if not s.is_grpc_available and label.startswith("grpc"):
                api_indicators[i] = "grpc (unavailable)"
                api_items[i] = 0.0
            if not s.is_graphql_available and label.startswith("graphql"):
                api_indicators[i] = "graphql (unavailable)"
                api_items[i] = 0.0

    return api_indicators, api_items, app_indicators, app_items
