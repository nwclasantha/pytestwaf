"""Statistics computation for test results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from gotestwaf.db.helpers import calculate_percentage, is_api_test, is_false_positive_test, round_value

if TYPE_CHECKING:
    from gotestwaf.db.database import DB
    from gotestwaf.db.models import Info


@dataclass(slots=True)
class RequestStats:
    """Request statistics counters."""

    all_requests_number: int = 0
    blocked_requests_number: int = 0
    bypassed_requests_number: int = 0
    unresolved_requests_number: int = 0
    failed_requests_number: int = 0
    resolved_requests_number: int = 0


@dataclass(slots=True)
class SummaryTableRow:
    """A single row in the summary table."""

    test_set: str = ""
    test_case: str = ""
    percentage: float = 0.0
    sent: int = 0
    blocked: int = 0
    bypassed: int = 0
    unresolved: int = 0
    failed: int = 0


@dataclass(slots=True)
class TestDetails:
    """Details for a single test result."""

    payload: str = ""
    test_case: str = ""
    test_set: str = ""
    encoder: str = ""
    placeholder: str = ""
    response_status_code: int = 0
    additional_info: list[str] = field(default_factory=list)
    type: str = ""
    # Full HTTP request/response for PoC evidence
    request_method: str = ""
    request_url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""


@dataclass(slots=True)
class FailedDetails:
    """Details for a failed test."""

    payload: str = ""
    test_case: str = ""
    test_set: str = ""
    encoder: str = ""
    placeholder: str = ""
    reason: list[str] = field(default_factory=list)
    type: str = ""


@dataclass(slots=True)
class TestsSummary:
    """Summary of test results for a category."""

    __test__ = False  # Prevent pytest from trying to collect this as a test class

    summary_table: list[SummaryTableRow] = field(default_factory=list)
    blocked: list[TestDetails] = field(default_factory=list)
    bypasses: list[TestDetails] = field(default_factory=list)
    unresolved: list[TestDetails] = field(default_factory=list)
    failed: list[FailedDetails] = field(default_factory=list)

    req_stats: RequestStats = field(default_factory=RequestStats)
    api_sec_req_stats: RequestStats = field(default_factory=RequestStats)
    app_sec_req_stats: RequestStats = field(default_factory=RequestStats)

    unresolved_requests_percentage: float = 0.0
    resolved_blocked_requests_percentage: float = 0.0
    resolved_bypassed_requests_percentage: float = 0.0
    failed_requests_percentage: float = 0.0


@dataclass(slots=True)
class Score:
    """Score for a category."""

    true_positive: float = 0.0
    true_negative: float = 0.0
    average: float = 0.0


@dataclass(slots=True)
class ScoreSet:
    """Combined scores."""

    api_sec: Score = field(default_factory=Score)
    app_sec: Score = field(default_factory=Score)
    average: float = 0.0


@dataclass(slots=True)
class Path:
    """A scanned path with method."""

    method: str = ""
    path: str = ""


@dataclass(slots=True)
class Statistics:
    """Complete test statistics."""

    is_grpc_available: bool = False
    is_graphql_available: bool = False

    paths: list[Path] = field(default_factory=list)

    test_cases_fingerprint: str = ""

    true_positive_tests: TestsSummary = field(default_factory=TestsSummary)
    true_negative_tests: TestsSummary = field(default_factory=TestsSummary)

    score: ScoreSet = field(default_factory=ScoreSet)


def _info_to_test_details(info: Info) -> TestDetails:
    """Convert Info to TestDetails."""
    return TestDetails(
        payload=info.payload,
        test_case=info.case,
        test_set=info.set,
        encoder=info.encoder,
        placeholder=info.placeholder,
        response_status_code=info.response_status_code,
        additional_info=sorted(info.additional_info),
        type=info.type,
        request_method=info.request_method,
        request_url=info.request_url,
        request_headers=info.request_headers,
        request_body=info.request_body,
        response_headers=info.response_headers,
        response_body=info.response_body,
    )


def _info_to_failed_details(info: Info) -> FailedDetails:
    """Convert Info to FailedDetails."""
    return FailedDetails(
        payload=info.payload,
        test_case=info.case,
        test_set=info.set,
        encoder=info.encoder,
        placeholder=info.placeholder,
        reason=info.additional_info,
        type=info.type,
    )


def _calculate_tests_summary_stat(s: TestsSummary) -> None:
    """Calculate aggregate statistics for a TestsSummary."""
    s.req_stats.all_requests_number = (
        s.req_stats.blocked_requests_number
        + s.req_stats.bypassed_requests_number
        + s.req_stats.unresolved_requests_number
        + s.req_stats.failed_requests_number
    )
    s.req_stats.resolved_requests_number = (
        s.req_stats.blocked_requests_number + s.req_stats.bypassed_requests_number
    )

    s.api_sec_req_stats.all_requests_number = (
        s.api_sec_req_stats.blocked_requests_number
        + s.api_sec_req_stats.bypassed_requests_number
        + s.api_sec_req_stats.unresolved_requests_number
        + s.api_sec_req_stats.failed_requests_number
    )
    s.api_sec_req_stats.resolved_requests_number = (
        s.api_sec_req_stats.blocked_requests_number + s.api_sec_req_stats.bypassed_requests_number
    )

    s.app_sec_req_stats.all_requests_number = (
        s.app_sec_req_stats.blocked_requests_number
        + s.app_sec_req_stats.bypassed_requests_number
        + s.app_sec_req_stats.unresolved_requests_number
        + s.app_sec_req_stats.failed_requests_number
    )
    s.app_sec_req_stats.resolved_requests_number = (
        s.app_sec_req_stats.blocked_requests_number + s.app_sec_req_stats.bypassed_requests_number
    )

    s.unresolved_requests_percentage = calculate_percentage(
        s.req_stats.unresolved_requests_number, s.req_stats.all_requests_number
    )
    s.resolved_blocked_requests_percentage = calculate_percentage(
        s.req_stats.blocked_requests_number, s.req_stats.resolved_requests_number
    )
    s.resolved_bypassed_requests_percentage = calculate_percentage(
        s.req_stats.bypassed_requests_number, s.req_stats.resolved_requests_number
    )
    s.failed_requests_percentage = calculate_percentage(
        s.req_stats.failed_requests_number, s.req_stats.all_requests_number
    )


def _calculate_score_percentage(
    score: Score,
    true_pos_blocked_num: int,
    true_pos_num: int,
    true_neg_bypass_num: int,
    true_neg_num: int,
) -> None:
    """Calculate score percentages."""
    divider = 0
    total = 0.0

    score.true_positive = calculate_percentage(true_pos_blocked_num, true_pos_num)
    score.true_negative = calculate_percentage(true_neg_bypass_num, true_neg_num)

    if true_pos_num != 0:
        divider += 1
        total += score.true_positive
    else:
        score.true_positive = -1.0

    if true_neg_num != 0:
        divider += 1
        total += score.true_negative
    else:
        score.true_negative = -1.0

    if divider != 0:
        score.average = round_value(total / divider)
    else:
        score.average = -1.0


def get_statistics(db: DB, ignore_unresolved: bool, non_blocked_as_passed: bool) -> Statistics:
    """Compute complete statistics from the database.

    Args:
        db: The test results database.
        ignore_unresolved: If True, count unresolved as bypassed.
        non_blocked_as_passed: If True, count non-blocked as passed.

    Returns:
        Complete Statistics object.
    """
    with db._lock:
        s = Statistics(
            is_grpc_available=db.is_grpc_available,
            is_graphql_available=db.is_graphql_available,
            test_cases_fingerprint=db.hash,
        )

        # Count unresolved requests per test set/case
        unresolved_requests_number: dict[str, dict[str, int]] = {}
        for unresolved_test in db.na_tests:
            unresolved_requests_number.setdefault(unresolved_test.set, {})
            if ignore_unresolved or non_blocked_as_passed:
                unresolved_requests_number[unresolved_test.set][unresolved_test.case] = 0
            else:
                unresolved_requests_number[unresolved_test.set].setdefault(unresolved_test.case, 0)
                unresolved_requests_number[unresolved_test.set][unresolved_test.case] += 1

        # Sort test sets and cases
        sorted_test_sets = sorted(db.counters.keys())

        for test_set in sorted_test_sets:
            sorted_test_cases = sorted(db.counters[test_set].keys())
            is_false_positive = is_false_positive_test(test_set)

            for test_case in sorted_test_cases:
                unresolved_requests = unresolved_requests_number.get(test_set, {}).get(test_case, 0)
                passed_requests = db.counters[test_set][test_case].get("passed", 0)
                blocked_requests = db.counters[test_set][test_case].get("blocked", 0)
                failed_requests = db.counters[test_set][test_case].get("failed", 0)

                total_requests = passed_requests + blocked_requests + failed_requests

                if not ignore_unresolved and not non_blocked_as_passed:
                    blocked_requests = max(0, blocked_requests - unresolved_requests)

                total_resolved_requests = passed_requests + blocked_requests

                row = SummaryTableRow(
                    test_set=test_set,
                    test_case=test_case,
                    percentage=0.0,
                    sent=total_requests,
                    blocked=blocked_requests,
                    bypassed=passed_requests,
                    unresolved=unresolved_requests,
                    failed=failed_requests,
                )

                if is_false_positive:
                    s.true_negative_tests.req_stats.blocked_requests_number += blocked_requests
                    s.true_negative_tests.req_stats.bypassed_requests_number += passed_requests
                    s.true_negative_tests.req_stats.unresolved_requests_number += unresolved_requests
                    s.true_negative_tests.req_stats.failed_requests_number += failed_requests

                    row.percentage = calculate_percentage(passed_requests, total_resolved_requests)
                    s.true_negative_tests.summary_table.append(row)
                else:
                    s.true_positive_tests.req_stats.blocked_requests_number += blocked_requests
                    s.true_positive_tests.req_stats.bypassed_requests_number += passed_requests
                    s.true_positive_tests.req_stats.unresolved_requests_number += unresolved_requests
                    s.true_positive_tests.req_stats.failed_requests_number += failed_requests

                    row.percentage = calculate_percentage(blocked_requests, total_resolved_requests)
                    s.true_positive_tests.summary_table.append(row)

        # Process blocked tests
        for blocked_test in db.blocked_tests:
            td = _info_to_test_details(blocked_test)
            is_fp = is_false_positive_test(blocked_test.set)
            is_api = is_api_test(blocked_test.set)

            if is_fp:
                s.true_negative_tests.blocked.append(td)
                if is_api:
                    s.true_negative_tests.api_sec_req_stats.blocked_requests_number += 1
                else:
                    s.true_negative_tests.app_sec_req_stats.blocked_requests_number += 1
            else:
                s.true_positive_tests.blocked.append(td)
                if is_api:
                    s.true_positive_tests.api_sec_req_stats.blocked_requests_number += 1
                else:
                    s.true_positive_tests.app_sec_req_stats.blocked_requests_number += 1

        # Process passed tests
        for passed_test in db.passed_tests:
            td = _info_to_test_details(passed_test)
            is_fp = is_false_positive_test(passed_test.set)
            is_api = is_api_test(passed_test.set)

            if is_fp:
                s.true_negative_tests.bypasses.append(td)
                if is_api:
                    s.true_negative_tests.api_sec_req_stats.bypassed_requests_number += 1
                else:
                    s.true_negative_tests.app_sec_req_stats.bypassed_requests_number += 1
            else:
                s.true_positive_tests.bypasses.append(td)
                if is_api:
                    s.true_positive_tests.api_sec_req_stats.bypassed_requests_number += 1
                else:
                    s.true_positive_tests.app_sec_req_stats.bypassed_requests_number += 1

        # Process unresolved tests
        for unresolved_test in db.na_tests:
            td = _info_to_test_details(unresolved_test)
            is_fp = is_false_positive_test(unresolved_test.set)
            is_api = is_api_test(unresolved_test.set)

            if ignore_unresolved or non_blocked_as_passed:
                if is_fp:
                    s.true_negative_tests.blocked.append(td)
                    if is_api:
                        s.true_negative_tests.api_sec_req_stats.blocked_requests_number += 1
                    else:
                        s.true_negative_tests.app_sec_req_stats.blocked_requests_number += 1
                else:
                    s.true_positive_tests.bypasses.append(td)
                    if is_api:
                        s.true_positive_tests.api_sec_req_stats.bypassed_requests_number += 1
                    else:
                        s.true_positive_tests.app_sec_req_stats.bypassed_requests_number += 1
            else:
                if is_fp:
                    s.true_negative_tests.unresolved.append(td)
                    if is_api:
                        s.true_negative_tests.api_sec_req_stats.unresolved_requests_number += 1
                    else:
                        s.true_negative_tests.app_sec_req_stats.unresolved_requests_number += 1
                else:
                    s.true_positive_tests.unresolved.append(td)
                    if is_api:
                        s.true_positive_tests.api_sec_req_stats.unresolved_requests_number += 1
                    else:
                        s.true_positive_tests.app_sec_req_stats.unresolved_requests_number += 1

        # Process failed tests
        for failed_test in db.failed_tests:
            fd = _info_to_failed_details(failed_test)
            is_fp = is_false_positive_test(failed_test.set)
            is_api = is_api_test(failed_test.set)

            if is_fp:
                s.true_negative_tests.failed.append(fd)
                if is_api:
                    s.true_negative_tests.api_sec_req_stats.failed_requests_number += 1
                else:
                    s.true_negative_tests.app_sec_req_stats.failed_requests_number += 1
            else:
                s.true_positive_tests.failed.append(fd)
                if is_api:
                    s.true_positive_tests.api_sec_req_stats.failed_requests_number += 1
                else:
                    s.true_positive_tests.app_sec_req_stats.failed_requests_number += 1

        # Process scanned paths
        if db.scanned_paths:
            paths: list[Path] = []
            for path, methods in db.scanned_paths.items():
                for method in methods:
                    paths.append(Path(method=method, path=path))
            paths.sort(key=lambda p: (p.path, p.method))
            s.paths = paths

        # Calculate summary stats
        _calculate_tests_summary_stat(s.true_positive_tests)
        _calculate_tests_summary_stat(s.true_negative_tests)

        # Calculate scores
        _calculate_score_percentage(
            s.score.api_sec,
            s.true_positive_tests.api_sec_req_stats.blocked_requests_number,
            s.true_positive_tests.api_sec_req_stats.resolved_requests_number,
            s.true_negative_tests.api_sec_req_stats.bypassed_requests_number,
            s.true_negative_tests.api_sec_req_stats.resolved_requests_number,
        )
        _calculate_score_percentage(
            s.score.app_sec,
            s.true_positive_tests.app_sec_req_stats.blocked_requests_number,
            s.true_positive_tests.app_sec_req_stats.resolved_requests_number,
            s.true_negative_tests.app_sec_req_stats.bypassed_requests_number,
            s.true_negative_tests.app_sec_req_stats.resolved_requests_number,
        )

        divider = 0
        total = 0.0
        if s.score.api_sec.average != -1.0:
            divider += 1
            total += s.score.api_sec.average
        if s.score.app_sec.average != -1.0:
            divider += 1
            total += s.score.app_sec.average

        if divider != 0:
            s.score.average = round_value(total / divider)
        else:
            s.score.average = -1.0

        return s
