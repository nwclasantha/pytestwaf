"""Export test results to CSV."""

from __future__ import annotations

import csv
from typing import TYPE_CHECKING

from gotestwaf.db.helpers import is_false_positive_test
from gotestwaf.payload.encoder.encoder import apply_encoder

if TYPE_CHECKING:
    from gotestwaf.db.database import DB


_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(val: str) -> str:
    """Prefix a leading single-quote when the cell would otherwise be parsed as
    a formula by Excel/LibreOffice. Attack payloads commonly start with `=`,
    `+`, `-`, or `@` and would auto-execute when the report is opened.
    """
    if val and val[0] in _FORMULA_TRIGGERS:
        return "'" + val
    return val


def export_payloads(db: DB, payloads_export_file: str) -> None:
    """Export all test payloads and results to a CSV file.

    Args:
        db: The test results database.
        payloads_export_file: Path to the output CSV file.
    """
    with open(payloads_export_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Payload",
            "Check Status",
            "Response Code",
            "Placeholder",
            "Encoder",
            "Set",
            "Case",
            "Test Result",
        ])

        # `_csv_safe` must be applied to every cell that originates from
        # user-supplied data (test-case YAML files, payload strings,
        # encoder/placeholder/set/case names). A custom test pack could
        # supply a set name like `=cmd|'/C calc'!A0` which Excel/LibreOffice
        # would auto-execute when the report CSV is opened. Sanitising only
        # the payload column left a CSV-injection vector through the
        # placeholder/encoder/set/case columns.
        for blocked_test in db.blocked_tests:
            try:
                ep = apply_encoder(blocked_test.encoder, blocked_test.payload)
            except Exception:
                ep = blocked_test.payload
            test_result = "failed" if is_false_positive_test(blocked_test.set) else "passed"
            writer.writerow([
                _csv_safe(ep),
                "blocked",
                str(blocked_test.response_status_code),
                _csv_safe(blocked_test.placeholder),
                _csv_safe(blocked_test.encoder),
                _csv_safe(blocked_test.set),
                _csv_safe(blocked_test.case),
                test_result,
            ])

        for passed_test in db.passed_tests:
            try:
                ep = apply_encoder(passed_test.encoder, passed_test.payload)
            except Exception:
                ep = passed_test.payload
            test_result = "passed" if is_false_positive_test(passed_test.set) else "failed"
            writer.writerow([
                _csv_safe(ep),
                "passed",
                str(passed_test.response_status_code),
                _csv_safe(passed_test.placeholder),
                _csv_safe(passed_test.encoder),
                _csv_safe(passed_test.set),
                _csv_safe(passed_test.case),
                test_result,
            ])

        for na_test in db.na_tests:
            try:
                ep = apply_encoder(na_test.encoder, na_test.payload)
            except Exception:
                ep = na_test.payload
            writer.writerow([
                _csv_safe(ep),
                "unresolved",
                str(na_test.response_status_code),
                _csv_safe(na_test.placeholder),
                _csv_safe(na_test.encoder),
                _csv_safe(na_test.set),
                _csv_safe(na_test.case),
                "unknown",
            ])
