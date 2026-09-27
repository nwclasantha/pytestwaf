"""Test result database with thread-safe operations."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field

from gotestwaf.db.models import Case, Info


@dataclass
class DB:
    """Thread-safe database for test results and statistics."""

    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    counters: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict, init=False)
    passed_tests: list[Info] = field(default_factory=list, init=False)
    blocked_tests: list[Info] = field(default_factory=list, init=False)
    failed_tests: list[Info] = field(default_factory=list, init=False)
    na_tests: list[Info] = field(default_factory=list, init=False)
    tests: list[Case] = field(default_factory=list, init=False)

    scanned_paths: dict[str, dict[str, None]] = field(default_factory=dict, init=False)

    number_of_tests: int = field(default=0, init=False)
    hash: str = field(default="", init=False)

    is_grpc_available: bool = field(default=False, init=False)
    is_graphql_available: bool = field(default=False, init=False)

    @classmethod
    def from_test_cases(cls, tests: list[Case]) -> DB:
        """Create a new DB from a list of test cases.

        Args:
            tests: List of test cases.

        Returns:
            Initialized DB instance.
        """
        db = cls()
        db.tests = tests

        hash_sums: list[bytes] = []

        for test in tests:
            db.counters.setdefault(test.set, {})
            db.counters[test.set].setdefault(test.name, {})

            db.number_of_tests += len(test.payloads) * len(test.encoders) * len(test.placeholders)
            hash_sums.append(test.hash())

        hash_sums.sort()

        sha256hash = hashlib.sha256()
        for h in hash_sums:
            sha256hash.update(h)

        db.hash = sha256hash.hexdigest()[:32]

        return db

    def _ensure_counter(self, test_set: str, test_case: str) -> None:
        """Ensure counter keys exist for the given test set and case."""
        if test_set not in self.counters:
            self.counters[test_set] = {}
        if test_case not in self.counters[test_set]:
            self.counters[test_set][test_case] = {}

    def update_passed_tests(self, t: Info) -> None:
        """Record a test that passed (bypassed WAF)."""
        with self._lock:
            self._ensure_counter(t.set, t.case)
            self.counters[t.set][t.case].setdefault("passed", 0)
            self.counters[t.set][t.case]["passed"] += 1
            self.passed_tests.append(t)

    def update_na_tests(
        self, t: Info, ignore_unresolved: bool, non_blocked_as_passed: bool, is_true_positive: bool
    ) -> None:
        """Record an unresolved test result."""
        with self._lock:
            self._ensure_counter(t.set, t.case)
            # Under ignore_unresolved / non_blocked_as_passed, an unresolved
            # response means the WAF did not visibly block it — count as
            # "passed" for BOTH attack and false-positive sets. Previously the
            # `and is_true_positive` clause routed unresolved FP requests into
            # the blocked counter, which suppressed the True-Negative score to
            # 0% whenever the WAF returned ambiguous responses on benign text.
            if ignore_unresolved or non_blocked_as_passed:
                self.counters[t.set][t.case].setdefault("passed", 0)
                self.counters[t.set][t.case]["passed"] += 1
            else:
                self.counters[t.set][t.case].setdefault("blocked", 0)
                self.counters[t.set][t.case]["blocked"] += 1
            self.na_tests.append(t)

    def update_blocked_tests(self, t: Info) -> None:
        """Record a test that was blocked by WAF."""
        with self._lock:
            self._ensure_counter(t.set, t.case)
            self.counters[t.set][t.case].setdefault("blocked", 0)
            self.counters[t.set][t.case]["blocked"] += 1
            self.blocked_tests.append(t)

    def update_failed_tests(self, t: Info) -> None:
        """Record a test that failed to execute."""
        with self._lock:
            self._ensure_counter(t.set, t.case)
            self.counters[t.set][t.case].setdefault("failed", 0)
            self.counters[t.set][t.case]["failed"] += 1
            self.failed_tests.append(t)

    def add_to_scanned_paths(self, method: str, path: str) -> None:
        """Track scanned HTTP paths."""
        with self._lock:
            self.scanned_paths.setdefault(path, {})
            self.scanned_paths[path][method] = None

    def get_test_cases(self) -> list[Case]:
        """Return all test cases."""
        return self.tests
