"""Profiler test-path exclusion rules."""

from __future__ import annotations

from shift_left.profiler.path_exclusions import is_excluded_test_path


def test_excludes_conventional_test_paths() -> None:
    assert is_excluded_test_path("t/unit/test_foo.py")
    assert is_excluded_test_path("tests/integration/test_bar.py")
    assert is_excluded_test_path("pkg/test_utils.py")
    assert is_excluded_test_path("spec/models/user_spec.rb")
    assert is_excluded_test_path("fixtures/data.json")
    assert is_excluded_test_path("t/smoke/conftest.py")


def test_keeps_production_paths() -> None:
    assert not is_excluded_test_path("celery/backends/database/result_filter.py")
    assert not is_excluded_test_path("setup.py")
    assert not is_excluded_test_path("docs/changelog_formatter.py")
