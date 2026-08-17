"""Resolving the token pepper, and the ways that must not go quietly wrong.

Two failures matter more than the rest. A pepper that changes between starts
silently invalidates every credential in the database, which an operator reads
as "all my tokens broke for no reason". A pepper written world-readable makes the
verifiers it protects testable offline by anyone who can read the data directory.
Both are tested here rather than left to review.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from scrappy_os.core.errors import ConfigurationError
from scrappy_os.security.credentials import compute_verifier, verify_secret
from scrappy_os.security.pepper import (
    MIN_PEPPER_LENGTH,
    PEPPER_FILENAME,
    PepperSource,
    resolve_pepper,
)


class TestEnvironmentPepper:
    def test_a_configured_pepper_is_used_and_labelled(self, tmp_path: Path) -> None:
        resolved = resolve_pepper(configured="an-environment-pepper", data_dir=tmp_path)
        assert resolved.value == "an-environment-pepper"
        assert resolved.source is PepperSource.ENVIRONMENT
        assert resolved.is_environment

    def test_a_configured_pepper_does_not_create_a_file(self, tmp_path: Path) -> None:
        """Nothing should sit in the data directory pretending to protect anything."""
        resolve_pepper(configured="an-environment-pepper", data_dir=tmp_path)
        assert not (tmp_path / PEPPER_FILENAME).exists()

    def test_surrounding_whitespace_is_stripped(self, tmp_path: Path) -> None:
        """A trailing newline from a shell heredoc must not change the key."""
        resolved = resolve_pepper(configured="  an-environment-pepper\n", data_dir=tmp_path)
        assert resolved.value == "an-environment-pepper"

    @pytest.mark.parametrize("weak", ["short", "changeme", "x" * (MIN_PEPPER_LENGTH - 1)])
    def test_a_trivially_short_pepper_is_refused(self, tmp_path: Path, weak: str) -> None:
        """Accepting it would produce verifiers that look protected and are not."""
        with pytest.raises(ConfigurationError, match="SCRAPPY_TOKEN_PEPPER"):
            resolve_pepper(configured=weak, data_dir=tmp_path)

    def test_an_empty_configured_pepper_falls_back_rather_than_failing(
        self, tmp_path: Path
    ) -> None:
        """Unset and set-to-empty mean the same thing to a shell."""
        resolved = resolve_pepper(configured="   ", data_dir=tmp_path)
        assert resolved.source is PepperSource.DATA_DIRECTORY


class TestGeneratedPepper:
    def test_a_pepper_is_generated_on_first_use(self, tmp_path: Path) -> None:
        resolved = resolve_pepper(configured=None, data_dir=tmp_path / "data")
        assert resolved.source is PepperSource.DATA_DIRECTORY
        assert len(resolved.value) >= MIN_PEPPER_LENGTH

    def test_the_generated_pepper_is_stable_across_calls(self, tmp_path: Path) -> None:
        """The regression that would break every credential on restart."""
        first = resolve_pepper(configured=None, data_dir=tmp_path)
        second = resolve_pepper(configured=None, data_dir=tmp_path)
        assert first.value == second.value

    def test_credentials_survive_a_simulated_restart(self, tmp_path: Path) -> None:
        """The property the stability above exists to protect."""
        first = resolve_pepper(configured=None, data_dir=tmp_path)
        verifier = compute_verifier("a-secret", pepper=first.value)

        after_restart = resolve_pepper(configured=None, data_dir=tmp_path)
        assert verify_secret("a-secret", verifier, pepper=after_restart.value)

    def test_the_pepper_file_is_owner_only(self, tmp_path: Path) -> None:
        resolve_pepper(configured=None, data_dir=tmp_path)
        mode = stat.S_IMODE((tmp_path / PEPPER_FILENAME).stat().st_mode)
        assert mode == 0o600, f"pepper is mode {mode:#o}, readable beyond its owner"

    def test_the_data_directory_is_created_owner_only(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "fresh"
        resolve_pepper(configured=None, data_dir=data_dir)
        assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700

    def test_two_data_directories_get_different_peppers(self, tmp_path: Path) -> None:
        first = resolve_pepper(configured=None, data_dir=tmp_path / "a")
        second = resolve_pepper(configured=None, data_dir=tmp_path / "b")
        assert first.value != second.value

    def test_an_empty_pepper_file_fails_loudly(self, tmp_path: Path) -> None:
        """Regenerating would silently invalidate every existing credential."""
        (tmp_path / PEPPER_FILENAME).write_text("", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="empty"):
            resolve_pepper(configured=None, data_dir=tmp_path)

    def test_a_whitespace_only_pepper_file_fails_loudly(self, tmp_path: Path) -> None:
        (tmp_path / PEPPER_FILENAME).write_text("   \n", encoding="utf-8")
        with pytest.raises(ConfigurationError):
            resolve_pepper(configured=None, data_dir=tmp_path)

    def test_environment_wins_over_an_existing_file(self, tmp_path: Path) -> None:
        resolve_pepper(configured=None, data_dir=tmp_path)
        resolved = resolve_pepper(configured="an-environment-pepper", data_dir=tmp_path)
        assert resolved.source is PepperSource.ENVIRONMENT


class TestDescription:
    def test_the_description_never_contains_the_pepper(self, tmp_path: Path) -> None:
        """It is written for doctor output, which operators paste into issues."""
        for configured in ("an-environment-pepper-value", None):
            resolved = resolve_pepper(configured=configured, data_dir=tmp_path)
            assert resolved.value not in resolved.describe()

    def test_the_description_says_where_the_key_lives(self, tmp_path: Path) -> None:
        assert "environment" in resolve_pepper(
            configured="an-environment-pepper", data_dir=tmp_path
        ).describe()
        assert PEPPER_FILENAME in resolve_pepper(
            configured=None, data_dir=tmp_path
        ).describe()
