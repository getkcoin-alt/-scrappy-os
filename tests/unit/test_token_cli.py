"""Argument parsing for ``scrappy token``.

Small surface, but two of these functions decide a security boundary and one
decides what gets deleted, so they are tested directly rather than through the
Typer runner.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import typer

from scrappy_os.core.identity import Scope, all_scopes
from scrappy_os.interface.token_cli import parse_cutoff, parse_expiry, parse_scope_list

NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)


class TestParseExpiry:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("30s", NOW + timedelta(seconds=30)),
            ("15m", NOW + timedelta(minutes=15)),
            ("12h", NOW + timedelta(hours=12)),
            ("30d", NOW + timedelta(days=30)),
            ("2w", NOW + timedelta(weeks=2)),
        ],
    )
    def test_durations_are_relative_to_now(self, raw: str, expected: datetime) -> None:
        assert parse_expiry(raw, now=NOW) == expected

    def test_an_absolute_timestamp_is_used_as_given(self) -> None:
        assert parse_expiry("2026-09-16T10:30:00+00:00", now=NOW) == datetime(
            2026, 9, 16, 10, 30, tzinfo=UTC
        )

    def test_an_offset_timestamp_is_normalised_to_utc(self) -> None:
        assert parse_expiry("2026-09-16T16:00:00+05:30", now=NOW) == datetime(
            2026, 9, 16, 10, 30, tzinfo=UTC
        )

    @pytest.mark.parametrize("raw", [None, "", "   "])
    def test_absent_means_no_expiry(self, raw: str | None) -> None:
        assert parse_expiry(raw, now=NOW) is None

    def test_a_naive_timestamp_is_refused(self) -> None:
        """Expiry is a boundary; "which midnight" is not a guess to make."""
        with pytest.raises(typer.BadParameter, match="timezone"):
            parse_expiry("2026-09-16T10:30:00", now=NOW)

    @pytest.mark.parametrize("raw", ["0d", "-5d"])
    def test_a_non_positive_duration_is_refused(self, raw: str) -> None:
        with pytest.raises(typer.BadParameter):
            parse_expiry(raw, now=NOW)

    @pytest.mark.parametrize("raw", ["soon", "30", "30y", "d30", "thirty-days"])
    def test_nonsense_is_refused(self, raw: str) -> None:
        with pytest.raises(typer.BadParameter):
            parse_expiry(raw, now=NOW)


class TestParseCutoff:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("90d", NOW - timedelta(days=90)),
            ("12h", NOW - timedelta(hours=12)),
            ("2w", NOW - timedelta(weeks=2)),
        ],
    )
    def test_a_duration_reaches_backwards(self, raw: str, expected: datetime) -> None:
        """``--older-than 90d`` means ninety days *ago*."""
        assert parse_cutoff(raw, now=NOW) == expected

    def test_an_absolute_cutoff_is_used_exactly_as_written(self) -> None:
        """Regression: the cutoff used to be reflected about the present.

        ``prune`` computed ``now - (parse_expiry(raw) - now)``, which is right
        for a duration and badly wrong for a timestamp. With now = 2026-08-17,
        ``--older-than 2026-01-01T00:00:00Z`` produced a cutoff in April 2027 -
        seven months in the future - so the one command that deletes rows would
        have removed every retired credential instead of those retired before
        January.
        """
        january = datetime(2026, 1, 1, tzinfo=UTC)
        cutoff = parse_cutoff("2026-01-01T00:00:00+00:00", now=NOW)
        assert cutoff == january
        assert cutoff is not None and cutoff < NOW, "a cutoff must not be in the future"

    def test_expiry_and_cutoff_point_in_opposite_directions(self) -> None:
        """The distinction the two functions exist to keep."""
        expiry = parse_expiry("90d", now=NOW)
        cutoff = parse_cutoff("90d", now=NOW)
        assert expiry is not None and cutoff is not None
        assert expiry > NOW > cutoff

    def test_a_naive_cutoff_is_refused(self) -> None:
        with pytest.raises(typer.BadParameter, match="timezone"):
            parse_cutoff("2026-01-01T00:00:00", now=NOW)

    @pytest.mark.parametrize("raw", [None, "", "   "])
    def test_absent_means_no_cutoff(self, raw: str | None) -> None:
        assert parse_cutoff(raw, now=NOW) is None


class TestParseScopeList:
    def test_a_single_scope_resolves(self) -> None:
        assert parse_scope_list("task:read") == frozenset({Scope.TASK_READ})

    def test_several_scopes_resolve(self) -> None:
        assert parse_scope_list("task:create,task:read") == frozenset(
            {Scope.TASK_CREATE, Scope.TASK_READ}
        )

    def test_surrounding_whitespace_is_tolerated(self) -> None:
        assert parse_scope_list(" task:create , task:read ") == frozenset(
            {Scope.TASK_CREATE, Scope.TASK_READ}
        )

    def test_duplicates_collapse(self) -> None:
        assert parse_scope_list("task:read,task:read") == frozenset({Scope.TASK_READ})

    def test_every_known_scope_is_grantable(self) -> None:
        names = ",".join(str(scope) for scope in all_scopes())
        assert parse_scope_list(names) == all_scopes()

    def test_an_unknown_scope_is_refused_rather_than_dropped(self) -> None:
        """Dropping it would issue a weaker credential than was asked for."""
        with pytest.raises(typer.BadParameter, match="unknown scope"):
            parse_scope_list("task:read,galaxy:destroy")

    def test_the_error_lists_what_is_available(self) -> None:
        with pytest.raises(typer.BadParameter) as caught:
            parse_scope_list("nope")
        assert "task:read" in str(caught.value)

    @pytest.mark.parametrize("raw", [None, "", "   ", ",", " , "])
    def test_no_scopes_is_refused(self, raw: str | None) -> None:
        """Scopes are never defaulted; a credential with none is a mistake."""
        with pytest.raises(typer.BadParameter):
            parse_scope_list(raw)

    def test_scope_matching_is_exact(self) -> None:
        """No prefix or case leniency: 'TASK:READ' is not a scope."""
        with pytest.raises(typer.BadParameter):
            parse_scope_list("TASK:READ")
