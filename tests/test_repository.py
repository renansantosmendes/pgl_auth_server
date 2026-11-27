from datetime import datetime, timedelta, timezone

from core import repository
from core.config import LOCK_DURATION
from tests.fakes import FakeDatabase

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)


def cursor_with(routes):
    database = FakeDatabase(routes)
    return database, database.connect().cursor()


def last_upsert_params(database):
    return database.statements_containing("INSERT INTO pgl_auth.login_attempts")[-1][1]


def test_failed_attempt_is_counted_without_locking():
    database, cursor = cursor_with([("SELECT failed_count, locked_until", (1, None))])

    locked_until = repository.register_failed_attempt(cursor, "12345", NOW)

    assert locked_until is None
    assert last_upsert_params(database) == ("12345", 2, None)


def test_fifth_failed_attempt_locks_the_account_and_resets_the_counter():
    database, cursor = cursor_with([("SELECT failed_count, locked_until", (4, None))])

    locked_until = repository.register_failed_attempt(cursor, "12345", NOW)

    assert locked_until == NOW + LOCK_DURATION
    assert last_upsert_params(database) == ("12345", 0, NOW + LOCK_DURATION)


def test_expired_lock_restarts_the_count():
    expired = NOW - timedelta(minutes=1)
    database, cursor = cursor_with([("SELECT failed_count, locked_until", (0, expired))])

    locked_until = repository.register_failed_attempt(cursor, "12345", NOW)

    assert locked_until is None
    assert last_upsert_params(database) == ("12345", 1, None)


def test_first_failure_for_unknown_student_starts_at_one():
    database, cursor = cursor_with([])

    repository.register_failed_attempt(cursor, "99999", NOW)

    assert last_upsert_params(database) == ("99999", 1, None)
