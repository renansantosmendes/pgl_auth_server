from datetime import datetime
from typing import Optional

from core.config import LOCK_DURATION, MAX_FAILED_ATTEMPTS, RESET_CODE_TTL


def find_enrollment(cursor, registration_number: str) -> Optional[tuple]:
    """Read the enrollment of a student from the course roster.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.

    Returns
    -------
    tuple | None
        ``(is_active, login_id)`` of the roster row, or None when the
        student is not on the roster.
    """
    cursor.execute(
        "SELECT is_active, login_id FROM pgl_proxy.students "
        "WHERE registration_number = %s",
        (registration_number,),
    )
    return cursor.fetchone()


def find_auth_student(cursor, registration_number: str) -> Optional[tuple]:
    """Read the password record of a student.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.

    Returns
    -------
    tuple | None
        ``(password_hash, is_active, token_version)``, or None when the
        student has never set a password.
    """
    cursor.execute(
        "SELECT password_hash, is_active, token_version "
        "FROM pgl_auth.students WHERE registration_number = %s",
        (registration_number,),
    )
    return cursor.fetchone()


def find_professor_role(cursor, registration_number: str) -> Optional[tuple]:
    """Read the role of a roster member.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the member.

    Returns
    -------
    tuple | None
        ``(role, is_active)`` of the roster row, or None when the member is
        not on the roster.
    """
    cursor.execute(
        "SELECT role, is_active FROM pgl_proxy.students "
        "WHERE registration_number = %s",
        (registration_number,),
    )
    return cursor.fetchone()


def create_student(
    cursor,
    registration_number: str,
    password_hash: str,
) -> None:
    """Insert a new password record for a student.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.
    password_hash : str
        bcrypt hash of the new password.

    Raises
    ------
    psycopg2.errors.UniqueViolation
        If the student already has a password record.
    """
    cursor.execute(
        "INSERT INTO pgl_auth.students "
        "(registration_number, password_hash, is_active) "
        "VALUES (%s, %s, TRUE)",
        (registration_number, password_hash),
    )


def save_password(
    cursor,
    registration_number: str,
    password_hash: str,
) -> None:
    """Create or replace the password of a student.

    Replacing the password increments ``token_version``, which invalidates
    every token issued before the change. The ``is_active`` flag is left
    unchanged on existing rows, so a deactivated student stays blocked.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.
    password_hash : str
        bcrypt hash of the new password.
    """
    cursor.execute(
        "INSERT INTO pgl_auth.students "
        "(registration_number, password_hash, is_active) "
        "VALUES (%s, %s, TRUE) "
        "ON CONFLICT (registration_number) DO UPDATE SET "
        "password_hash = EXCLUDED.password_hash, "
        "token_version = pgl_auth.students.token_version + 1",
        (registration_number, password_hash),
    )


def increment_token_version(cursor, registration_number: str) -> None:
    """Invalidate every token issued so far for a student.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.
    """
    cursor.execute(
        "UPDATE pgl_auth.students "
        "SET token_version = token_version + 1 "
        "WHERE registration_number = %s",
        (registration_number,),
    )


def set_student_active(
    cursor,
    registration_number: str,
    is_active: bool,
) -> bool:
    """Activate or block the password access of a student.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.
    is_active : bool
        New status of the account.

    Returns
    -------
    bool
        True when a password record was updated, False when the student has
        no password record yet.
    """
    cursor.execute(
        "UPDATE pgl_auth.students SET is_active = %s "
        "WHERE registration_number = %s",
        (is_active, registration_number),
    )
    return cursor.rowcount > 0


def list_student_accounts(cursor) -> list:
    """List every roster member with the state of their password account.

    Parameters
    ----------
    cursor : Any
        Open database cursor.

    Returns
    -------
    list
        Rows of ``(registration_number, full_name, login_id,
        roster_active, has_password, account_active)``.
    """
    cursor.execute(
        "SELECT p.registration_number, p.full_name, p.login_id, "
        "p.is_active, a.registration_number IS NOT NULL, a.is_active "
        "FROM pgl_proxy.students p "
        "LEFT JOIN pgl_auth.students a "
        "ON a.registration_number = p.registration_number "
        "ORDER BY p.registration_number"
    )
    return cursor.fetchall()


def find_lock_until(
    cursor,
    registration_number: str,
) -> Optional[datetime]:
    """Read until when the password login of a student is locked.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.

    Returns
    -------
    datetime | None
        Lock expiration, or None when the student is not locked.
    """
    cursor.execute(
        "SELECT locked_until FROM pgl_auth.login_attempts "
        "WHERE registration_number = %s",
        (registration_number,),
    )
    row = cursor.fetchone()
    return row[0] if row else None


def register_failed_attempt(
    cursor,
    registration_number: str,
    now: datetime,
) -> Optional[datetime]:
    """Count one failed password check and lock the account when needed.

    After ``MAX_FAILED_ATTEMPTS`` consecutive failures, the account is
    locked for ``LOCK_DURATION`` and the counter restarts.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number that failed the check.
    now : datetime
        Current time, timezone-aware.

    Returns
    -------
    datetime | None
        Lock expiration when this failure locked the account, otherwise
        None.
    """
    cursor.execute(
        "SELECT failed_count, locked_until FROM pgl_auth.login_attempts "
        "WHERE registration_number = %s",
        (registration_number,),
    )
    row = cursor.fetchone()
    failed_count = row[0] if row else 0
    if row and row[1] is not None and row[1] <= now:
        failed_count = 0
    failed_count += 1

    locked_until: Optional[datetime] = None
    if failed_count >= MAX_FAILED_ATTEMPTS:
        locked_until = now + LOCK_DURATION
        failed_count = 0

    cursor.execute(
        "INSERT INTO pgl_auth.login_attempts "
        "(registration_number, failed_count, locked_until) "
        "VALUES (%s, %s, %s) "
        "ON CONFLICT (registration_number) DO UPDATE SET "
        "failed_count = EXCLUDED.failed_count, "
        "locked_until = EXCLUDED.locked_until",
        (registration_number, failed_count, locked_until),
    )
    return locked_until


def clear_failed_attempts(cursor, registration_number: str) -> None:
    """Forget the failed attempts of a student after a successful check.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.
    """
    cursor.execute(
        "DELETE FROM pgl_auth.login_attempts WHERE registration_number = %s",
        (registration_number,),
    )


def find_reset_code(cursor, registration_number: str) -> Optional[tuple]:
    """Read the pending reset code of a student.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.

    Returns
    -------
    tuple | None
        ``(code_hash, expires_at, attempts, created_at)``, or None when no
        code is pending.
    """
    cursor.execute(
        "SELECT code_hash, expires_at, attempts, created_at "
        "FROM pgl_auth.password_reset_codes "
        "WHERE registration_number = %s",
        (registration_number,),
    )
    return cursor.fetchone()


def save_reset_code(
    cursor,
    registration_number: str,
    code_hash: str,
    expires_at: datetime,
    created_at: datetime,
) -> None:
    """Store a new reset code, replacing any pending one.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.
    code_hash : str
        Keyed hash of the code, see ``security.hash_reset_code``.
    expires_at : datetime
        Moment after which the code is no longer accepted.
    created_at : datetime
        Moment the code was issued, used for the resend cooldown.
    """
    cursor.execute(
        "INSERT INTO pgl_auth.password_reset_codes "
        "(registration_number, code_hash, expires_at, attempts, created_at) "
        "VALUES (%s, %s, %s, 0, %s) "
        "ON CONFLICT (registration_number) DO UPDATE SET "
        "code_hash = EXCLUDED.code_hash, "
        "expires_at = EXCLUDED.expires_at, "
        "attempts = 0, "
        "created_at = EXCLUDED.created_at",
        (registration_number, code_hash, expires_at, created_at),
    )


def increment_reset_attempts(cursor, registration_number: str) -> int:
    """Count one wrong code submitted for a student.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.

    Returns
    -------
    int
        Number of wrong attempts made with the current code.
    """
    cursor.execute(
        "UPDATE pgl_auth.password_reset_codes "
        "SET attempts = attempts + 1 "
        "WHERE registration_number = %s RETURNING attempts",
        (registration_number,),
    )
    row = cursor.fetchone()
    return row[0] if row else 0


def delete_reset_code(cursor, registration_number: str) -> None:
    """Remove the pending reset code of a student.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number of the student.
    """
    cursor.execute(
        "DELETE FROM pgl_auth.password_reset_codes "
        "WHERE registration_number = %s",
        (registration_number,),
    )


def record_audit_event(
    cursor,
    event: str,
    registration_number: Optional[str],
    actor: Optional[str],
    detail: str,
) -> None:
    """Append one event to the audit trail.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    event : str
        Event name, for example ``login_success``.
    registration_number : str | None
        Student the event is about.
    actor : str | None
        Registration number of whoever caused the event, when different.
    detail : str
        Short free text. Never store passwords or codes here.
    """
    cursor.execute(
        "INSERT INTO pgl_auth.audit_log "
        "(event, registration_number, actor, detail) "
        "VALUES (%s, %s, %s, %s)",
        (event, registration_number, actor, detail),
    )


def code_expiry(now: datetime) -> datetime:
    """Compute when a reset code issued at ``now`` stops being valid.

    Parameters
    ----------
    now : datetime
        Issue time, timezone-aware.

    Returns
    -------
    datetime
        Expiration time of the code.
    """
    return now + RESET_CODE_TTL
