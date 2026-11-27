from datetime import datetime
from typing import Callable

from core import mailer, repository, security
from core.config import RESET_CODE_COOLDOWN

CODE_SENT = "sent"
COOLDOWN_ACTIVE = "cooldown"


def issue_code(
    cursor,
    registration_number: str,
    recipient: str,
    build_message: Callable[[str], tuple[str, str]],
    now: datetime,
    secret: str,
) -> str:
    """Create a reset code, store its keyed hash and e-mail it.

    A new code is not issued while the previous one is inside the resend
    cooldown. The e-mail is sent after the hash is stored, in the same
    transaction: if the e-mail fails, the exception propagates and the
    database work is rolled back.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Student the code belongs to.
    recipient : str
        Institutional e-mail address of the student.
    build_message : Callable[[str], tuple[str, str]]
        Function that receives the code and returns ``(subject, text)``.
    now : datetime
        Current time, timezone-aware.
    secret : str
        Server secret used to key the code hash.

    Returns
    -------
    str
        ``CODE_SENT`` when a code was issued, or ``COOLDOWN_ACTIVE`` when a
        code was issued too recently.

    Example
    -------
    >>> issue_code(cur, "12345", "a@b.com", build, now, "s")  # doctest: +SKIP
    'sent'
    """
    existing = repository.find_reset_code(cursor, registration_number)
    if existing is not None and existing[3] + RESET_CODE_COOLDOWN > now:
        return COOLDOWN_ACTIVE

    code = security.generate_reset_code()
    code_hash = security.hash_reset_code(code, registration_number, secret)
    repository.save_reset_code(
        cursor,
        registration_number,
        code_hash,
        repository.code_expiry(now),
        now,
    )
    subject, text = build_message(code)
    mailer.send_message(recipient, subject, text)
    return CODE_SENT
