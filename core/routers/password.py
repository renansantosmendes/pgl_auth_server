import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from core import db, messages, repository, reset_flow, security, validation
from core.config import RESET_CODE_MAX_ATTEMPTS
from core.routers.auth import raise_validation_error
from core.schemas import ForgotPasswordRequest, MessageResponse, PasswordResetRequest

logger = logging.getLogger("pgl_auth_server.password")

router = APIRouter(prefix="/api/password", tags=["password"])

FORGOT_MESSAGE = (
    "Se a matrícula estiver ativa e tiver um e-mail institucional "
    "cadastrado, enviaremos um código para esse e-mail."
)
INVALID_CODE_MESSAGE = "Código inválido ou expirado."
RESET_DONE_MESSAGE = "Senha redefinida com sucesso."


@router.post("/forgot", response_model=MessageResponse, status_code=202)
def forgot_password(payload: ForgotPasswordRequest) -> MessageResponse:
    """Send a reset code to the institutional e-mail of the student.

    The response is the same whether or not a code was sent, so the
    endpoint does not reveal which registration numbers exist. Code
    delivery errors are logged and not shown to the caller.

    Parameters
    ----------
    payload : ForgotPasswordRequest
        Registration number of the student.

    Returns
    -------
    MessageResponse
        Generic confirmation message.

    Raises
    ------
    HTTPException
        422 when the registration number has an invalid format.
    """
    registration_number = payload.registration_number
    errors = validation.registration_number_problems(registration_number)
    if errors:
        raise_validation_error(errors)

    now = datetime.now(timezone.utc)
    try:
        with db.get_connection() as conn:
            with conn.cursor() as cur:
                enrollment = repository.find_enrollment(cur, registration_number)
                if _can_receive_code(enrollment):
                    outcome = reset_flow.issue_code(
                        cur,
                        registration_number,
                        enrollment[1].strip(),
                        messages.reset_code_message,
                        now,
                        os.environ["JWT_SECRET_KEY"],
                    )
                    if outcome == reset_flow.CODE_SENT:
                        repository.record_audit_event(
                            cur,
                            "password_reset_requested",
                            registration_number,
                            None,
                            "code sent",
                        )
    except Exception:
        logger.exception("Could not deliver a password reset code.")
    return MessageResponse(message=FORGOT_MESSAGE)


def _can_receive_code(enrollment) -> bool:
    """Tell whether a roster row can receive a reset code by e-mail.

    Parameters
    ----------
    enrollment : tuple | None
        ``(is_active, login_id)`` of the roster row, or None.

    Returns
    -------
    bool
        True when the student is active and ``login_id`` is an e-mail.
    """
    if enrollment is None or not enrollment[0]:
        return False
    login_id = (enrollment[1] or "").strip()
    return validation.email_problems(login_id) == []


@router.post("/reset", response_model=MessageResponse)
def reset_password(payload: PasswordResetRequest) -> MessageResponse:
    """Set a new password using the code received by e-mail.

    The password rules are checked before the code is consumed. Five wrong
    codes discard the pending code, and a new one must be requested.

    Parameters
    ----------
    payload : PasswordResetRequest
        Registration number, code and new password.

    Returns
    -------
    MessageResponse
        Confirmation that the password was replaced.

    Raises
    ------
    HTTPException
        422 for invalid data or a weak password, 400 for an invalid or
        expired code.
    """
    registration_number = payload.registration_number
    errors = validation.registration_number_problems(registration_number)
    errors += validation.password_problems(payload.nova_senha, registration_number)
    if errors:
        raise_validation_error(errors)

    now = datetime.now(timezone.utc)
    secret = os.environ["JWT_SECRET_KEY"]
    accepted = False
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            accepted = _consume_code(
                cur, registration_number, payload.codigo, payload.nova_senha, now, secret
            )
    if not accepted:
        raise HTTPException(status_code=400, detail=INVALID_CODE_MESSAGE)
    return MessageResponse(message=RESET_DONE_MESSAGE)


def _consume_code(
    cursor,
    registration_number: str,
    code: str,
    new_password: str,
    now: datetime,
    secret: str,
) -> bool:
    """Check the reset code and, if it matches, replace the password.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Student that requested the reset.
    code : str
        Code typed by the student.
    new_password : str
        New password, already validated against the strength rules.
    now : datetime
        Current time, timezone-aware.
    secret : str
        Server secret used to check the code hash.

    Returns
    -------
    bool
        True when the password was replaced, False otherwise.
    """
    enrollment = repository.find_enrollment(cursor, registration_number)
    if enrollment is None or not enrollment[0]:
        return False

    stored = repository.find_reset_code(cursor, registration_number)
    if stored is None:
        return False
    code_hash, expires_at, attempts, _ = stored
    if expires_at <= now or attempts >= RESET_CODE_MAX_ATTEMPTS:
        repository.delete_reset_code(cursor, registration_number)
        return False

    if not security.reset_code_matches(code, registration_number, secret, code_hash):
        attempts = repository.increment_reset_attempts(cursor, registration_number)
        if attempts >= RESET_CODE_MAX_ATTEMPTS:
            repository.delete_reset_code(cursor, registration_number)
        repository.record_audit_event(
            cursor,
            "password_reset_failed",
            registration_number,
            None,
            "wrong code",
        )
        return False

    repository.save_password(
        cursor, registration_number, security.hash_password(new_password)
    )
    repository.delete_reset_code(cursor, registration_number)
    repository.record_audit_event(
        cursor, "password_reset", registration_number, None, "code accepted"
    )
    return True
