import logging
from datetime import datetime, timezone
from typing import Optional

import psycopg2
from fastapi import APIRouter, Header, HTTPException

from core import auth_tokens, db, repository, security, validation
from core.config import TOKEN_TTL
from core.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    MessageResponse,
    RegisterRequest,
    RegisterResponse,
)

logger = logging.getLogger("pgl_auth_server.auth")

router = APIRouter(prefix="/api", tags=["auth"])

INVALID_CREDENTIALS = "Matrícula ou senha inválidos."
LOCKED_MESSAGE = "Muitas tentativas incorretas. Tente novamente mais tarde."
INVALID_DATA_MESSAGE = "Dados inválidos para a operação."


def raise_validation_error(errors: list[str]) -> None:
    """Raise a 422 response listing every rule that the input broke.

    Parameters
    ----------
    errors : list[str]
        Human readable problems found in the request.

    Raises
    ------
    HTTPException
        Always, with status 422 and a ``message`` and ``errors`` detail.
    """
    raise HTTPException(
        status_code=422,
        detail={"message": INVALID_DATA_MESSAGE, "errors": errors},
    )


def raise_if_locked(cursor, registration_number: str, now: datetime) -> None:
    """Reject the request while the student's password login is locked.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Student whose lock is checked.
    now : datetime
        Current time, timezone-aware.

    Raises
    ------
    HTTPException
        429 while the lock is active.
    """
    locked_until = repository.find_lock_until(cursor, registration_number)
    if locked_until is not None and locked_until > now:
        raise HTTPException(status_code=429, detail=LOCKED_MESSAGE)


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    """Check the password and issue an access token.

    Failed checks are counted per registration number, and the account is
    locked after too many of them. Passwords created before the strength
    rules are still accepted here.

    Parameters
    ----------
    payload : LoginRequest
        Registration number and password.

    Returns
    -------
    LoginResponse
        Access token and its lifetime in seconds.

    Raises
    ------
    HTTPException
        401 for wrong credentials, 403 for an inactive account, 429 while
        the account is locked.
    """
    registration_number = payload.registration_number
    now = datetime.now(timezone.utc)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            raise_if_locked(cur, registration_number, now)
            row = repository.find_auth_student(cur, registration_number)
            password_ok = row is not None and security.verify_password(
                payload.senha, row[0]
            )
            if not password_ok:
                repository.register_failed_attempt(cur, registration_number, now)
                repository.record_audit_event(
                    cur, "login_failed", registration_number, None, "credentials"
                )
            elif not row[1]:
                repository.record_audit_event(
                    cur, "login_denied", registration_number, None, "inactive"
                )
            else:
                repository.clear_failed_attempts(cur, registration_number)
                repository.record_audit_event(
                    cur, "login_success", registration_number, None, "token issued"
                )

    if not password_ok:
        raise HTTPException(status_code=401, detail=INVALID_CREDENTIALS)
    if not row[1]:
        raise HTTPException(status_code=403, detail="Cadastro do aluno está inativo.")
    return LoginResponse(
        access_token=auth_tokens.issue_token(registration_number, row[2]),
        expires_in=int(TOKEN_TTL.total_seconds()),
    )


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(payload: RegisterRequest) -> RegisterResponse:
    """Create the password of an enrolled student for the first time.

    Every field is mandatory: registration number, institutional e-mail,
    password and its confirmation. The e-mail must match the one on the
    course roster, and the password must follow the strength rules.

    Parameters
    ----------
    payload : RegisterRequest
        Registration number, e-mail, password and confirmation.

    Returns
    -------
    RegisterResponse
        Confirmation with the registration number.

    Raises
    ------
    HTTPException
        422 for invalid data, 403 when the student is not enrolled or the
        e-mail does not match the roster, 409 when a password already exists.
    """
    registration_number = payload.registration_number
    errors = validation.registration_number_problems(registration_number)
    errors += validation.email_problems(payload.email)
    if payload.senha != payload.senha_confirmacao:
        errors.append("As senhas não coincidem.")
    errors += validation.password_problems(payload.senha, registration_number)
    if errors:
        raise_validation_error(errors)

    password_hash = security.hash_password(payload.senha)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            enrollment = repository.find_enrollment(cur, registration_number)
            if enrollment is None or not enrollment[0]:
                raise HTTPException(
                    status_code=403,
                    detail="Matrícula não encontrada ou inativa na disciplina.",
                )
            roster_email = (enrollment[1] or "").strip().lower()
            if roster_email != payload.email.strip().lower():
                raise HTTPException(
                    status_code=403,
                    detail="O e-mail informado não confere com o cadastro da disciplina.",
                )
            try:
                repository.create_student(cur, registration_number, password_hash)
            except psycopg2.errors.UniqueViolation:
                raise HTTPException(status_code=409, detail="Matrícula já cadastrada.")
            repository.record_audit_event(
                cur, "register", registration_number, None, "password created"
            )
    return RegisterResponse(registration_number=registration_number)


@router.post("/logout", response_model=MessageResponse)
def logout(authorization: Optional[str] = Header(default=None)) -> MessageResponse:
    """Revoke every token issued so far for the calling student.

    Parameters
    ----------
    authorization : str | None
        Bearer token of the student.

    Returns
    -------
    MessageResponse
        Confirmation that the session was closed.
    """
    claims = auth_tokens.decode_bearer(authorization)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            registration_number = auth_tokens.student_from_claims(cur, claims)
            repository.increment_token_version(cur, registration_number)
            repository.record_audit_event(
                cur, "logout", registration_number, None, "tokens revoked"
            )
    return MessageResponse(message="Sessão encerrada.")


@router.post("/password/change", response_model=LoginResponse)
def change_password(
    payload: ChangePasswordRequest,
    authorization: Optional[str] = Header(default=None),
) -> LoginResponse:
    """Replace the password of the calling student.

    The current password must be confirmed. Every older token is revoked,
    and a fresh token is returned so the student stays logged in.

    Parameters
    ----------
    payload : ChangePasswordRequest
        Current password and the new password.
    authorization : str | None
        Bearer token of the student.

    Returns
    -------
    LoginResponse
        New access token for the student.

    Raises
    ------
    HTTPException
        401 for a wrong current password, 422 for a weak new password,
        429 while the account is locked.
    """
    now = datetime.now(timezone.utc)
    claims = auth_tokens.decode_bearer(authorization)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            registration_number = auth_tokens.student_from_claims(cur, claims)
            raise_if_locked(cur, registration_number, now)
            row = repository.find_auth_student(cur, registration_number)
            current_ok = security.verify_password(payload.senha_atual, row[0])
            if not current_ok:
                repository.register_failed_attempt(cur, registration_number, now)
                repository.record_audit_event(
                    cur,
                    "password_change_failed",
                    registration_number,
                    None,
                    "wrong current password",
                )
            else:
                errors = validation.password_problems(
                    payload.nova_senha, registration_number
                )
                if errors:
                    raise_validation_error(errors)
                repository.save_password(
                    cur,
                    registration_number,
                    security.hash_password(payload.nova_senha),
                )
                repository.clear_failed_attempts(cur, registration_number)
                repository.record_audit_event(
                    cur, "password_changed", registration_number, None, "self service"
                )
                row = repository.find_auth_student(cur, registration_number)

    if not current_ok:
        raise HTTPException(status_code=401, detail="Senha atual inválida.")
    return LoginResponse(
        access_token=auth_tokens.issue_token(registration_number, row[2]),
        expires_in=int(TOKEN_TTL.total_seconds()),
    )
