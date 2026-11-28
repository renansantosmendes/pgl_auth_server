import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from core import auth_tokens, db, mailer, messages, repository, security, validation
from core.config import CONFIRMATION_TTL, FRONTEND_BASE_URL, TOKEN_TTL
from core.schemas import (
    ChangePasswordRequest,
    ConfirmRegistrationRequest,
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
CONFIRMATION_SENT_MESSAGE = (
    "Enviamos um link de confirmação para o seu e-mail institucional. "
    "Abra o link em até 10 minutos para concluir o cadastro."
)
INVALID_LINK_MESSAGE = "Link inválido ou já utilizado."
EXPIRED_LINK_MESSAGE = "Link expirado. Faça o cadastro novamente."


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


@router.post("/register", response_model=MessageResponse, status_code=202)
def register(payload: RegisterRequest) -> MessageResponse:
    """Start a registration and e-mail the confirmation link.

    Every field is mandatory: registration number, institutional e-mail,
    password and its confirmation. The e-mail must match the one on the
    course roster, and the password must follow the strength rules. No
    account is created here: the account exists only after the student
    opens the link, which is valid for ``CONFIRMATION_TTL``.

    Parameters
    ----------
    payload : RegisterRequest
        Registration number, e-mail, password and confirmation.

    Returns
    -------
    MessageResponse
        Instruction to open the link sent by e-mail.

    Raises
    ------
    HTTPException
        422 for invalid data, 403 when the student is not enrolled or the
        e-mail does not match the roster, 409 when a password already exists,
        503 when the confirmation e-mail cannot be sent.
    """
    registration_number = payload.registration_number
    email = payload.email.strip()
    errors = validation.registration_number_problems(registration_number)
    errors += validation.email_problems(email)
    if payload.senha != payload.senha_confirmacao:
        errors.append("As senhas não coincidem.")
    errors += validation.password_problems(payload.senha, registration_number)
    if errors:
        raise_validation_error(errors)

    token = security.new_confirmation_token()
    now = datetime.now(timezone.utc)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            enrollment = repository.find_enrollment(cur, registration_number)
            if enrollment is None or not enrollment[0]:
                raise HTTPException(
                    status_code=403,
                    detail="Matrícula não encontrada ou inativa na disciplina.",
                )
            if (enrollment[1] or "").strip().lower() != email.lower():
                raise HTTPException(
                    status_code=403,
                    detail="O e-mail informado não confere com o cadastro da disciplina.",
                )
            if repository.find_auth_student(cur, registration_number) is not None:
                raise HTTPException(status_code=409, detail="Matrícula já cadastrada.")

            repository.save_pending_registration(
                cur,
                registration_number,
                email,
                security.hash_password(payload.senha),
                security.hash_confirmation_token(token),
                now + CONFIRMATION_TTL,
            )
            subject, text = messages.registration_confirmation_message(
                build_confirmation_link(token)
            )
            try:
                mailer.send_message(email, subject, text)
            except Exception:
                logger.exception("Could not send the registration confirmation e-mail.")
                raise HTTPException(
                    status_code=503,
                    detail="Não foi possível enviar o e-mail de confirmação. Tente novamente.",
                )
            repository.record_audit_event(
                cur,
                "registration_requested",
                registration_number,
                None,
                "confirmation e-mail sent",
            )
    return MessageResponse(message=CONFIRMATION_SENT_MESSAGE)


def build_confirmation_link(token: str) -> str:
    """Build the link the student opens to confirm the registration.

    Parameters
    ----------
    token : str
        Confirmation token. It is URL-safe, so it needs no encoding.

    Returns
    -------
    str
        Address of the confirmation page of the frontend.
    """
    return f"{FRONTEND_BASE_URL}/confirmar?token={token}"


@router.post("/register/confirm", response_model=RegisterResponse, status_code=201)
def confirm_registration(payload: ConfirmRegistrationRequest) -> RegisterResponse:
    """Create the account of a registration whose link was opened in time.

    The pending request is removed whether the account is created or not,
    so a link can be used only once and expired links are discarded.

    Parameters
    ----------
    payload : ConfirmRegistrationRequest
        Token copied from the confirmation link.

    Returns
    -------
    RegisterResponse
        Registration number of the new account.

    Raises
    ------
    HTTPException
        400 for an unknown, used or expired link, 403 when the student is no
        longer enrolled, 409 when the account already exists.
    """
    now = datetime.now(timezone.utc)
    token_hash = security.hash_confirmation_token(payload.token)
    outcome = "invalid"
    registration_number = ""
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            pending = repository.find_pending_registration(cur, token_hash)
            if pending is not None:
                registration_number, _, password_hash, expires_at = pending
                if expires_at <= now:
                    outcome = "expired"
                else:
                    outcome = _create_account(cur, registration_number, password_hash)
                repository.delete_pending_registration(cur, registration_number)

    if outcome == "created":
        return RegisterResponse(registration_number=registration_number)
    if outcome == "expired":
        raise HTTPException(status_code=400, detail=EXPIRED_LINK_MESSAGE)
    if outcome == "not_enrolled":
        raise HTTPException(
            status_code=403,
            detail="Matrícula não encontrada ou inativa na disciplina.",
        )
    if outcome == "duplicate":
        raise HTTPException(status_code=409, detail="Matrícula já cadastrada.")
    raise HTTPException(status_code=400, detail=INVALID_LINK_MESSAGE)


def _create_account(cursor, registration_number: str, password_hash: str) -> str:
    """Insert the password account of a confirmed registration.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    registration_number : str
        Registration number that confirmed the e-mail.
    password_hash : str
        bcrypt hash stored when the registration was requested.

    Returns
    -------
    str
        ``created``, ``not_enrolled`` or ``duplicate``.
    """
    enrollment = repository.find_enrollment(cursor, registration_number)
    if enrollment is None or not enrollment[0]:
        return "not_enrolled"
    if repository.find_auth_student(cursor, registration_number) is not None:
        return "duplicate"
    repository.create_student(cursor, registration_number, password_hash)
    repository.record_audit_event(
        cursor, "register_confirmed", registration_number, None, "account created"
    )
    return "created"


@router.post("/logout", response_model=MessageResponse)
def logout(authorization: Optional[str] = Depends(auth_tokens.bearer_authorization)) -> MessageResponse:
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
    authorization: Optional[str] = Depends(auth_tokens.bearer_authorization),
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
