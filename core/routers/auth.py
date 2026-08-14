import logging
import os
from datetime import datetime, timezone
from typing import Optional

import jwt
import psycopg2
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from core import db, security
from core.config import TOKEN_TTL

logger = logging.getLogger("pgl_auth_server.auth")

router = APIRouter(prefix="/api", tags=["auth"])


class LoginRequest(BaseModel):
    registration_number: str
    senha: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RegisterRequest(BaseModel):
    registration_number: str
    senha: str


class RegisterResponse(BaseModel):
    registration_number: str
    message: str = "Student registered successfully."


class ResetPasswordRequest(BaseModel):
    registration_number: str
    new_senha: str


class ResetPasswordResponse(BaseModel):
    registration_number: str
    message: str = "Password reset successfully."


def _authenticate_professor(authorization: Optional[str]) -> str:
    """Verify the bearer JWT and confirm its owner has role 'Professor'.

    Reused by admin-only endpoints (currently just /api/reset-password).
    A professor authenticates the exact same way a student does (POST
    /api/login), so this only needs to check role in pgl_proxy.students
    for the token's registration_number — no separate professor account
    system.

    Returns
    -------
    str
        The professor's registration_number (the token's ``sub`` claim).

    Raises
    ------
    HTTPException
        401 if the token is missing/malformed/invalid/expired, 403 if its
        owner isn't an active professor.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")

    token = authorization[len("Bearer "):].strip()
    try:
        claims = jwt.decode(token, os.environ["JWT_SECRET_KEY"], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired.") from None
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.") from None

    registration_number = claims.get("sub")
    if not registration_number:
        raise HTTPException(status_code=401, detail="Invalid token.")

    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT role, is_active FROM pgl_proxy.students WHERE registration_number = %s",
                (registration_number,),
            )
            row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=403, detail="Only professors can reset a student's password.")

    role, is_active = row
    if not is_active or (role or "").strip().lower() != "professor":
        raise HTTPException(status_code=403, detail="Only professors can reset a student's password.")

    return registration_number


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    logger.info(
        "Login attempt received | registration_number=%s senha_fp=%s",
        payload.registration_number,
        security.fingerprint(payload.senha),
    )

    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT password_hash, is_active FROM pgl_auth.students WHERE registration_number = %s",
                (payload.registration_number,),
            )
            row = cur.fetchone()

    if row is None:
        logger.warning(
            "Login denied: registration_number not found | registration_number=%s",
            payload.registration_number,
        )
        raise HTTPException(status_code=401, detail="Matrícula ou senha inválidos.")

    password_hash, is_active = row

    if not security.verify_password(payload.senha, password_hash):
        logger.warning(
            "Login denied: incorrect password | registration_number=%s",
            payload.registration_number,
        )
        raise HTTPException(status_code=401, detail="Matrícula ou senha inválidos.")

    if not is_active:
        logger.warning(
            "Login denied: student is inactive | registration_number=%s",
            payload.registration_number,
        )
        raise HTTPException(status_code=403, detail="Cadastro do aluno está inativo.")

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": payload.registration_number, "iat": now, "exp": now + TOKEN_TTL},
        os.environ["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    logger.info("Login successful | registration_number=%s", payload.registration_number)
    return LoginResponse(access_token=token, expires_in=int(TOKEN_TTL.total_seconds()))


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(payload: RegisterRequest) -> RegisterResponse:
    logger.info(
        "Registration attempt received | registration_number=%s senha_fp=%s",
        payload.registration_number,
        security.fingerprint(payload.senha),
    )

    password_hash = security.hash_password(payload.senha)

    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT is_active FROM pgl_proxy.students WHERE registration_number = %s",
                (payload.registration_number,),
            )
            proxy_row = cur.fetchone()

            if proxy_row is None or not proxy_row[0]:
                logger.warning(
                    "Registration denied: registration_number not enrolled/active in pgl_proxy | registration_number=%s",
                    payload.registration_number,
                )
                raise HTTPException(
                    status_code=403,
                    detail="Matrícula não encontrada ou inativa na disciplina.",
                )

            try:
                cur.execute(
                    "INSERT INTO pgl_auth.students (registration_number, password_hash, is_active) "
                    "VALUES (%s, %s, TRUE)",
                    (payload.registration_number, password_hash),
                )
            except psycopg2.errors.UniqueViolation:
                logger.warning(
                    "Registration denied: registration_number already exists | registration_number=%s",
                    payload.registration_number,
                )
                raise HTTPException(status_code=409, detail="Matrícula já cadastrada.")

    logger.info("Registration successful | registration_number=%s", payload.registration_number)
    return RegisterResponse(registration_number=payload.registration_number)


@router.post("/reset-password", response_model=ResetPasswordResponse)
def reset_password(
    payload: ResetPasswordRequest, authorization: Optional[str] = Header(default=None)
) -> ResetPasswordResponse:
    """Let a professor set (or reset) a student's password.

    Authenticates the caller as a professor via their own JWT (same
    `/api/login` flow students use), then upserts the target student's
    password in `pgl_auth.students` — this works whether or not the
    student had registered a password before, so a professor can also
    use it to set an initial password on a student's behalf.
    """
    professor_registration_number = _authenticate_professor(authorization)

    password_hash = security.hash_password(payload.new_senha)

    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO pgl_auth.students (registration_number, password_hash, is_active)
                VALUES (%s, %s, TRUE)
                ON CONFLICT (registration_number)
                DO UPDATE SET password_hash = EXCLUDED.password_hash, is_active = TRUE
                """,
                (payload.registration_number, password_hash),
            )

    logger.info(
        "Password reset | professor=%s target=%s",
        professor_registration_number,
        payload.registration_number,
    )
    return ResetPasswordResponse(registration_number=payload.registration_number)
