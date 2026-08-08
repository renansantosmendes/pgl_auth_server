import logging
import os
from datetime import datetime, timezone

import jwt
import psycopg2
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core import db, security
from core.config import TOKEN_TTL

logger = logging.getLogger("pgl_auth_server.auth")

router = APIRouter(prefix="/api", tags=["auth"])


class LoginRequest(BaseModel):
    matricula: str
    senha: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RegisterRequest(BaseModel):
    matricula: str
    senha: str


class RegisterResponse(BaseModel):
    matricula: str
    message: str = "Student registered successfully."


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    logger.info(
        "Login attempt received | matricula=%s senha_fp=%s",
        payload.matricula,
        security.fingerprint(payload.senha),
    )

    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT password_hash, is_active FROM pgl_auth.students WHERE matricula = %s",
                (payload.matricula,),
            )
            row = cur.fetchone()

    if row is None:
        logger.warning(
            "Login denied: matricula not found | matricula=%s", payload.matricula
        )
        raise HTTPException(status_code=401, detail="Matrícula ou senha inválidos.")

    password_hash, is_active = row

    if not security.verify_password(payload.senha, password_hash):
        logger.warning(
            "Login denied: incorrect password | matricula=%s", payload.matricula
        )
        raise HTTPException(status_code=401, detail="Matrícula ou senha inválidos.")

    if not is_active:
        logger.warning(
            "Login denied: student is inactive | matricula=%s", payload.matricula
        )
        raise HTTPException(status_code=403, detail="Cadastro do aluno está inativo.")

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": payload.matricula, "iat": now, "exp": now + TOKEN_TTL},
        os.environ["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    logger.info("Login successful | matricula=%s", payload.matricula)
    return LoginResponse(access_token=token, expires_in=int(TOKEN_TTL.total_seconds()))


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(payload: RegisterRequest) -> RegisterResponse:
    logger.info(
        "Registration attempt received | matricula=%s senha_fp=%s",
        payload.matricula,
        security.fingerprint(payload.senha),
    )

    password_hash = security.hash_password(payload.senha)

    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT is_active FROM pgl_proxy.students WHERE matricula = %s",
                (payload.matricula,),
            )
            proxy_row = cur.fetchone()

            if proxy_row is None or not proxy_row[0]:
                logger.warning(
                    "Registration denied: matricula not enrolled/active in pgl_proxy | matricula=%s",
                    payload.matricula,
                )
                raise HTTPException(
                    status_code=403,
                    detail="Matrícula não encontrada ou inativa na disciplina.",
                )

            try:
                cur.execute(
                    "INSERT INTO pgl_auth.students (matricula, password_hash, is_active) "
                    "VALUES (%s, %s, TRUE)",
                    (payload.matricula, password_hash),
                )
            except psycopg2.errors.UniqueViolation:
                logger.warning(
                    "Registration denied: matricula already exists | matricula=%s",
                    payload.matricula,
                )
                raise HTTPException(status_code=409, detail="Matrícula já cadastrada.")

    logger.info("Registration successful | matricula=%s", payload.matricula)
    return RegisterResponse(matricula=payload.matricula)
