import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import psycopg2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

TOKEN_TTL = timedelta(hours=4)


class LoginRequest(BaseModel):
    matricula: str
    senha: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def _get_connection():
    return psycopg2.connect(os.environ["NEON_DATABASE_URL"])


@app.post("/api/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT password_hash, is_active FROM pgl_auth.students WHERE matricula = %s",
                (payload.matricula,),
            )
            row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=401, detail="Matrícula ou senha inválidos.")

    password_hash, is_active = row

    if not bcrypt.checkpw(payload.senha.encode("utf-8"), password_hash.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Matrícula ou senha inválidos.")

    if not is_active:
        raise HTTPException(status_code=403, detail="Cadastro do aluno está inativo.")

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": payload.matricula, "iat": now, "exp": now + TOKEN_TTL},
        os.environ["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    return LoginResponse(access_token=token, expires_in=int(TOKEN_TTL.total_seconds()))
