import os
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import HTTPException

from core import db, repository
from core.config import TOKEN_TTL

SESSION_EXPIRED_MESSAGE = "Sessão inválida. Faça login novamente."
PROFESSOR_ONLY_MESSAGE = "Apenas professores podem executar esta ação."


def issue_token(registration_number: str, token_version: int) -> str:
    """Create a signed access token for a student.

    Parameters
    ----------
    registration_number : str
        Registration number, stored in the ``sub`` claim.
    token_version : int
        Current token version of the student, stored in the ``ver`` claim.
        Changing the version invalidates the token.

    Returns
    -------
    str
        Signed JWT valid for ``TOKEN_TTL``.

    Example
    -------
    >>> token = issue_token("12345", 0)  # doctest: +SKIP
    """
    now = datetime.now(timezone.utc)
    claims = {
        "sub": registration_number,
        "ver": token_version,
        "iat": now,
        "exp": now + TOKEN_TTL,
    }
    return jwt.encode(claims, os.environ["JWT_SECRET_KEY"], algorithm="HS256")


def decode_bearer(authorization: Optional[str]) -> dict:
    """Read and verify the bearer token of a request.

    Parameters
    ----------
    authorization : str | None
        Value of the ``Authorization`` header.

    Returns
    -------
    dict
        Claims of the verified token.

    Raises
    ------
    HTTPException
        401 when the header is missing, the token is malformed, invalid or
        expired.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")

    token = authorization[len("Bearer ") :].strip()
    try:
        return jwt.decode(
            token, os.environ["JWT_SECRET_KEY"], algorithms=["HS256"]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired.") from None
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.") from None


def check_token_is_current(claims: dict, token_version: int) -> None:
    """Reject a token whose version no longer matches the student's.

    Tokens issued before the ``ver`` claim existed are read as version 0.

    Parameters
    ----------
    claims : dict
        Verified claims of the token.
    token_version : int
        Current token version stored for the student.

    Raises
    ------
    HTTPException
        401 when the token was revoked by a logout or a password change.
    """
    if int(claims.get("ver", 0)) != token_version:
        raise HTTPException(status_code=401, detail=SESSION_EXPIRED_MESSAGE)


def authenticate_student(cursor, authorization: Optional[str]) -> str:
    """Identify the student behind a bearer token.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    authorization : str | None
        Value of the ``Authorization`` header.

    Returns
    -------
    str
        Registration number of the authenticated student.

    Raises
    ------
    HTTPException
        401 for an invalid or revoked token, 403 for an inactive account.
    """
    return student_from_claims(cursor, decode_bearer(authorization))


def student_from_claims(cursor, claims: dict) -> str:
    """Identify the student behind already verified token claims.

    Call ``decode_bearer`` before opening a database connection, so that a
    missing or invalid token is rejected without touching the database.

    Parameters
    ----------
    cursor : Any
        Open database cursor.
    claims : dict
        Claims returned by ``decode_bearer``.

    Returns
    -------
    str
        Registration number of the authenticated student.

    Raises
    ------
    HTTPException
        401 for a revoked token, 403 for an inactive account.
    """
    registration_number = claims.get("sub")
    if not registration_number:
        raise HTTPException(status_code=401, detail="Invalid token.")

    row = repository.find_auth_student(cursor, registration_number)
    if row is None:
        raise HTTPException(status_code=401, detail=SESSION_EXPIRED_MESSAGE)
    _, is_active, token_version = row
    if not is_active:
        raise HTTPException(status_code=403, detail="Cadastro do aluno está inativo.")
    check_token_is_current(claims, token_version)
    return registration_number


def authenticate_professor(authorization: Optional[str]) -> str:
    """Identify a professor behind a bearer token.

    A professor logs in exactly like a student. The token must be current,
    and the roster role of its owner must be ``Professor``.

    Parameters
    ----------
    authorization : str | None
        Value of the ``Authorization`` header.

    Returns
    -------
    str
        Registration number of the professor.

    Raises
    ------
    HTTPException
        401 for an invalid or revoked token, 403 when the caller is not an
        active professor.
    """
    claims = decode_bearer(authorization)
    registration_number = claims.get("sub")
    if not registration_number:
        raise HTTPException(status_code=401, detail="Invalid token.")

    with db.get_connection() as conn:
        with conn.cursor() as cur:
            auth_row = repository.find_auth_student(cur, registration_number)
            role_row = repository.find_professor_role(cur, registration_number)

    if auth_row is None:
        raise HTTPException(status_code=403, detail=PROFESSOR_ONLY_MESSAGE)
    check_token_is_current(claims, auth_row[2])

    if role_row is None:
        raise HTTPException(status_code=403, detail=PROFESSOR_ONLY_MESSAGE)
    role, is_active = role_row
    if not is_active or (role or "").strip().lower() != "professor":
        raise HTTPException(status_code=403, detail=PROFESSOR_ONLY_MESSAGE)
    return registration_number


def verify_identity(authorization: Optional[str]) -> dict:
    """Describe the owner of a current bearer token.

    Other services call this function through ``GET /api/token/verify`` to
    learn who is calling them and whether that person is a professor. The
    checks are the same as for the student routes: the token must be
    current and the account must be active.

    Parameters
    ----------
    authorization : str | None
        Value of the ``Authorization`` header.

    Returns
    -------
    dict
        ``registration_number`` of the owner and ``role``, which is
        ``professor`` or ``student``.

    Raises
    ------
    HTTPException
        401 for an invalid, expired or revoked token, 403 for an inactive
        account.
    """
    claims = decode_bearer(authorization)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            registration_number = student_from_claims(cur, claims)
            role_row = repository.find_professor_role(cur, registration_number)
    is_professor = (
        role_row is not None
        and bool(role_row[1])
        and (role_row[0] or "").strip().lower() == "professor"
    )
    return {
        "registration_number": registration_number,
        "role": "professor" if is_professor else "student",
    }
