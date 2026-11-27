import jwt
import pytest

from core import db
from tests.conftest import SECRET, bearer, expired_token, password_hash, student_token, use_database

NEW_PASSWORD = "Novo@Senha2026"


def auth_row(senha="Atual@Senha2026", is_active=True, version=0):
    return (password_hash(senha), is_active, version)


def test_logout_revokes_the_session(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row())],
    )

    response = client.post("/api/logout", headers=bearer(student_token()))

    assert response.status_code == 200
    assert database.statements_containing("SET token_version = token_version + 1")


def test_token_is_rejected_after_logout(client, monkeypatch):
    use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row(version=1))],
    )

    response = client.post("/api/logout", headers=bearer(student_token(version=0)))

    assert response.status_code == 401


def test_logout_without_token_returns_401(client):
    response = client.post("/api/logout")

    assert response.status_code == 401


def test_logout_with_expired_token_returns_401(client):
    response = client.post("/api/logout", headers=bearer(expired_token()))

    assert response.status_code == 401


def test_change_password_success_returns_new_token(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row(version=2))],
    )

    response = client.post(
        "/api/password/change",
        json={"senha_atual": "Atual@Senha2026", "nova_senha": NEW_PASSWORD},
        headers=bearer(student_token(version=2)),
    )

    assert response.status_code == 200
    claims = jwt.decode(response.json()["access_token"], SECRET, algorithms=["HS256"])
    assert claims["sub"] == "12345"
    assert database.statements_containing("ON CONFLICT (registration_number) DO UPDATE SET")


def test_change_password_wrong_current_password_returns_401(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row())],
    )

    response = client.post(
        "/api/password/change",
        json={"senha_atual": "errada", "nova_senha": NEW_PASSWORD},
        headers=bearer(student_token()),
    )

    assert response.status_code == 401
    assert database.statements_containing("INSERT INTO pgl_auth.login_attempts")


def test_change_password_rejects_weak_new_password(client, monkeypatch):
    use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row())],
    )

    response = client.post(
        "/api/password/change",
        json={"senha_atual": "Atual@Senha2026", "nova_senha": "fraca"},
        headers=bearer(student_token()),
    )

    assert response.status_code == 422


def test_change_password_is_blocked_while_locked(client, monkeypatch):
    from datetime import datetime, timedelta, timezone

    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    use_database(
        monkeypatch,
        [
            ("SELECT locked_until FROM pgl_auth.login_attempts", (future,)),
            ("SELECT password_hash, is_active, token_version", auth_row()),
        ],
    )

    response = client.post(
        "/api/password/change",
        json={"senha_atual": "Atual@Senha2026", "nova_senha": NEW_PASSWORD},
        headers=bearer(student_token()),
    )

    assert response.status_code == 429


def test_change_password_inactive_account_is_forbidden(client, monkeypatch):
    use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row(is_active=False))],
    )

    response = client.post(
        "/api/password/change",
        json={"senha_atual": "Atual@Senha2026", "nova_senha": NEW_PASSWORD},
        headers=bearer(student_token()),
    )

    assert response.status_code == 403


def test_change_password_without_token_returns_401(client):
    response = client.post(
        "/api/password/change",
        json={"senha_atual": "x", "nova_senha": NEW_PASSWORD},
    )

    assert response.status_code == 401


def test_change_password_missing_fields_returns_422(client):
    response = client.post(
        "/api/password/change",
        json={"senha_atual": "x"},
        headers=bearer(student_token()),
    )

    assert response.status_code == 422
