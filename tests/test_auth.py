from unittest.mock import MagicMock

import bcrypt
import jwt
import psycopg2
import pytest
from fastapi.testclient import TestClient

from api.application import app
from core import db
from core.config import TOKEN_TTL


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("NEON_DATABASE_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")


@pytest.fixture
def client():
    return TestClient(app)


def _mock_connection(fetchone_result):
    cursor = MagicMock()
    cursor.fetchone.return_value = fetchone_result
    cursor.__enter__.return_value = cursor
    cursor.__exit__.return_value = False

    connection = MagicMock()
    connection.cursor.return_value = cursor
    connection.__enter__.return_value = connection
    connection.__exit__.return_value = False
    return connection


def _password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _professor_token(registration_number: str = "prof-1") -> str:
    return jwt.encode({"sub": registration_number}, "test-secret", algorithm="HS256")


def test_login_success(client, monkeypatch):
    password_hash = _password_hash("correct-password")
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((password_hash, True)))

    response = client.post(
        "/api/login", json={"registration_number": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == int(TOKEN_TTL.total_seconds())

    decoded = jwt.decode(body["access_token"], "test-secret", algorithms=["HS256"])
    assert decoded["sub"] == "12345"


def test_login_unknown_registration_number(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection(None))

    response = client.post(
        "/api/login", json={"registration_number": "does-not-exist", "senha": "whatever"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Matrícula ou senha inválidos."


def test_login_wrong_password(client, monkeypatch):
    password_hash = _password_hash("correct-password")
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((password_hash, True)))

    response = client.post(
        "/api/login", json={"registration_number": "12345", "senha": "wrong-password"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Matrícula ou senha inválidos."


def test_login_inactive_student(client, monkeypatch):
    password_hash = _password_hash("correct-password")
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((password_hash, False)))

    response = client.post(
        "/api/login", json={"registration_number": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Cadastro do aluno está inativo."


def test_login_missing_fields(client):
    response = client.post("/api/login", json={"registration_number": "12345"})

    assert response.status_code == 422


def test_register_success(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((True,)))

    response = client.post(
        "/api/register", json={"registration_number": "12345", "senha": "new-password"}
    )

    assert response.status_code == 201
    assert response.json() == {
        "registration_number": "12345",
        "message": "Student registered successfully.",
    }


def test_register_not_enrolled(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection(None))

    response = client.post(
        "/api/register", json={"registration_number": "does-not-exist", "senha": "new-password"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Matrícula não encontrada ou inativa na disciplina."


def test_register_inactive_in_proxy(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((False,)))

    response = client.post(
        "/api/register", json={"registration_number": "12345", "senha": "new-password"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Matrícula não encontrada ou inativa na disciplina."


def test_register_duplicate(client, monkeypatch):
    connection = _mock_connection((True,))
    connection.cursor.return_value.execute.side_effect = [None, psycopg2.errors.UniqueViolation]
    monkeypatch.setattr(db, "get_connection", lambda: connection)

    response = client.post(
        "/api/register", json={"registration_number": "12345", "senha": "new-password"}
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Matrícula já cadastrada."


def test_register_missing_fields(client):
    response = client.post("/api/register", json={"registration_number": "12345"})

    assert response.status_code == 422


# --- POST /api/reset-password -------------------------------------------


def test_reset_password_success(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection(("Professor", True)))

    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": "brand-new-password"},
        headers={"Authorization": f"Bearer {_professor_token()}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "registration_number": "12345",
        "message": "Password reset successfully.",
    }


def test_reset_password_missing_token_returns_401(client):
    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": "brand-new-password"},
    )

    assert response.status_code == 401


def test_reset_password_invalid_token_returns_401(client):
    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": "brand-new-password"},
        headers={"Authorization": "Bearer not-a-real-jwt"},
    )

    assert response.status_code == 401


def test_reset_password_non_professor_returns_403(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection(("Aluno", True)))

    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": "brand-new-password"},
        headers={"Authorization": f"Bearer {_professor_token('student-1')}"},
    )

    assert response.status_code == 403


def test_reset_password_unknown_caller_returns_403(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection(None))

    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": "brand-new-password"},
        headers={"Authorization": f"Bearer {_professor_token('ghost')}"},
    )

    assert response.status_code == 403


def test_reset_password_inactive_professor_returns_403(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection(("Professor", False)))

    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": "brand-new-password"},
        headers={"Authorization": f"Bearer {_professor_token()}"},
    )

    assert response.status_code == 403


def test_reset_password_missing_fields(client):
    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345"},
        headers={"Authorization": f"Bearer {_professor_token()}"},
    )

    assert response.status_code == 422
