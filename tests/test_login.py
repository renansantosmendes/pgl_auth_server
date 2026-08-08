from unittest.mock import MagicMock

import bcrypt
import jwt
import pytest
from fastapi.testclient import TestClient

from api import login


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("NEON_DATABASE_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")


@pytest.fixture
def client():
    return TestClient(login.app)


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


def test_login_success(client, monkeypatch):
    password_hash = _password_hash("correct-password")
    monkeypatch.setattr(
        login, "_get_connection", lambda: _mock_connection((password_hash, True))
    )

    response = client.post(
        "/api/login", json={"matricula": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == int(login.TOKEN_TTL.total_seconds())

    decoded = jwt.decode(body["access_token"], "test-secret", algorithms=["HS256"])
    assert decoded["sub"] == "12345"


def test_login_unknown_matricula(client, monkeypatch):
    monkeypatch.setattr(login, "_get_connection", lambda: _mock_connection(None))

    response = client.post(
        "/api/login", json={"matricula": "does-not-exist", "senha": "whatever"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Matrícula ou senha inválidos."


def test_login_wrong_password(client, monkeypatch):
    password_hash = _password_hash("correct-password")
    monkeypatch.setattr(
        login, "_get_connection", lambda: _mock_connection((password_hash, True))
    )

    response = client.post(
        "/api/login", json={"matricula": "12345", "senha": "wrong-password"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Matrícula ou senha inválidos."


def test_login_inactive_student(client, monkeypatch):
    password_hash = _password_hash("correct-password")
    monkeypatch.setattr(
        login, "_get_connection", lambda: _mock_connection((password_hash, False))
    )

    response = client.post(
        "/api/login", json={"matricula": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Cadastro do aluno está inativo."


def test_login_missing_fields(client):
    response = client.post("/api/login", json={"matricula": "12345"})

    assert response.status_code == 422
