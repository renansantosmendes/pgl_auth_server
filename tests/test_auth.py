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


def test_login_success(client, monkeypatch):
    password_hash = _password_hash("correct-password")
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((password_hash, True)))

    response = client.post(
        "/api/login", json={"matricula": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == int(TOKEN_TTL.total_seconds())

    decoded = jwt.decode(body["access_token"], "test-secret", algorithms=["HS256"])
    assert decoded["sub"] == "12345"


def test_login_unknown_matricula(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection(None))

    response = client.post(
        "/api/login", json={"matricula": "does-not-exist", "senha": "whatever"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Matrícula ou senha inválidos."


def test_login_wrong_password(client, monkeypatch):
    password_hash = _password_hash("correct-password")
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((password_hash, True)))

    response = client.post(
        "/api/login", json={"matricula": "12345", "senha": "wrong-password"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Matrícula ou senha inválidos."


def test_login_inactive_student(client, monkeypatch):
    password_hash = _password_hash("correct-password")
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((password_hash, False)))

    response = client.post(
        "/api/login", json={"matricula": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Cadastro do aluno está inativo."


def test_login_missing_fields(client):
    response = client.post("/api/login", json={"matricula": "12345"})

    assert response.status_code == 422


def test_register_success(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((True,)))

    response = client.post(
        "/api/register", json={"matricula": "12345", "senha": "new-password"}
    )

    assert response.status_code == 201
    assert response.json() == {
        "matricula": "12345",
        "message": "Student registered successfully.",
    }


def test_register_matricula_not_enrolled(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection(None))

    response = client.post(
        "/api/register", json={"matricula": "does-not-exist", "senha": "new-password"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Matrícula não encontrada ou inativa na disciplina."


def test_register_matricula_inactive_in_proxy(client, monkeypatch):
    monkeypatch.setattr(db, "get_connection", lambda: _mock_connection((False,)))

    response = client.post(
        "/api/register", json={"matricula": "12345", "senha": "new-password"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Matrícula não encontrada ou inativa na disciplina."


def test_register_duplicate_matricula(client, monkeypatch):
    connection = _mock_connection((True,))
    connection.cursor.return_value.execute.side_effect = [None, psycopg2.errors.UniqueViolation]
    monkeypatch.setattr(db, "get_connection", lambda: connection)

    response = client.post(
        "/api/register", json={"matricula": "12345", "senha": "new-password"}
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Matrícula já cadastrada."


def test_register_missing_fields(client):
    response = client.post("/api/register", json={"matricula": "12345"})

    assert response.status_code == 422
