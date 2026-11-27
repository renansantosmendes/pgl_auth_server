from datetime import datetime, timedelta, timezone

import jwt

from tests.conftest import SECRET, password_hash, use_database


def auth_row(senha="correct-password", is_active=True, version=0):
    return (password_hash(senha), is_active, version)


def test_login_success_issues_token_with_version(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row(version=3))],
    )

    response = client.post(
        "/api/login", json={"registration_number": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    claims = jwt.decode(body["access_token"], SECRET, algorithms=["HS256"])
    assert claims["sub"] == "12345"
    assert claims["ver"] == 3
    assert database.statements_containing("INSERT INTO pgl_auth.audit_log")


def test_login_success_clears_failed_attempts(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row())],
    )

    client.post("/api/login", json={"registration_number": "12345", "senha": "correct-password"})

    assert database.statements_containing("DELETE FROM pgl_auth.login_attempts")


def test_login_unknown_registration_number_is_rejected_and_counted(client, monkeypatch):
    database = use_database(monkeypatch, [])

    response = client.post(
        "/api/login", json={"registration_number": "99999", "senha": "whatever"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Matrícula ou senha inválidos."
    assert database.statements_containing("INSERT INTO pgl_auth.login_attempts")


def test_login_wrong_password_is_rejected_and_counted(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row())],
    )

    response = client.post(
        "/api/login", json={"registration_number": "12345", "senha": "wrong-password"}
    )

    assert response.status_code == 401
    assert database.statements_containing("INSERT INTO pgl_auth.login_attempts")
    assert database.outcomes[-1] == "commit"


def test_login_inactive_student_is_forbidden(client, monkeypatch):
    use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row(is_active=False))],
    )

    response = client.post(
        "/api/login", json={"registration_number": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Cadastro do aluno está inativo."


def test_login_accepts_passwords_created_before_the_strength_rules(client, monkeypatch):
    use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", auth_row(senha="abc"))],
    )

    response = client.post("/api/login", json={"registration_number": "12345", "senha": "abc"})

    assert response.status_code == 200


def test_login_is_locked_while_the_lock_is_active(client, monkeypatch):
    future = datetime.now(timezone.utc) + timedelta(minutes=10)
    use_database(
        monkeypatch,
        [
            ("SELECT locked_until FROM pgl_auth.login_attempts", (future,)),
            ("SELECT password_hash, is_active, token_version", auth_row()),
        ],
    )

    response = client.post(
        "/api/login", json={"registration_number": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 429


def test_login_works_again_after_the_lock_expires(client, monkeypatch):
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    use_database(
        monkeypatch,
        [
            ("SELECT locked_until FROM pgl_auth.login_attempts", (past,)),
            ("SELECT password_hash, is_active, token_version", auth_row()),
        ],
    )

    response = client.post(
        "/api/login", json={"registration_number": "12345", "senha": "correct-password"}
    )

    assert response.status_code == 200


def test_login_missing_fields_returns_422(client):
    response = client.post("/api/login", json={"registration_number": "12345"})

    assert response.status_code == 422
