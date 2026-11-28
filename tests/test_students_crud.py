from datetime import datetime, timezone

from core import auth_tokens
from tests.conftest import bearer, password_hash, student_token, use_database

PROFESSOR_AUTH = ("SELECT password_hash, is_active, token_version", (password_hash("x"), True, 0))
PROFESSOR_ROLE = ("SELECT role, is_active FROM pgl_proxy.students", ("Professor", True))
STUDENT_ROLE = ("SELECT role, is_active FROM pgl_proxy.students", ("Aluno", True))
DETAIL = (
    "FROM pgl_proxy.students p",
    (
        "12345",
        "9f0c2a3e-1b2c-4d5e-8f90-123456789abc",
        True,
        2,
        None,
        "Ana Souza",
        "12345@pucminas.edu.br",
        "SIS-1",
        "IA Generativa",
        "Aluno",
        True,
        datetime(2026, 11, 1, tzinfo=timezone.utc),
        True,
    ),
)


def professor_headers():
    return bearer(auth_tokens.issue_token("prof-1", 0))


def test_detail_returns_every_column_without_the_password_hash(client, monkeypatch):
    use_database(monkeypatch, [PROFESSOR_AUTH, PROFESSOR_ROLE, DETAIL])

    response = client.get("/api/professor/students/12345", headers=professor_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "9f0c2a3e-1b2c-4d5e-8f90-123456789abc"
    assert body["is_active"] is True
    assert body["token_version"] == 2
    assert body["login_id"] == "12345@pucminas.edu.br"
    assert body["has_password"] is True
    assert "password_hash" not in body


def test_detail_for_student_not_on_roster_returns_404(client, monkeypatch):
    use_database(monkeypatch, [PROFESSOR_AUTH, PROFESSOR_ROLE])

    response = client.get("/api/professor/students/99999", headers=professor_headers())

    assert response.status_code == 404


def test_detail_without_token_returns_401(client):
    assert client.get("/api/professor/students/12345").status_code == 401


def test_detail_by_a_student_returns_403(client, monkeypatch):
    use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", (password_hash("x"), True, 0)), STUDENT_ROLE],
    )

    response = client.get("/api/professor/students/12345", headers=bearer(student_token("s-1")))

    assert response.status_code == 403


def test_delete_removes_the_account_and_records_the_action(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [PROFESSOR_AUTH, PROFESSOR_ROLE, ("DELETE FROM pgl_auth.students", None)],
    )

    response = client.delete("/api/professor/students/12345", headers=professor_headers())

    assert response.status_code == 200
    assert database.statements_containing("DELETE FROM pgl_auth.students")
    assert database.statements_containing("INSERT INTO pgl_auth.audit_log")


def test_delete_without_account_returns_404(client, monkeypatch):
    use_database(monkeypatch, [PROFESSOR_AUTH, PROFESSOR_ROLE])

    response = client.delete("/api/professor/students/12345", headers=professor_headers())

    assert response.status_code == 404


def test_delete_by_a_student_returns_403(client, monkeypatch):
    use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", (password_hash("x"), True, 0)), STUDENT_ROLE],
    )

    response = client.delete("/api/professor/students/12345", headers=bearer(student_token("s-1")))

    assert response.status_code == 403
