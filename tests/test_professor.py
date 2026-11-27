import jwt

from core import auth_tokens
from tests.conftest import bearer, password_hash, student_token, use_database

NEW_PASSWORD = "Novo@Senha2026"
PROFESSOR_AUTH = ("SELECT password_hash, is_active, token_version", (password_hash("x"), True, 0))
PROFESSOR_ROLE = ("SELECT role, is_active FROM pgl_proxy.students", ("Professor", True))
STUDENT_ROLE = ("SELECT role, is_active FROM pgl_proxy.students", ("Aluno", True))


def professor_headers():
    return bearer(auth_tokens.issue_token("prof-1", 0))


def test_professor_resets_student_password(client, monkeypatch):
    database = use_database(monkeypatch, [PROFESSOR_AUTH, PROFESSOR_ROLE])

    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": NEW_PASSWORD},
        headers=professor_headers(),
    )

    assert response.status_code == 200
    assert response.json() == {
        "registration_number": "12345",
        "message": "Password reset successfully.",
    }
    assert database.statements_containing("ON CONFLICT (registration_number) DO UPDATE SET")
    assert database.statements_containing("INSERT INTO pgl_auth.audit_log")


def test_reset_password_rejects_weak_password(client, monkeypatch):
    use_database(monkeypatch, [PROFESSOR_AUTH, PROFESSOR_ROLE])

    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": "fraca"},
        headers=professor_headers(),
    )

    assert response.status_code == 422


def test_reset_password_without_token_returns_401(client):
    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": NEW_PASSWORD},
    )

    assert response.status_code == 401


def test_reset_password_with_invalid_token_returns_401(client):
    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": NEW_PASSWORD},
        headers={"Authorization": "Bearer not-a-real-jwt"},
    )

    assert response.status_code == 401


def test_reset_password_by_student_returns_403(client, monkeypatch):
    use_database(
        monkeypatch,
        [
            ("SELECT password_hash, is_active, token_version", (password_hash("x"), True, 0)),
            STUDENT_ROLE,
        ],
    )

    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": NEW_PASSWORD},
        headers=bearer(student_token("student-1")),
    )

    assert response.status_code == 403


def test_reset_password_by_unknown_caller_returns_403(client, monkeypatch):
    use_database(monkeypatch, [])

    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": NEW_PASSWORD},
        headers=bearer(auth_tokens.issue_token("ghost", 0)),
    )

    assert response.status_code == 403


def test_inactive_professor_returns_403(client, monkeypatch):
    use_database(
        monkeypatch,
        [PROFESSOR_AUTH, ("SELECT role, is_active FROM pgl_proxy.students", ("Professor", False))],
    )

    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345", "new_senha": NEW_PASSWORD},
        headers=professor_headers(),
    )

    assert response.status_code == 403


def test_reset_password_missing_fields_returns_422(client):
    response = client.post(
        "/api/reset-password",
        json={"registration_number": "12345"},
        headers=professor_headers(),
    )

    assert response.status_code == 422


def test_professor_lists_students_with_account_state(client, monkeypatch):
    use_database(
        monkeypatch,
        [
            PROFESSOR_AUTH,
            PROFESSOR_ROLE,
            (
                "FROM pgl_proxy.students p",
                [("12345", "Ana", "12345@pucminas.edu.br", True, True, True),
                 ("67890", "Bruno", None, True, False, None)],
            ),
        ],
    )

    response = client.get("/api/professor/students", headers=professor_headers())

    assert response.status_code == 200
    students = response.json()["students"]
    assert students[0]["has_password"] is True
    assert students[1]["has_password"] is False
    assert students[1]["login_id"] is None


def test_professor_blocks_a_student_account(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [PROFESSOR_AUTH, PROFESSOR_ROLE, ("UPDATE pgl_auth.students SET is_active", None)],
    )

    response = client.post(
        "/api/professor/students/12345/status",
        json={"is_active": False},
        headers=professor_headers(),
    )

    assert response.status_code == 200
    assert response.json() == {"registration_number": "12345", "is_active": False}
    assert database.statements_containing("INSERT INTO pgl_auth.audit_log")


def test_status_change_for_student_without_password_returns_404(client, monkeypatch):
    use_database(monkeypatch, [PROFESSOR_AUTH, PROFESSOR_ROLE])

    response = client.post(
        "/api/professor/students/12345/status",
        json={"is_active": True},
        headers=professor_headers(),
    )

    assert response.status_code == 404


def test_invitations_report_sent_and_skipped_students(client, monkeypatch, sent_messages):
    def enrollment(params):
        registration_number = params[0]
        rows = {
            "12345": (True, "12345@pucminas.edu.br"),
            "67890": (True, "ID-SEM-ARROBA"),
            "11111": (True, "11111@pucminas.edu.br"),
            "22222": None,
        }
        return rows.get(registration_number)

    def auth_row(params):
        if params[0] == "prof-1":
            return (password_hash("x"), True, 0)
        if params[0] == "11111":
            return (password_hash("x"), True, 0)
        return None

    use_database(
        monkeypatch,
        [
            ("SELECT password_hash, is_active, token_version", auth_row),
            PROFESSOR_ROLE,
            ("login_id FROM pgl_proxy.students", enrollment),
            ("SELECT password_hash, is_active, token_version", auth_row),
            ("SELECT code_hash, expires_at, attempts, created_at", None),
        ],
    )

    response = client.post(
        "/api/professor/invitations",
        json={"registration_numbers": ["12345", "67890", "11111", "22222", "abc", "12345"]},
        headers=professor_headers(),
    )

    body = response.json()
    assert response.status_code == 200
    assert body["sent"] == ["12345"]
    reasons = {item["registration_number"]: item["reason"] for item in body["skipped"]}
    assert reasons["67890"] == "sem e-mail institucional cadastrado"
    assert reasons["11111"] == "já possui senha cadastrada"
    assert reasons["22222"] == "não matriculado ou inativo na disciplina"
    assert reasons["abc"] == "matrícula inválida"
    assert len(sent_messages) == 1
    assert "Crie sua senha" in sent_messages[0]["subject"]


def test_invitations_report_delivery_failures(client, monkeypatch):
    def failing_send(recipient, subject, text):
        raise RuntimeError("provider down")

    monkeypatch.setattr("core.mailer.send_message", failing_send)
    use_database(
        monkeypatch,
        [
            (
                "SELECT password_hash, is_active, token_version",
                lambda params: (password_hash("x"), True, 0) if params[0] == "prof-1" else None,
            ),
            PROFESSOR_ROLE,
            ("login_id FROM pgl_proxy.students", (True, "12345@pucminas.edu.br")),
            ("SELECT code_hash, expires_at, attempts, created_at", None),
        ],
    )

    response = client.post(
        "/api/professor/invitations",
        json={"registration_numbers": ["12345"]},
        headers=professor_headers(),
    )

    assert response.json()["skipped"][0]["reason"] == "falha ao enviar o e-mail"


def test_invitations_reject_empty_batches(client):
    response = client.post(
        "/api/professor/invitations",
        json={"registration_numbers": []},
        headers=professor_headers(),
    )

    assert response.status_code == 422
