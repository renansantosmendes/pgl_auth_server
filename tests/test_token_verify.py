from tests.conftest import bearer, password_hash, student_token, use_database

ACTIVE_AUTH = ("SELECT password_hash, is_active, token_version", (password_hash("x"), True, 0))
STUDENT_ROLE = ("SELECT role, is_active FROM pgl_proxy.students", ("Aluno", True))
PROFESSOR_ROLE = ("SELECT role, is_active FROM pgl_proxy.students", ("Professor", True))


def test_verify_returns_student_identity(client, monkeypatch):
    use_database(monkeypatch, [ACTIVE_AUTH, STUDENT_ROLE])

    response = client.get("/api/token/verify", headers=bearer(student_token("12345")))

    assert response.status_code == 200
    assert response.json() == {"registration_number": "12345", "role": "student"}


def test_verify_returns_professor_identity(client, monkeypatch):
    use_database(monkeypatch, [ACTIVE_AUTH, PROFESSOR_ROLE])

    response = client.get("/api/token/verify", headers=bearer(student_token("prof-1")))

    assert response.json()["role"] == "professor"


def test_verify_rejects_a_revoked_token(client, monkeypatch):
    use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", (password_hash("x"), True, 2))],
    )

    response = client.get("/api/token/verify", headers=bearer(student_token(version=0)))

    assert response.status_code == 401


def test_verify_rejects_an_inactive_account(client, monkeypatch):
    use_database(
        monkeypatch,
        [("SELECT password_hash, is_active, token_version", (password_hash("x"), False, 0))],
    )

    response = client.get("/api/token/verify", headers=bearer(student_token()))

    assert response.status_code == 403


def test_verify_without_token_returns_401(client):
    response = client.get("/api/token/verify")

    assert response.status_code == 401
