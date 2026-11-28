from datetime import datetime, timedelta, timezone

from core import security
from tests.conftest import password_hash, use_database

TOKEN = "token-of-the-test"
TOKEN_HASH = security.hash_confirmation_token(TOKEN)


def pending_route(expires_in=timedelta(minutes=10), token_hash=TOKEN_HASH):
    expires_at = datetime.now(timezone.utc) + expires_in
    return (
        "SELECT registration_number, email, password_hash, expires_at",
        ("12345", "12345@pucminas.edu.br", password_hash(STRONG), expires_at)
        if token_hash == TOKEN_HASH
        else None,
    )


STRONG = "Exemplo@2026"
ENROLLED = ("login_id FROM pgl_proxy.students", (True, "12345@pucminas.edu.br"))


def test_confirmation_creates_the_account_once(client, monkeypatch):
    database = use_database(monkeypatch, [pending_route(), ENROLLED])

    response = client.post("/api/register/confirm", json={"token": TOKEN})

    assert response.status_code == 201
    assert response.json() == {"registration_number": "12345", "message": "Student registered successfully."}
    assert database.statements_containing("INSERT INTO pgl_auth.students")
    assert database.statements_containing("DELETE FROM pgl_auth.pending_registrations")


def test_unknown_or_used_link_is_rejected(client, monkeypatch):
    database = use_database(monkeypatch, [pending_route(token_hash="other")])

    response = client.post("/api/register/confirm", json={"token": "wrong"})

    assert response.status_code == 400
    assert response.json()["detail"] == "Link inválido ou já utilizado."
    assert not database.statements_containing("INSERT INTO pgl_auth.students")


def test_expired_link_is_rejected_and_discarded(client, monkeypatch):
    database = use_database(monkeypatch, [pending_route(expires_in=-timedelta(seconds=1))])

    response = client.post("/api/register/confirm", json={"token": TOKEN})

    assert response.status_code == 400
    assert "expirado" in response.json()["detail"]
    assert not database.statements_containing("INSERT INTO pgl_auth.students")
    assert database.statements_containing("DELETE FROM pgl_auth.pending_registrations")


def test_link_is_rejected_when_the_student_is_no_longer_enrolled(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [pending_route(), ("login_id FROM pgl_proxy.students", (False, "12345@pucminas.edu.br"))],
    )

    response = client.post("/api/register/confirm", json={"token": TOKEN})

    assert response.status_code == 403
    assert not database.statements_containing("INSERT INTO pgl_auth.students")


def test_link_is_rejected_when_an_account_already_exists(client, monkeypatch):
    use_database(
        monkeypatch,
        [
            pending_route(),
            ENROLLED,
            ("SELECT password_hash, is_active, token_version", ("x", True, 0)),
        ],
    )

    response = client.post("/api/register/confirm", json={"token": TOKEN})

    assert response.status_code == 409


def test_confirmation_requires_a_token(client):
    assert client.post("/api/register/confirm", json={}).status_code == 422
