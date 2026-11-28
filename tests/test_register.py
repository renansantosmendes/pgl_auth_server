import psycopg2
import pytest

from tests.conftest import use_database

STRONG = "Exemplo@2026"
VALID_BODY = {
    "registration_number": "12345",
    "email": "12345@pucminas.edu.br",
    "senha": STRONG,
    "senha_confirmacao": STRONG,
}


def enrollment_route(value):
    return ("login_id FROM pgl_proxy.students", value)


ENROLLED = enrollment_route((True, "12345@pucminas.edu.br"))


def test_register_sends_a_confirmation_and_creates_no_account(client, monkeypatch, sent_messages):
    database = use_database(monkeypatch, [ENROLLED])

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 202
    assert len(sent_messages) == 1
    assert sent_messages[0]["to"] == "12345@pucminas.edu.br"
    assert "/confirmar?token=" in sent_messages[0]["text"]
    assert database.statements_containing("INSERT INTO pgl_auth.pending_registrations")
    assert not database.statements_containing("INSERT INTO pgl_auth.students")


def test_register_stores_only_the_token_digest(client, monkeypatch, sent_messages):
    database = use_database(monkeypatch, [ENROLLED])

    client.post("/api/register", json=VALID_BODY)

    token = sent_messages[0]["text"].split("token=")[1].split()[0]
    saved = database.statements_containing("INSERT INTO pgl_auth.pending_registrations")[0][1]
    assert token not in saved
    assert len(saved[3]) == 64


def test_register_email_match_ignores_case_and_spaces(client, monkeypatch, sent_messages):
    use_database(monkeypatch, [enrollment_route((True, "12345@PUCMINAS.edu.br"))])
    body = dict(VALID_BODY, email="  12345@pucminas.edu.br ")

    assert client.post("/api/register", json=body).status_code == 202


@pytest.mark.parametrize("missing", ["email", "senha", "senha_confirmacao"])
def test_register_requires_every_mandatory_field(client, missing):
    body = {key: value for key, value in VALID_BODY.items() if key != missing}

    assert client.post("/api/register", json=body).status_code == 422


def test_register_rejects_mismatched_confirmation(client, monkeypatch, sent_messages):
    use_database(monkeypatch, [ENROLLED])
    body = dict(VALID_BODY, senha_confirmacao="Outro@2026xyz")

    response = client.post("/api/register", json=body)

    assert response.status_code == 422
    assert "As senhas não coincidem." in response.json()["detail"]["errors"]
    assert sent_messages == []


def test_register_rejects_weak_password_with_every_problem(client, monkeypatch, sent_messages):
    use_database(monkeypatch, [ENROLLED])
    body = dict(VALID_BODY, senha="abc", senha_confirmacao="abc")

    response = client.post("/api/register", json=body)

    detail = response.json()["detail"]
    assert response.status_code == 422
    assert len(detail["errors"]) >= 3


def test_register_rejects_non_numeric_registration_number(client):
    body = dict(VALID_BODY, registration_number="ab-123")

    response = client.post("/api/register", json=body)

    assert response.status_code == 422


def test_register_rejects_registration_number_with_four_digits(client):
    body = dict(VALID_BODY, registration_number="1234")

    assert client.post("/api/register", json=body).status_code == 422


def test_register_not_enrolled_is_forbidden(client, monkeypatch, sent_messages):
    use_database(monkeypatch, [enrollment_route(None)])

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 403
    assert response.json()["detail"] == "Matrícula não encontrada ou inativa na disciplina."
    assert sent_messages == []


def test_register_inactive_in_roster_is_forbidden(client, monkeypatch):
    use_database(monkeypatch, [enrollment_route((False, "12345@pucminas.edu.br"))])

    assert client.post("/api/register", json=VALID_BODY).status_code == 403


def test_register_email_that_does_not_match_roster_is_forbidden(client, monkeypatch, sent_messages):
    use_database(monkeypatch, [enrollment_route((True, "outra@pucminas.edu.br"))])

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 403
    assert "não confere" in response.json()["detail"]
    assert sent_messages == []


def test_register_for_an_existing_account_returns_conflict(client, monkeypatch, sent_messages):
    use_database(
        monkeypatch,
        [ENROLLED, ("SELECT password_hash, is_active, token_version", ("x", True, 0))],
    )

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 409
    assert response.json()["detail"] == "Matrícula já cadastrada."
    assert sent_messages == []


def test_register_fails_and_rolls_back_when_the_email_cannot_be_sent(client, monkeypatch):
    database = use_database(monkeypatch, [ENROLLED])

    def failing_send(recipient, subject, text):
        raise RuntimeError("provider down")

    monkeypatch.setattr("core.mailer.send_message", failing_send)

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 503
    assert database.outcomes[-1] == "rollback"


def test_register_duplicate_pending_request_is_accepted(client, monkeypatch, sent_messages):
    database = use_database(monkeypatch, [ENROLLED])

    client.post("/api/register", json=VALID_BODY)
    client.post("/api/register", json=VALID_BODY)

    assert len(sent_messages) == 2
    assert len(database.statements_containing("ON CONFLICT (registration_number) DO UPDATE SET")) == 2
