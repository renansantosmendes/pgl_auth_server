import re
from datetime import datetime, timedelta, timezone

import pytest

from core import security
from tests.conftest import SECRET, use_database

ENROLLED_ROUTE = ("login_id FROM pgl_proxy.students", (True, "12345@pucminas.edu.br"))
NEW_PASSWORD = "Nova@Senha2026"
KNOWN_CODE = "123456"


def stored_code(attempts=0, expires_in=timedelta(minutes=15), created_ago=timedelta(minutes=5)):
    now = datetime.now(timezone.utc)
    return (
        security.hash_reset_code(KNOWN_CODE, "12345", SECRET),
        now + expires_in,
        attempts,
        now - created_ago,
    )


def code_route(value):
    return ("SELECT code_hash, expires_at, attempts, created_at", value)


def extract_code(message_text):
    return re.search(r"\b(\d{6})\b", message_text).group(1)


def test_forgot_sends_code_to_institutional_email(client, monkeypatch, sent_messages):
    database = use_database(monkeypatch, [ENROLLED_ROUTE])

    response = client.post("/api/password/forgot", json={"registration_number": "12345"})

    assert response.status_code == 202
    assert len(sent_messages) == 1
    assert sent_messages[0]["to"] == "12345@pucminas.edu.br"
    code = extract_code(sent_messages[0]["text"])
    saved = database.statements_containing("INSERT INTO pgl_auth.password_reset_codes")
    assert saved[0][1][1] == security.hash_reset_code(code, "12345", SECRET)


def test_forgot_response_does_not_reveal_unknown_registration_numbers(
    client, monkeypatch, sent_messages
):
    use_database(monkeypatch, [("login_id FROM pgl_proxy.students", None)])

    response = client.post("/api/password/forgot", json={"registration_number": "99999"})

    assert response.status_code == 202
    assert sent_messages == []


def test_forgot_skips_students_without_email_login(client, monkeypatch, sent_messages):
    use_database(monkeypatch, [("login_id FROM pgl_proxy.students", (True, "ID-SEM-ARROBA"))])

    response = client.post("/api/password/forgot", json={"registration_number": "12345"})

    assert response.status_code == 202
    assert sent_messages == []


def test_forgot_respects_the_resend_cooldown(client, monkeypatch, sent_messages):
    use_database(monkeypatch, [ENROLLED_ROUTE, code_route(stored_code(created_ago=timedelta(seconds=10)))])

    response = client.post("/api/password/forgot", json={"registration_number": "12345"})

    assert response.status_code == 202
    assert sent_messages == []


def test_forgot_rolls_back_when_the_email_fails(client, monkeypatch, sent_messages):
    database = use_database(monkeypatch, [ENROLLED_ROUTE])

    def failing_send(recipient, subject, text):
        raise RuntimeError("provider down")

    monkeypatch.setattr("core.mailer.send_message", failing_send)

    response = client.post("/api/password/forgot", json={"registration_number": "12345"})

    assert response.status_code == 202
    assert database.outcomes[-1] == "rollback"


def test_forgot_rejects_invalid_registration_number(client):
    response = client.post("/api/password/forgot", json={"registration_number": "12"})

    assert response.status_code == 422


def test_reset_with_valid_code_replaces_the_password(client, monkeypatch):
    database = use_database(monkeypatch, [ENROLLED_ROUTE, code_route(stored_code())])

    response = client.post(
        "/api/password/reset",
        json={"registration_number": "12345", "codigo": KNOWN_CODE, "nova_senha": NEW_PASSWORD},
    )

    assert response.status_code == 200
    assert database.statements_containing("ON CONFLICT (registration_number) DO UPDATE SET")
    assert database.statements_containing("DELETE FROM pgl_auth.password_reset_codes")


def test_reset_with_wrong_code_counts_the_attempt(client, monkeypatch):
    database = use_database(monkeypatch, [ENROLLED_ROUTE, code_route(stored_code()), ("RETURNING attempts", (1,))])

    response = client.post(
        "/api/password/reset",
        json={"registration_number": "12345", "codigo": "000000", "nova_senha": NEW_PASSWORD},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Código inválido ou expirado."
    assert database.statements_containing("RETURNING attempts")


def test_reset_discards_the_code_after_too_many_wrong_attempts(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [ENROLLED_ROUTE, code_route(stored_code(attempts=4)), ("RETURNING attempts", (5,))],
    )

    response = client.post(
        "/api/password/reset",
        json={"registration_number": "12345", "codigo": "000000", "nova_senha": NEW_PASSWORD},
    )

    assert response.status_code == 400
    assert database.statements_containing("DELETE FROM pgl_auth.password_reset_codes")


def test_reset_rejects_expired_code(client, monkeypatch):
    database = use_database(
        monkeypatch,
        [ENROLLED_ROUTE, code_route(stored_code(expires_in=-timedelta(minutes=1)))],
    )

    response = client.post(
        "/api/password/reset",
        json={"registration_number": "12345", "codigo": KNOWN_CODE, "nova_senha": NEW_PASSWORD},
    )

    assert response.status_code == 400
    assert database.statements_containing("DELETE FROM pgl_auth.password_reset_codes")


def test_reset_without_pending_code_is_rejected(client, monkeypatch):
    use_database(monkeypatch, [ENROLLED_ROUTE])

    response = client.post(
        "/api/password/reset",
        json={"registration_number": "12345", "codigo": KNOWN_CODE, "nova_senha": NEW_PASSWORD},
    )

    assert response.status_code == 400


def test_reset_is_rejected_for_students_not_enrolled(client, monkeypatch):
    use_database(monkeypatch, [("login_id FROM pgl_proxy.students", None)])

    response = client.post(
        "/api/password/reset",
        json={"registration_number": "12345", "codigo": KNOWN_CODE, "nova_senha": NEW_PASSWORD},
    )

    assert response.status_code == 400


def test_reset_checks_password_strength_before_the_code(client, monkeypatch):
    use_database(monkeypatch, [ENROLLED_ROUTE, code_route(stored_code())])

    response = client.post(
        "/api/password/reset",
        json={"registration_number": "12345", "codigo": KNOWN_CODE, "nova_senha": "fraca"},
    )

    assert response.status_code == 422


@pytest.mark.parametrize("missing", ["codigo", "nova_senha"])
def test_reset_requires_code_and_new_password(client, missing):
    body = {"registration_number": "12345", "codigo": KNOWN_CODE, "nova_senha": NEW_PASSWORD}
    del body[missing]

    response = client.post("/api/password/reset", json=body)

    assert response.status_code == 422
