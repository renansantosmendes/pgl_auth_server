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
ENROLLED = ("ENROLLED", (True, "12345@pucminas.edu.br"))


def enrollment_route(value):
    return ("login_id FROM pgl_proxy.students", value)


def test_register_success_with_every_field(client, monkeypatch):
    database = use_database(monkeypatch, [enrollment_route((True, "12345@pucminas.edu.br"))])

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 201
    assert response.json()["registration_number"] == "12345"
    assert database.statements_containing("INSERT INTO pgl_auth.students")
    assert database.statements_containing("INSERT INTO pgl_auth.audit_log")


def test_register_email_match_ignores_case_and_spaces(client, monkeypatch):
    use_database(monkeypatch, [enrollment_route((True, "12345@PUCMINAS.edu.br"))])
    body = dict(VALID_BODY, email="  12345@pucminas.edu.br ")

    response = client.post("/api/register", json=body)

    assert response.status_code == 201


@pytest.mark.parametrize("missing", ["email", "senha", "senha_confirmacao"])
def test_register_requires_every_mandatory_field(client, missing):
    body = {key: value for key, value in VALID_BODY.items() if key != missing}

    response = client.post("/api/register", json=body)

    assert response.status_code == 422


def test_register_rejects_mismatched_confirmation(client, monkeypatch):
    use_database(monkeypatch, [enrollment_route((True, "12345@pucminas.edu.br"))])
    body = dict(VALID_BODY, senha_confirmacao="Outro@2026xyz")

    response = client.post("/api/register", json=body)

    assert response.status_code == 422
    assert "As senhas não coincidem." in response.json()["detail"]["errors"]


def test_register_rejects_weak_password_with_every_problem(client, monkeypatch):
    use_database(monkeypatch, [enrollment_route((True, "12345@pucminas.edu.br"))])
    body = dict(VALID_BODY, senha="abc", senha_confirmacao="abc")

    response = client.post("/api/register", json=body)

    detail = response.json()["detail"]
    assert response.status_code == 422
    assert detail["message"] == "Dados inválidos para a operação."
    assert len(detail["errors"]) >= 3


def test_register_rejects_non_numeric_registration_number(client):
    body = dict(VALID_BODY, registration_number="ab-123")

    response = client.post("/api/register", json=body)

    assert response.status_code == 422
    assert any("apenas números" in error for error in response.json()["detail"]["errors"])


def test_register_rejects_registration_number_with_four_digits(client):
    body = dict(VALID_BODY, registration_number="1234")

    response = client.post("/api/register", json=body)

    assert response.status_code == 422


def test_register_not_enrolled_is_forbidden(client, monkeypatch):
    use_database(monkeypatch, [enrollment_route(None)])

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 403
    assert response.json()["detail"] == "Matrícula não encontrada ou inativa na disciplina."


def test_register_inactive_in_roster_is_forbidden(client, monkeypatch):
    use_database(monkeypatch, [enrollment_route((False, "12345@pucminas.edu.br"))])

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 403


def test_register_email_that_does_not_match_roster_is_forbidden(client, monkeypatch):
    use_database(monkeypatch, [enrollment_route((True, "outra@pucminas.edu.br"))])

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 403
    assert "não confere" in response.json()["detail"]


def test_register_duplicate_returns_conflict(client, monkeypatch):
    use_database(
        monkeypatch,
        [
            enrollment_route((True, "12345@pucminas.edu.br")),
            (
                "INSERT INTO pgl_auth.students",
                psycopg2.errors.UniqueViolation,
            ),
        ],
    )

    response = client.post("/api/register", json=VALID_BODY)

    assert response.status_code == 409
    assert response.json()["detail"] == "Matrícula já cadastrada."
