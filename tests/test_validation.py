import pytest

from core import validation


@pytest.mark.parametrize("registration_number", ["12345", "2021012345"])
def test_registration_number_accepts_five_to_twenty_digits(registration_number):
    assert validation.registration_number_problems(registration_number) == []


@pytest.mark.parametrize("registration_number", ["1234", "", "12a45", "12 345", "1" * 21])
def test_registration_number_rejects_bad_shapes(registration_number):
    assert validation.registration_number_problems(registration_number)


@pytest.mark.parametrize("email", ["aluno@pucminas.edu.br", "  a.b@c.com  "])
def test_email_accepts_common_addresses(email):
    assert validation.email_problems(email) == []


@pytest.mark.parametrize("email", ["", "sem-arroba.com", "a@b", "a b@c.com"])
def test_email_rejects_malformed_addresses(email):
    assert validation.email_problems(email)


def test_strong_password_has_no_problems():
    assert validation.password_problems("Exemplo@2026", "12345") == []


@pytest.mark.parametrize(
    ("senha", "fragment"),
    [
        ("Curta@1A", "pelo menos 10 caracteres"),
        ("exemplo@2026", "maiúscula"),
        ("EXEMPLO@2026", "minúscula"),
        ("Exemplo@Abc", "número"),
        ("Exemplo2026", "símbolo"),
        ("Exemplo@12345", "não pode conter a matrícula"),
    ],
)
def test_password_rules_report_each_broken_rule(senha, fragment):
    problems = validation.password_problems(senha, "12345")

    assert any(fragment in problem for problem in problems)


def test_password_rejects_more_than_72_bytes():
    senha = "Aa1@" + "x" * 80

    problems = validation.password_problems(senha, "12345")

    assert any("72 bytes" in problem for problem in problems)


def test_password_rejects_common_passwords():
    problems = validation.password_problems("Password123", "12345")

    assert any("muito comum" in problem for problem in problems)
