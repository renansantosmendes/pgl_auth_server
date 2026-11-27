import re

REGISTRATION_NUMBER_PATTERN = re.compile(r"[0-9]{5,20}")
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_BYTES = 72
COMMON_PASSWORDS = frozenset(
    {
        "12345678",
        "123456789",
        "1234567890",
        "password",
        "password1",
        "password123",
        "senha1234",
        "senha12345",
        "senhaforte",
        "qwerty123",
        "qwertyuiop",
        "abc12345",
        "abcd1234",
        "iloveyou",
        "admin123",
        "letmein123",
        "welcome123",
        "trustno1",
        "monkey123",
        "dragon123",
    }
)


def registration_number_problems(registration_number: str) -> list[str]:
    """Validate the format of a registration number.

    A registration number must contain only digits and have between 5 and
    20 of them.

    Parameters
    ----------
    registration_number : str
        Value informed by the student.

    Returns
    -------
    list[str]
        Human readable problems. The list is empty when the value is valid.

    Example
    -------
    >>> registration_number_problems("1234")
    ['A matrícula deve conter apenas números, com 5 a 20 dígitos.']
    """
    if REGISTRATION_NUMBER_PATTERN.fullmatch(registration_number):
        return []
    return ["A matrícula deve conter apenas números, com 5 a 20 dígitos."]


def email_problems(email: str) -> list[str]:
    """Validate the shape of an e-mail address.

    Parameters
    ----------
    email : str
        Address informed by the student.

    Returns
    -------
    list[str]
        Human readable problems. The list is empty when the address looks
        valid.

    Example
    -------
    >>> email_problems("aluno@pucminas.edu.br")
    []
    """
    if EMAIL_PATTERN.fullmatch(email.strip()):
        return []
    return ["Informe um e-mail válido."]


def password_problems(
    senha: str,
    registration_number: str,
) -> list[str]:
    """List every rule that a new password breaks.

    The rules are: at least 10 characters, at most 72 bytes (the bcrypt
    limit), one lowercase letter, one uppercase letter, one digit, one
    symbol, no registration number inside it, and not a common password.

    Parameters
    ----------
    senha : str
        Candidate password.
    registration_number : str
        Registration number of the student, which must not appear in the
        password.

    Returns
    -------
    list[str]
        Messages for the broken rules. The list is empty when the password
        is strong.

    Example
    -------
    >>> password_problems("Exemplo@2026", "12345")
    []
    """
    problems = []
    if len(senha) < MIN_PASSWORD_LENGTH:
        problems.append(
            f"A senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres."
        )
    if len(senha.encode("utf-8")) > MAX_PASSWORD_BYTES:
        problems.append(
            f"A senha deve ter no máximo {MAX_PASSWORD_BYTES} bytes."
        )
    if not any(char.islower() for char in senha):
        problems.append("A senha deve ter pelo menos uma letra minúscula.")
    if not any(char.isupper() for char in senha):
        problems.append("A senha deve ter pelo menos uma letra maiúscula.")
    if not any(char.isdigit() for char in senha):
        problems.append("A senha deve ter pelo menos um número.")
    if all(char.isalnum() for char in senha):
        problems.append("A senha deve ter pelo menos um símbolo (ex.: @, #, !).")
    if registration_number and registration_number in senha:
        problems.append("A senha não pode conter a matrícula.")
    if senha.lower() in COMMON_PASSWORDS:
        problems.append("Essa senha é muito comum. Escolha outra.")
    return problems
