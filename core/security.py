import hashlib
import hmac
import secrets

import bcrypt

RESET_CODE_LENGTH = 6


def hash_password(senha: str) -> str:
    """Hash a password with bcrypt.

    Parameters
    ----------
    senha : str
        Plain-text password.

    Returns
    -------
    str
        bcrypt hash, safe to store in the database.

    Example
    -------
    >>> hash_password("Exemplo@2026").startswith("$2b$")
    True
    """
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(senha: str, password_hash: str) -> bool:
    """Check a plain-text password against a stored bcrypt hash.

    Parameters
    ----------
    senha : str
        Plain-text password sent by the client.
    password_hash : str
        bcrypt hash stored in the database.

    Returns
    -------
    bool
        True when the password matches the hash.
    """
    return bcrypt.checkpw(senha.encode("utf-8"), password_hash.encode("utf-8"))


def generate_reset_code() -> str:
    """Create a random numeric code for password reset e-mails.

    Returns
    -------
    str
        Code with ``RESET_CODE_LENGTH`` digits, drawn from ``secrets``.

    Example
    -------
    >>> len(generate_reset_code()) == RESET_CODE_LENGTH
    True
    """
    return "".join(str(secrets.randbelow(10)) for _ in range(RESET_CODE_LENGTH))


def hash_reset_code(
    code: str,
    registration_number: str,
    secret: str,
) -> str:
    """Compute the keyed hash stored for a reset code.

    The code is bound to the registration number and to the server secret,
    so a leaked table cannot be brute-forced offline without the secret.

    Parameters
    ----------
    code : str
        Numeric code sent by e-mail.
    registration_number : str
        Student the code belongs to.
    secret : str
        Server secret, read from ``JWT_SECRET_KEY``.

    Returns
    -------
    str
        Hexadecimal HMAC-SHA256 digest.

    Example
    -------
    >>> len(hash_reset_code("123456", "12345", "secret")) == 64
    True
    """
    message = f"{registration_number}:{code}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def reset_code_matches(
    code: str,
    registration_number: str,
    secret: str,
    expected_hash: str,
) -> bool:
    """Compare a submitted reset code with the stored keyed hash.

    Parameters
    ----------
    code : str
        Code typed by the student.
    registration_number : str
        Student the code was issued for.
    secret : str
        Server secret, read from ``JWT_SECRET_KEY``.
    expected_hash : str
        Hash stored when the code was issued.

    Returns
    -------
    bool
        True when the code matches, compared in constant time.
    """
    computed = hash_reset_code(code, registration_number, secret)
    return hmac.compare_digest(computed, expected_hash)


def new_confirmation_token() -> str:
    """Create the random token carried by a registration confirmation link.

    Returns
    -------
    str
        URL-safe token with 256 bits of randomness.

    Example
    -------
    >>> len(new_confirmation_token()) > 40
    True
    """
    return secrets.token_urlsafe(32)


def hash_confirmation_token(token: str) -> str:
    """Compute the digest stored for a confirmation token.

    Only the digest is stored, so a leaked table does not reveal the links.

    Parameters
    ----------
    token : str
        Token that was sent in the confirmation link.

    Returns
    -------
    str
        Hexadecimal SHA-256 digest of the token.

    Example
    -------
    >>> len(hash_confirmation_token("abc")) == 64
    True
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
