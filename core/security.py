import hashlib

import bcrypt


def fingerprint(senha: str) -> str:
    """Irreversible hash (SHA-256, 12 chars) used only to correlate attempts in the
    logs — it never allows the original password to be recovered."""
    return hashlib.sha256(senha.encode("utf-8")).hexdigest()[:12]


def hash_password(senha: str) -> str:
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(senha: str, password_hash: str) -> bool:
    return bcrypt.checkpw(senha.encode("utf-8"), password_hash.encode("utf-8"))
