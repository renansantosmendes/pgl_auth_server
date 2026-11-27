from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pytest
from fastapi.testclient import TestClient

from api.application import app
from core import auth_tokens, db, mailer
from tests.fakes import FakeDatabase

SECRET = "test-secret"


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    monkeypatch.setenv("NEON_DATABASE_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("JWT_SECRET_KEY", SECRET)
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    monkeypatch.delenv("RESEND_FROM", raising=False)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sent_messages(monkeypatch):
    messages = []

    def fake_send(recipient, subject, text):
        messages.append({"to": recipient, "subject": subject, "text": text})
        return "email-id"

    monkeypatch.setattr(mailer, "send_message", fake_send)
    return messages


def use_database(monkeypatch, routes):
    database = FakeDatabase(routes)
    monkeypatch.setattr(db, "get_connection", database.connect)
    return database


def password_hash(senha: str) -> str:
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def student_token(registration_number: str = "12345", version: int = 0) -> str:
    return auth_tokens.issue_token(registration_number, version)


def expired_token(registration_number: str = "12345") -> str:
    past = datetime.now(timezone.utc) - timedelta(hours=10)
    claims = {"sub": registration_number, "ver": 0, "iat": past, "exp": past}
    return jwt.encode(claims, SECRET, algorithm="HS256")


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
