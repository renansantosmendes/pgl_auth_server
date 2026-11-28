from unittest.mock import MagicMock

import pytest
import resend

from core import mailer


def test_send_message_uses_the_noreply_sender_by_default(monkeypatch):
    send = MagicMock(return_value={"id": "email-1"})
    monkeypatch.setattr(resend.Emails, "send", send)
    monkeypatch.delenv("RESEND_FROM", raising=False)

    email_id = mailer.send_message("aluno@pucminas.edu.br", "Oi", "Texto")

    assert email_id == "email-1"
    payload = send.call_args.args[0]
    assert payload["from"] == "noreply@synapseaisolutions.com"
    assert payload["to"] == ["aluno@pucminas.edu.br"]
    assert payload["subject"] == "Oi"
    assert payload["text"] == "Texto"


def test_send_message_honours_resend_from(monkeypatch):
    send = MagicMock(return_value={"id": "email-2"})
    monkeypatch.setattr(resend.Emails, "send", send)
    monkeypatch.setenv("RESEND_FROM", "suporte@synapseaisolutions.com")

    mailer.send_message("aluno@pucminas.edu.br", "Oi", "Texto")

    assert send.call_args.args[0]["from"] == "suporte@synapseaisolutions.com"


def test_send_message_requires_the_api_key(monkeypatch):
    monkeypatch.delenv("RESEND_API_KEY")

    with pytest.raises(KeyError):
        mailer.send_message("aluno@pucminas.edu.br", "Oi", "Texto")


def test_resend_failure_is_logged_and_raised(monkeypatch, caplog):
    def failing_send(payload):
        raise RuntimeError("invalid from address")

    monkeypatch.setattr(resend.Emails, "send", failing_send)
    monkeypatch.setenv("RESEND_API_KEY", "re_test")

    with caplog.at_level("ERROR", logger="pgl_auth_server.mailer"):
        with pytest.raises(RuntimeError):
            mailer.send_message("aluno@pucminas.edu.br", "Oi", "Texto")

    assert "Resend rejected the e-mail" in caplog.text
    assert "RuntimeError" in caplog.text


def test_missing_api_key_is_logged(monkeypatch, caplog):
    monkeypatch.delenv("RESEND_API_KEY")

    with caplog.at_level("ERROR", logger="pgl_auth_server.mailer"):
        with pytest.raises(KeyError):
            mailer.send_message("aluno@pucminas.edu.br", "Oi", "Texto")

    assert "RESEND_API_KEY is not set" in caplog.text
