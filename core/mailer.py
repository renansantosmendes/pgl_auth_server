import logging
import os

import resend

from core.config import DEFAULT_SENDER, SENDER_ENV_VAR

logger = logging.getLogger("pgl_auth_server.mailer")


def send_message(
    recipient: str,
    subject: str,
    text: str,
) -> str:
    """Send a plain-text e-mail through the Resend API.

    The sender is read from ``RESEND_FROM`` and defaults to the
    no-reply address of the platform. The API key is read from
    ``RESEND_API_KEY``.

    Parameters
    ----------
    recipient : str
        Address that receives the message.
    subject : str
        Subject line.
    text : str
        Plain-text body.

    Returns
    -------
    str
        Identifier that Resend assigned to the message.

    Raises
    ------
    KeyError
        If ``RESEND_API_KEY`` is not set.

    Example
    -------
    >>> send_message("aluno@pucminas.edu.br", "Oi", "Texto")  # doctest: +SKIP
    """
    resend.api_key = os.environ["RESEND_API_KEY"]
    sender = os.environ.get(SENDER_ENV_VAR, DEFAULT_SENDER)
    response = resend.Emails.send(
        {
            "from": sender,
            "to": [recipient],
            "subject": subject,
            "text": text,
        }
    )
    logger.info("Message sent | recipient_domain=%s", recipient.split("@")[-1])
    return response["id"]
