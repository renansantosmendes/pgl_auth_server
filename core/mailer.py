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
    Exception
        Any error raised by the Resend client. It is logged and re-raised.

    Example
    -------
    >>> send_message("aluno@pucminas.edu.br", "Oi", "Texto")  # doctest: +SKIP
    """
    api_key = os.environ.get("RESEND_API_KEY", "")
    if not api_key:
        logger.error("E-mail not sent: RESEND_API_KEY is not set on this deployment.")
        raise KeyError("RESEND_API_KEY")
    resend.api_key = api_key
    sender = os.environ.get(SENDER_ENV_VAR, DEFAULT_SENDER)
    domain = recipient.split("@")[-1]
    logger.info(
        "Sending e-mail | from=%s recipient_domain=%s subject=%r",
        sender,
        domain,
        subject,
    )
    try:
        response = resend.Emails.send(
            {
                "from": sender,
                "to": [recipient],
                "subject": subject,
                "text": text,
            }
        )
    except Exception as error:
        logger.error(
            "Resend rejected the e-mail | recipient_domain=%s error_type=%s message=%s",
            domain,
            type(error).__name__,
            error,
        )
        raise
    logger.info(
        "E-mail accepted by Resend | id=%s recipient_domain=%s",
        response["id"],
        domain,
    )
    return response["id"]
