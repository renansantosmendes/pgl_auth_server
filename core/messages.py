from core.config import RESET_CODE_TTL


def reset_code_message(code: str) -> tuple[str, str]:
    """Build the e-mail that carries a password reset code.

    Parameters
    ----------
    code : str
        Numeric code the student must type in the client.

    Returns
    -------
    tuple[str, str]
        Subject and plain-text body of the message.

    Example
    -------
    >>> subject, body = reset_code_message("123456")
    """
    minutes = int(RESET_CODE_TTL.total_seconds() // 60)
    subject = "Código para redefinir sua senha - pgl_auth"
    text = (
        "Olá,\n\n"
        "Recebemos um pedido para redefinir a senha da sua conta de acesso "
        "ao proxy de modelos da disciplina.\n\n"
        f"Seu código é: {code}\n\n"
        f"Ele vale por {minutes} minutos. Digite-o no cliente pgl_auth "
        "para escolher a nova senha.\n\n"
        "Se você não fez esse pedido, ignore esta mensagem. Sua senha "
        "atual continua valendo.\n"
    )
    return subject, text


def invitation_message(code: str) -> tuple[str, str]:
    """Build the e-mail that invites a student to create a password.

    Parameters
    ----------
    code : str
        Numeric code the student must type in the client.

    Returns
    -------
    tuple[str, str]
        Subject and plain-text body of the message.

    Example
    -------
    >>> subject, body = invitation_message("123456")
    """
    minutes = int(RESET_CODE_TTL.total_seconds() // 60)
    subject = "Crie sua senha de acesso - pgl_auth"
    text = (
        "Olá,\n\n"
        "Sua matrícula está ativa na disciplina e agora você pode criar a "
        "senha de acesso ao proxy de modelos de IA.\n\n"
        f"Seu código é: {code}\n\n"
        f"Ele vale por {minutes} minutos. Digite-o no cliente pgl_auth "
        "para criar sua senha.\n\n"
        "Se você não esperava esta mensagem, ignore-a.\n"
    )
    return subject, text
