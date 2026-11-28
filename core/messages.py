from core.config import CONFIRMATION_TTL, RESET_CODE_TTL


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


def registration_confirmation_message(link: str) -> tuple[str, str]:
    """Build the e-mail that asks a new student to confirm the registration.

    Parameters
    ----------
    link : str
        Confirmation link. It is valid for ``CONFIRMATION_TTL``.

    Returns
    -------
    tuple[str, str]
        Subject and plain-text body of the message.

    Example
    -------
    >>> subject, body = registration_confirmation_message("https://x/confirmar")
    """
    minutes = int(CONFIRMATION_TTL.total_seconds() // 60)
    subject = "Confirme seu cadastro - pgl_auth"
    text = (
        "Olá,\n\n"
        "Recebemos um pedido de cadastro para a sua matrícula no proxy de "
        "modelos de IA da disciplina. Para concluir, abra o link abaixo:\n\n"
        f"{link}\n\n"
        f"O link vale por {minutes} minutos. Depois disso, será preciso fazer "
        "o cadastro novamente.\n\n"
        "Se você não fez esse pedido, ignore esta mensagem. Nenhuma conta será "
        "criada sem a confirmação.\n"
    )
    return subject, text
