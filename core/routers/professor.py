import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends

from core import auth_tokens, db, messages, repository, reset_flow, security, validation
from core.schemas import (
    InvitationRequest,
    InvitationResponse,
    InvitationSkip,
    ResetPasswordRequest,
    ResetPasswordResponse,
    StudentListResponse,
    StudentAccount,
    StudentStatusRequest,
)
from core.routers.auth import raise_validation_error

logger = logging.getLogger("pgl_auth_server.professor")

router = APIRouter(prefix="/api", tags=["professor"])


@router.post("/reset-password", response_model=ResetPasswordResponse)
def reset_password(
    payload: ResetPasswordRequest,
    authorization: Optional[str] = Depends(auth_tokens.bearer_authorization),
) -> ResetPasswordResponse:
    """Let a professor set or replace the password of a student.

    The new password must follow the same strength rules as the student
    flows. Every token of the student is revoked by the change.

    Parameters
    ----------
    payload : ResetPasswordRequest
        Registration number of the student and the new password.
    authorization : str | None
        Bearer token of the professor.

    Returns
    -------
    ResetPasswordResponse
        Confirmation with the registration number.

    Raises
    ------
    HTTPException
        401 for a missing or invalid token, 403 when the caller is not an
        active professor, 422 for a weak password.
    """
    professor = auth_tokens.authenticate_professor(authorization)
    errors = validation.password_problems(
        payload.new_senha, payload.registration_number
    )
    if errors:
        raise_validation_error(errors)

    with db.get_connection() as conn:
        with conn.cursor() as cur:
            repository.save_password(
                cur,
                payload.registration_number,
                security.hash_password(payload.new_senha),
            )
            repository.record_audit_event(
                cur,
                "professor_password_reset",
                payload.registration_number,
                professor,
                "password set by professor",
            )
    return ResetPasswordResponse(registration_number=payload.registration_number)


@router.get("/professor/students", response_model=StudentListResponse)
def list_students(
    authorization: Optional[str] = Depends(auth_tokens.bearer_authorization),
) -> StudentListResponse:
    """List every roster member with the state of their password account.

    Parameters
    ----------
    authorization : str | None
        Bearer token of the professor.

    Returns
    -------
    StudentListResponse
        Roster members with their enrollment and password status.
    """
    auth_tokens.authenticate_professor(authorization)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            rows = repository.list_student_accounts(cur)
    return StudentListResponse(
        students=[
            StudentAccount(
                registration_number=row[0],
                full_name=row[1],
                login_id=row[2],
                roster_active=row[3],
                has_password=row[4],
                account_active=row[5],
            )
            for row in rows
        ]
    )


@router.post("/professor/students/{registration_number}/status")
def set_student_status(
    registration_number: str,
    payload: StudentStatusRequest,
    authorization: Optional[str] = Depends(auth_tokens.bearer_authorization),
) -> dict:
    """Block or unblock the password login of a student.

    This changes only the password account. The enrollment on the course
    roster is not touched.

    Parameters
    ----------
    registration_number : str
        Student whose account is changed.
    payload : StudentStatusRequest
        New status of the account.
    authorization : str | None
        Bearer token of the professor.

    Returns
    -------
    dict
        Registration number and the new status.

    Raises
    ------
    HTTPException
        404 when the student has no password account yet.
    """
    professor = auth_tokens.authenticate_professor(authorization)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            updated = repository.set_student_active(
                cur, registration_number, payload.is_active
            )
            if updated:
                repository.record_audit_event(
                    cur,
                    "professor_status_change",
                    registration_number,
                    professor,
                    f"is_active={payload.is_active}",
                )
    if not updated:
        raise HTTPException(
            status_code=404, detail="Este aluno ainda não tem uma senha cadastrada."
        )
    return {"registration_number": registration_number, "is_active": payload.is_active}


@router.post("/professor/invitations", response_model=InvitationResponse)
def send_invitations(
    payload: InvitationRequest,
    authorization: Optional[str] = Depends(auth_tokens.bearer_authorization),
) -> InvitationResponse:
    """Invite enrolled students who have no password yet.

    Each invitation is an e-mail with a code, sent to the institutional
    address of the student. Students that cannot be invited are listed with
    the reason. Each invitation runs in its own transaction, so one failed
    delivery does not cancel the others.

    Parameters
    ----------
    payload : InvitationRequest
        Registration numbers to invite, up to the batch limit.
    authorization : str | None
        Bearer token of the professor.

    Returns
    -------
    InvitationResponse
        Registration numbers invited and the skipped ones with reasons.
    """
    auth_tokens.authenticate_professor(authorization)
    sent: list[str] = []
    skipped: list[InvitationSkip] = []
    for registration_number in dict.fromkeys(payload.registration_numbers):
        reason = _invite_student(registration_number)
        if reason is None:
            sent.append(registration_number)
        else:
            skipped.append(
                InvitationSkip(registration_number=registration_number, reason=reason)
            )
    return InvitationResponse(sent=sent, skipped=skipped)


def _invite_student(registration_number: str) -> Optional[str]:
    """Send one invitation code and report why it was skipped, if it was.

    Parameters
    ----------
    registration_number : str
        Student to invite.

    Returns
    -------
    str | None
        None when the invitation was sent, otherwise the reason it was not.
    """
    if validation.registration_number_problems(registration_number):
        return "matrícula inválida"

    now = datetime.now(timezone.utc)
    try:
        with db.get_connection() as conn:
            with conn.cursor() as cur:
                enrollment = repository.find_enrollment(cur, registration_number)
                if enrollment is None or not enrollment[0]:
                    return "não matriculado ou inativo na disciplina"
                login_id = (enrollment[1] or "").strip()
                if validation.email_problems(login_id):
                    return "sem e-mail institucional cadastrado"
                if repository.find_auth_student(cur, registration_number) is not None:
                    return "já possui senha cadastrada"
                outcome = reset_flow.issue_code(
                    cur,
                    registration_number,
                    login_id,
                    messages.invitation_message,
                    now,
                    os.environ["JWT_SECRET_KEY"],
                )
                if outcome != reset_flow.CODE_SENT:
                    return "convite enviado recentemente"
                repository.record_audit_event(
                    cur, "invitation_sent", registration_number, None, "code sent"
                )
    except Exception:
        logger.exception("Could not send an invitation.")
        return "falha ao enviar o e-mail"
    return None
