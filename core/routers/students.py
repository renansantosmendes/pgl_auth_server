import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from core import auth_tokens, db, repository
from core.schemas import MessageResponse, StudentDetail

logger = logging.getLogger("pgl_auth_server.students")

router = APIRouter(prefix="/api/professor/students", tags=["professor"])

STUDENT_NOT_FOUND_MESSAGE = "Aluno não encontrado na disciplina."
ACCOUNT_NOT_FOUND_MESSAGE = "Este aluno ainda não tem uma conta de acesso."


@router.get("/{registration_number}", response_model=StudentDetail)
def get_student(
    registration_number: str,
    authorization: Optional[str] = Depends(auth_tokens.bearer_authorization),
) -> StudentDetail:
    """Read every column of one student, for the professor CRUD screen.

    The password hash is never returned.

    Parameters
    ----------
    registration_number : str
        Registration number of the student.
    authorization : str | None
        Bearer token of the professor.

    Returns
    -------
    StudentDetail
        Roster and account columns of the student.

    Raises
    ------
    HTTPException
        401 or 403 for a caller that is not an active professor, 404 when the
        student is not on the roster.
    """
    auth_tokens.authenticate_professor(authorization)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            row = repository.find_student_detail(cur, registration_number)
    if row is None:
        raise HTTPException(status_code=404, detail=STUDENT_NOT_FOUND_MESSAGE)

    (
        number,
        account_id,
        is_active,
        token_version,
        updated_at,
        full_name,
        login_id,
        sis_id,
        course,
        role,
        roster_active,
        last_modified,
        has_password,
    ) = row
    return StudentDetail(
        registration_number=number,
        id=str(account_id) if account_id else None,
        is_active=is_active,
        token_version=token_version,
        updated_at=updated_at,
        has_password=bool(has_password),
        full_name=full_name,
        login_id=login_id,
        sis_id=sis_id,
        course=course,
        role=role,
        roster_active=roster_active,
        last_modified=last_modified,
    )


@router.delete("/{registration_number}", response_model=MessageResponse)
def delete_student_account(
    registration_number: str,
    authorization: Optional[str] = Depends(auth_tokens.bearer_authorization),
) -> MessageResponse:
    """Delete the access account of a student.

    The roster entry is kept, and the student can register again. Tokens of
    the deleted account stop working, because the account no longer exists.

    Parameters
    ----------
    registration_number : str
        Registration number of the student.
    authorization : str | None
        Bearer token of the professor.

    Returns
    -------
    MessageResponse
        Confirmation of the deletion.

    Raises
    ------
    HTTPException
        401 or 403 for a caller that is not an active professor, 404 when the
        student has no access account.
    """
    professor = auth_tokens.authenticate_professor(authorization)
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            deleted = repository.delete_student(cur, registration_number)
            if deleted:
                repository.record_audit_event(
                    cur,
                    "professor_account_deleted",
                    registration_number,
                    professor,
                    "access account deleted",
                )
    if not deleted:
        raise HTTPException(status_code=404, detail=ACCOUNT_NOT_FOUND_MESSAGE)
    return MessageResponse(message="Conta de acesso removida.")
