from datetime import datetime
from typing import List

from pydantic import BaseModel, Field

from core.config import INVITATION_BATCH_LIMIT


class LoginRequest(BaseModel):
    registration_number: str
    senha: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RegisterRequest(BaseModel):
    registration_number: str
    email: str
    senha: str
    senha_confirmacao: str


class RegisterResponse(BaseModel):
    registration_number: str
    message: str = "Student registered successfully."


class ChangePasswordRequest(BaseModel):
    senha_atual: str
    nova_senha: str


class ForgotPasswordRequest(BaseModel):
    registration_number: str


class PasswordResetRequest(BaseModel):
    registration_number: str
    codigo: str
    nova_senha: str


class MessageResponse(BaseModel):
    message: str


class ResetPasswordRequest(BaseModel):
    registration_number: str
    new_senha: str


class ResetPasswordResponse(BaseModel):
    registration_number: str
    message: str = "Password reset successfully."


class StudentAccount(BaseModel):
    registration_number: str
    full_name: str | None
    login_id: str | None
    roster_active: bool
    has_password: bool
    account_active: bool | None


class StudentListResponse(BaseModel):
    students: List[StudentAccount]


class StudentStatusRequest(BaseModel):
    is_active: bool


class InvitationRequest(BaseModel):
    registration_numbers: List[str] = Field(
        min_length=1, max_length=INVITATION_BATCH_LIMIT
    )


class InvitationSkip(BaseModel):
    registration_number: str
    reason: str


class InvitationResponse(BaseModel):
    sent: List[str]
    skipped: List[InvitationSkip]


class IdentityResponse(BaseModel):
    """Identity of the owner of a bearer token.

    Attributes
    ----------
    registration_number : str
        Registration number of the owner.
    role : str
        ``professor`` or ``student``.
    """

    registration_number: str
    role: str


class ConfirmRegistrationRequest(BaseModel):
    """Token received in the registration confirmation link.

    Attributes
    ----------
    token : str
        Token copied from the link.
    """

    token: str


class StudentDetail(BaseModel):
    """Every column of a student, except the password hash.

    Attributes
    ----------
    registration_number : str
        Registration number of the roster member.
    id : str | None
        Identifier of the password account, or None without an account.
    is_active : bool | None
        Whether the password account can log in, or None without an account.
    token_version : int | None
        Version used to revoke tokens, or None without an account.
    updated_at : datetime | None
        Last change of the password account, or None without an account.
    has_password : bool
        Whether the student has a password account.
    full_name : str | None
        Name from the roster.
    login_id : str | None
        Login identifier from the roster, usually the institutional e-mail.
    sis_id : str | None
        SIS identifier from the roster.
    course : str | None
        Course from the roster.
    role : str | None
        Role from the roster.
    roster_active : bool
        Whether the roster entry is active.
    last_modified : datetime
        Last change of the roster entry.
    """

    registration_number: str
    id: str | None
    is_active: bool | None
    token_version: int | None
    updated_at: datetime | None
    has_password: bool
    full_name: str | None
    login_id: str | None
    sis_id: str | None
    course: str | None
    role: str | None
    roster_active: bool
    last_modified: datetime
