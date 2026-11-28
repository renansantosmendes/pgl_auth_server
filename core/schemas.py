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
