from typing import Optional

from fastapi import APIRouter, Depends

from core import auth_tokens
from core.schemas import IdentityResponse

router = APIRouter(prefix="/api", tags=["token"])


@router.get("/token/verify", response_model=IdentityResponse)
def verify_token(
    authorization: Optional[str] = Depends(auth_tokens.bearer_authorization),
) -> IdentityResponse:
    """Confirm a bearer token and return who it belongs to.

    Parameters
    ----------
    authorization : str | None
        Value of the ``Authorization`` header, for example
        ``Bearer <token>``.

    Returns
    -------
    IdentityResponse
        Registration number of the token owner and its role.
    """
    return IdentityResponse(**auth_tokens.verify_identity(authorization))
