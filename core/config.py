import logging
import os
from datetime import timedelta

TOKEN_TTL = timedelta(hours=4)
MAX_FAILED_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=15)
RESET_CODE_TTL = timedelta(minutes=15)
RESET_CODE_MAX_ATTEMPTS = 5
RESET_CODE_COOLDOWN = timedelta(seconds=60)
CONFIRMATION_TTL = timedelta(minutes=10)
FRONTEND_BASE_URL = os.environ.get(
    "FRONTEND_BASE_URL", "https://pgl-auth-frontend.vercel.app"
).rstrip("/")
INVITATION_BATCH_LIMIT = 200
DEFAULT_SENDER = "noreply@synapseaisolutions.com"
SENDER_ENV_VAR = "RESEND_FROM"

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)

ALLOWED_FRONTEND_ORIGINS: list[str] = [
    origin.strip()
    for origin in os.environ.get("ALLOWED_FRONTEND_ORIGINS", "").split(",")
    if origin.strip()
]
