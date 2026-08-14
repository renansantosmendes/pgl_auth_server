import logging
import os
from datetime import timedelta

TOKEN_TTL = timedelta(hours=4)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)

#: Comma-separated list of origins allowed to call this API via CORS from a
#: browser, e.g. the deployed pgl-registry-front URL. Empty by default,
#: which leaves the API unreachable from any browser page until
#: explicitly configured.
ALLOWED_FRONTEND_ORIGINS: list[str] = [
    origin.strip()
    for origin in os.environ.get("ALLOWED_FRONTEND_ORIGINS", "").split(",")
    if origin.strip()
]
