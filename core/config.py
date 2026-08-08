import logging
import os
from datetime import timedelta

TOKEN_TTL = timedelta(hours=4)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)
