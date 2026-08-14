from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import ALLOWED_FRONTEND_ORIGINS
from core.routers.auth import router as auth_router


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(auth_router)

    # Only pgl-registry-front (or similar) calls this API from a browser;
    # the pgl_auth Python client and pgl_proxy call it server-side, which
    # isn't subject to CORS. With no origins configured, browsers can't
    # call this API at all.
    if ALLOWED_FRONTEND_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=ALLOWED_FRONTEND_ORIGINS,
            allow_methods=["POST"],
            allow_headers=["Content-Type"],
        )

    return app
