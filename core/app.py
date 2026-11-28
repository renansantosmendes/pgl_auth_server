from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import ALLOWED_FRONTEND_ORIGINS
from core.routers.auth import router as auth_router
from core.routers.password import router as password_router
from core.routers.professor import router as professor_router
from core.routers.token import router as token_router


def create_app() -> FastAPI:
    """Build the FastAPI application with every router and the CORS policy.

    Returns
    -------
    FastAPI
        Application ready to be served by Vercel or uvicorn.

    Example
    -------
    >>> app = create_app()  # doctest: +SKIP
    """
    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(password_router)
    app.include_router(professor_router)
    app.include_router(token_router)

    if ALLOWED_FRONTEND_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=ALLOWED_FRONTEND_ORIGINS,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "Authorization"],
        )

    return app
