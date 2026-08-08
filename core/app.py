from fastapi import FastAPI

from core.routers.auth import router as auth_router


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(auth_router)
    return app
