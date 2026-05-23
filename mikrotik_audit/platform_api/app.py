"""Implementation details for platform_api app."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from .command_runner import CommandRunner
from .config import PlatformApiSettings
from .db import build_engine, build_session_factory
from .orm import Base
from .routes import router


def create_app(settings: PlatformApiSettings | None = None) -> FastAPI:
    """Create app."""
    resolved_settings = settings or PlatformApiSettings.from_env()
    engine = build_engine(resolved_settings.database_url)
    session_factory = build_session_factory(engine)
    is_sqlite = resolved_settings.database_url.startswith("sqlite")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with engine.begin() as connection:
            if is_sqlite:
                await connection.execute(text("PRAGMA journal_mode=WAL"))
                await connection.execute(text("PRAGMA synchronous=NORMAL"))
                await connection.execute(text("PRAGMA busy_timeout=60000"))

            if resolved_settings.auto_create_schema:
                await connection.run_sync(Base.metadata.create_all)

        yield

        await engine.dispose()

    app = FastAPI(
        title=resolved_settings.app_name,
        version=resolved_settings.app_version,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    app.state.settings = resolved_settings
    app.state.auth_config = resolved_settings.auth_config
    app.state.refresh_tokens = set()
    app.state.command_runner = CommandRunner()
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.include_router(router)
    return app
