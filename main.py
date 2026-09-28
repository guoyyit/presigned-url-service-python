"""Application entry point: ``uvicorn main:app`` / ``fastapi dev main.py``."""

from __future__ import annotations

from presigned.api import create_app
from presigned.config import load_settings
from presigned.service import build_service

settings = load_settings()
service = build_service(settings)
app = create_app(service)
