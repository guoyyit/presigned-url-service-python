from fastapi import FastAPI

from presign.api import get_service, router as presign_router
from presign.audit import AuditLogger
from presign.config import Settings
from presign.service import PresignService
from presign.signing import KeyStore
from presign.store import StateStore


def build_service(settings: Settings) -> PresignService:
    """Wire the production service from configuration."""
    return PresignService(
        keys=KeyStore(settings.active_key_id, settings.signing_keys),
        store=StateStore(settings.db_path),
        audit=AuditLogger(settings.audit_log_path),
        clock_skew_seconds=settings.clock_skew_seconds,
        rotation_grace_seconds=settings.rotation_grace_seconds,
        scopes=settings.scopes,
    )


settings = Settings.from_env()
_service = build_service(settings)

app = FastAPI(title="presigned-url-service")
app.include_router(presign_router)
app.dependency_overrides[get_service] = lambda: _service


@app.get("/")
def read_root():
    return {"Hello": "World"}
