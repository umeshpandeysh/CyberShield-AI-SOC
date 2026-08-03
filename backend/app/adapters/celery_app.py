import logging
from celery import Celery

logger = logging.getLogger("celery_app")

try:
    from app.infra.config import settings
    REDIS_URL = (
        f"redis://:{settings.REDIS_PASSWORD}@"
        f"{settings.REDIS_HOST}:{settings.REDIS_PORT}/0"
    )
except Exception:
    REDIS_URL = "redis://localhost:6379/0"

celery_app = Celery("cybershield", broker=REDIS_URL, backend=REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_retry_delay=30,
    task_max_retries=3,
)
