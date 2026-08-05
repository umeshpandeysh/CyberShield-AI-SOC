import uuid
import logging
from app.adapters.celery_app import celery_app
from app.infra.db_session import SessionLocal

logger = logging.getLogger("celery_tasks")


@celery_app.task(
    bind=True,
    name="cybershield.analyze_email",
    max_retries=3,
    default_retry_delay=30,
    acks_late=True,
)
def analyze_email_task(self, task_record_id: str, eml_bytes_hex: str):
    """Celery task that executes the full email analysis pipeline.
    eml_bytes are passed as hex-encoded string for JSON serialization.
    Implements retry with exponential backoff for transient failures.
    """
    from app.adapters.task_processor import process_email_pipeline

    logger.info(
        f"Celery task {self.request.id}: starting analysis "
        f"for task_record={task_record_id}"
    )

    eml_bytes = bytes.fromhex(eml_bytes_hex)
    db = SessionLocal()

    try:
        result = process_email_pipeline(task_record_id, eml_bytes, db)
        logger.info(
            f"Celery task {self.request.id}: completed successfully."
        )
        return result
    except Exception as exc:
        logger.error(
            f"Celery task {self.request.id}: failed - {str(exc)}"
        )
        # Retry with exponential backoff for transient failures
        backoff = 30 * (2 ** self.request.retries)
        try:
            raise self.retry(exc=exc, countdown=backoff)
        except self.MaxRetriesExceededError:
            logger.error(
                f"Celery task {self.request.id}: max retries exceeded "
                f"for task_record={task_record_id}. "
                f"Logging as dead-letter failure."
            )
            # Dead-letter: mark as permanently failed
            try:
                from app.domain.models import TaskRecord
                task_rec = db.query(TaskRecord).filter(
                    TaskRecord.id == uuid.UUID(task_record_id)
                ).first()
                if task_rec:
                    task_rec.status = "Dead"
                    task_rec.error_message = (
                        f"Permanently failed after "
                        f"{self.request.retries} retries: {str(exc)}"
                    )[:1000]
                    db.commit()
            except Exception:
                db.rollback()
            return {"status": "Dead", "error": str(exc)}
    finally:
        db.close()
