import uuid
import hashlib
import logging
from datetime import datetime
from sqlalchemy.orm import Session

from app.domain.models import (
    Email, Attachment, URLIndicator, YaraMatch, Alert, TaskRecord
)
from app.adapters.email_parser import parse_eml_bytes
from app.adapters.storage import save_attachment_file
from app.adapters.ioc_service import IOCExtractionService
from app.adapters.threat_scanner import ThreatScannerService
from app.adapters.ai_service import get_ai_service

logger = logging.getLogger("task_processor")


def process_email_pipeline(
    task_record_id: str, eml_bytes: bytes, db: Session
) -> dict:
    """Executes the full email analysis pipeline synchronously.
    This function is called either directly (sync mode) or from a
    Celery task (async mode). It updates the TaskRecord throughout.

    Returns a summary dict of the processing results.
    """
    task_rec = db.query(TaskRecord).filter(
        TaskRecord.id == uuid.UUID(task_record_id)
    ).first()
    if task_rec:
        task_rec.status = "Running"
        task_rec.started_at = datetime.utcnow()
        db.commit()

    try:
        # Step 1: Parse EML
        logger.info(f"Task {task_record_id}: parsing EML bytes...")
        parsed_data = parse_eml_bytes(eml_bytes)

        # Step 2: Dedup check
        existing = db.query(Email).filter(
            Email.message_id == parsed_data["message_id"]
        ).first()
        if existing:
            raise ValueError(
                "Email with this Message-ID has already been ingested."
            )

        # Step 3: IOC extraction
        logger.info(f"Task {task_record_id}: extracting IOCs...")
        iocs = IOCExtractionService.extract_iocs(
            body_text=parsed_data["body_text"],
            body_html=parsed_data["body_html"],
            headers_text=parsed_data["raw_header"],
            attachments=parsed_data["attachments"]
        )

        # Step 4: Threat scanning
        logger.info(f"Task {task_record_id}: running threat scans...")
        scanner = ThreatScannerService()
        scan_report = scanner.execute_pipeline(
            subject=parsed_data["subject"],
            body_text=parsed_data["body_text"],
            body_html=parsed_data["body_html"],
            headers=parsed_data["raw_header"],
            attachments=parsed_data["attachments"]
        )

        # Step 5: AI classification
        logger.info(f"Task {task_record_id}: running AI classification...")
        ai_service = get_ai_service()
        ai_report = ai_service.classify_email(
            body=parsed_data["body_text"],
            headers=parsed_data["raw_header"],
            attachments=parsed_data["attachments"]
        )

        # Step 6: Persist Email
        email = Email(
            id=uuid.uuid4(),
            message_id=parsed_data["message_id"],
            subject=parsed_data["subject"],
            sender=parsed_data["sender"],
            recipient=parsed_data["recipient"],
            body_text=parsed_data["body_text"],
            body_html=parsed_data["body_html"],
            raw_header=parsed_data["raw_header"],
            size_bytes=parsed_data["size_bytes"],
            received_at=parsed_data["received_at"],
            status="Completed"
        )
        db.add(email)

        # Step 7: Persist Attachments
        for idx, att in enumerate(parsed_data["attachments"]):
            att_id = uuid.uuid4()
            scan_res = scan_report.attachments[idx]
            try:
                path = save_attachment_file(
                    att_id, att["filename"], att["payload"]
                )
            except Exception:
                path = None

            attachment = Attachment(
                id=att_id,
                email_id=email.id,
                filename=att["filename"],
                file_size=att["file_size"],
                content_type=att["content_type"],
                file_hash_sha256=scan_res.sha256,
                path_on_disk=path,
                scanning_status=scan_res.status,
                virus_found=scan_res.virus_found,
                threat_label=scan_res.threat_label
            )
            db.add(attachment)

        # Step 8: Persist URL indicators
        for url_str in iocs.urls:
            url_id = uuid.uuid4()
            url_hash = hashlib.sha256(url_str.encode()).hexdigest()
            url_ind = URLIndicator(
                id=url_id,
                email_id=email.id,
                url=url_str,
                hash_sha256=url_hash,
                status="Unrated"
            )
            db.add(url_ind)

        # Step 9: Persist YARA matches
        for ym in scan_report.yara_matches:
            yara_match = YaraMatch(
                id=uuid.uuid4(),
                email_id=email.id,
                rule_name=ym.rule_name,
                tags=ym.tags,
                matched_strings={"matches": ym.matched_strings}
            )
            db.add(yara_match)

        # Step 10: Consolidate risk and create Alert
        final_risk = max(
            scan_report.risk_score, ai_report["final_risk_score"]
        )
        if final_risk >= 0.5:
            alert = Alert(
                id=uuid.uuid4(),
                email_id=email.id,
                risk_score=final_risk,
                status="OPEN",
                ai_phishing_probability=ai_report["phishing_probability"],
                ai_spam_probability=ai_report["metadata_probability"],
                ai_explanation={"explanations": ai_report["explanations"]},
                ai_model_version=ai_report["model_version"],
                ai_scanned_at=datetime.utcnow()
            )
            db.add(alert)

        # Step 11: Update TaskRecord
        if task_rec:
            task_rec.email_id = email.id
            task_rec.status = "Completed"
            task_rec.completed_at = datetime.utcnow()
            task_rec.result_data = {
                "email_id": str(email.id),
                "message_id": email.message_id,
                "sender": email.sender,
                "risk_score": final_risk,
            }

        db.commit()
        logger.info(
            f"Task {task_record_id}: completed successfully. "
            f"email_id={email.id}"
        )

        return {
            "email_id": str(email.id),
            "message_id": email.message_id,
            "sender": email.sender,
            "risk_score": final_risk,
            "status": "Completed"
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Task {task_record_id}: failed - {str(e)}")

        # Re-query task record after rollback to get fresh object
        try:
            task_rec = db.query(TaskRecord).filter(
                TaskRecord.id == uuid.UUID(task_record_id)
            ).first()
            if task_rec:
                task_rec.status = "Failed"
                task_rec.completed_at = datetime.utcnow()
                task_rec.error_message = str(e)[:1000]
                task_rec.retry_count = (task_rec.retry_count or 0) + 1
                db.commit()
        except Exception:
            db.rollback()

        raise
