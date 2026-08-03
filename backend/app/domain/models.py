import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Text, Boolean, Integer, Float, ForeignKey, DateTime, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    assigned_alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="assignee")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")


class Email(Base):
    __tablename__ = "emails"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    message_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    subject: Mapped[Optional[str]] = mapped_column(String(998), nullable=True)
    sender: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    body_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_header: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="Queued")

    # Relationships
    attachments: Mapped[List["Attachment"]] = relationship("Attachment", back_populates="email", cascade="all, delete-orphan")
    urls: Mapped[List["URLIndicator"]] = relationship("URLIndicator", back_populates="email", cascade="all, delete-orphan")
    yara_matches: Mapped[List["YaraMatch"]] = relationship("YaraMatch", back_populates="email", cascade="all, delete-orphan")
    alert: Mapped[Optional["Alert"]] = relationship("Alert", back_populates="email", uselist=False, cascade="all, delete-orphan")


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    file_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    path_on_disk: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    scanning_status: Mapped[str] = mapped_column(String(50), nullable=False, default="Pending")
    virus_found: Mapped[bool] = mapped_column(Boolean, default=False)
    threat_label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="attachments")


class URLIndicator(Base):
    __tablename__ = "url_indicators"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    vt_positives: Mapped[int] = mapped_column(Integer, default=0)
    vt_total: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="Unrated")

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="urls")


class YaraMatch(Base):
    __tablename__ = "yara_matches"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tags: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    matched_strings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="yara_matches")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), unique=True, nullable=False)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="OPEN", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # AI prediction storage
    ai_phishing_probability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ai_spam_probability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ai_explanation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ai_model_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ai_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="alert")
    assignee: Mapped[Optional["User"]] = relationship("User", back_populates="assigned_alerts")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_entity: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")


class TaskRecord(Base):
    __tablename__ = "task_records"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    task_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="Pending", index=True)
    email_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), nullable=True, index=True)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    result_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(50), nullable=False, default="Medium", index=True
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="Open", index=True
    )
    alert_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True, index=True
    )
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True, index=True
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )
    tags: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Relationships
    alert: Mapped[Optional["Alert"]] = relationship(
        "Alert", foreign_keys=[alert_id]
    )
    assignee: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[assigned_to]
    )
    creator: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[created_by]
    )
    notes: Mapped[List["CaseNote"]] = relationship(
        "CaseNote", back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseNote.created_at.desc()"
    )
    events: Mapped[List["CaseEvent"]] = relationship(
        "CaseEvent", back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseEvent.timestamp.desc()"
    )
    evidence_items: Mapped[List["CaseEvidence"]] = relationship(
        "CaseEvidence", back_populates="case",
        cascade="all, delete-orphan"
    )


class CaseNote(Base):
    __tablename__ = "case_notes"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    author_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="notes")
    author: Mapped[Optional["User"]] = relationship("User")


class CaseEvent(Base):
    __tablename__ = "case_events"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    event_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[Optional[dict]] = mapped_column(
        JSON, nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="events")
    actor: Mapped[Optional["User"]] = relationship("User")


class CaseEvidence(Base):
    __tablename__ = "case_evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    evidence_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    reference_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    added_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    # Relationships
    case: Mapped["Case"] = relationship(
        "Case", back_populates="evidence_items"
    )
    collector: Mapped[Optional["User"]] = relationship("User")


class ThreatIntelRecord(Base):
    __tablename__ = "threat_intel_records"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    ioc: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    reputation: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    malware_family: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    raw_response: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    cache_expiry: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
