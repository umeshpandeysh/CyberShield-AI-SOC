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

