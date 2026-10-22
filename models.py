import hashlib
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, ForeignKey, func, Index, LargeBinary
from sqlalchemy.orm import relationship
from database import Base


class SoftwareLicense(Base):
    __tablename__ = "software_licenses"

    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String(100), unique=True, nullable=False, index=True)
    client_name = Column(String(255), nullable=False)
    tier = Column(String(50), default="starter")
    max_monthly_audits = Column(Integer, default=100)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    api_keys = relationship("APIKey", back_populates="license")
    leads = relationship("AuditLead", back_populates="license")
    audit_reservations = relationship("AuditQuotaReservation", back_populates="license")


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("software_licenses.id", ondelete="CASCADE"))
    api_key_hash = Column(String(255), unique=True, nullable=False)
    key_prefix = Column(String(10), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    license = relationship("SoftwareLicense", back_populates="api_keys")

    @staticmethod
    def hash_key(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()


class AuditLead(Base):
    __tablename__ = "audit_leads"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("software_licenses.id", ondelete="SET NULL"), nullable=True)
    domain = Column(String(255), index=True, nullable=False)
    mobile_score = Column(Integer, nullable=False)
    speed_index_sec = Column(Float, nullable=False)
    contact_email = Column(String(255), nullable=True)
    revenue_leak_hypothesis = Column(Text, nullable=True)
    email_subject = Column(String(255), nullable=True)
    email_body = Column(Text, nullable=True)
    source_channel = Column(String(50), default="wordpress_hub")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    license = relationship("SoftwareLicense", back_populates="leads")


class AuditQuotaReservation(Base):
    """Short-lived, durable quota slot held while an audit runs outside a DB transaction."""

    __tablename__ = "audit_quota_reservations"
    __table_args__ = (
        Index("ix_audit_quota_reservations_license_created", "license_id", "created_at"),
        Index("ix_audit_quota_reservations_expires_at", "expires_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(
        Integer,
        ForeignKey("software_licenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)

    license = relationship("SoftwareLicense", back_populates="audit_reservations")


class AuditReport(Base):
    """Persist the exact customer PDF and auditable metadata under its owning license."""

    __tablename__ = "audit_reports"
    __table_args__ = (
        Index("ix_audit_reports_license_created", "license_id", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(
        Integer,
        ForeignKey("software_licenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    domain = Column(String(255), nullable=False, index=True)
    pdf_bytes = Column(LargeBinary, nullable=False)
    coverage_json = Column(Text, nullable=False, default="{}")
    finding_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class SaaSPlanPackage(Base):
    """Operator-managed plan catalogue; raw SQL endpoints use the same table schema."""
    __tablename__ = "saas_plan_packages"

    tier = Column(String(50), primary_key=True)
    label = Column(String(100), nullable=False)
    monthly_audit_allowance = Column(Integer, nullable=False)
    max_concurrent_audits = Column(Integer, nullable=False)
    paddle_price_id = Column(String(100), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, server_default="true")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class SaaSAdminActionLog(Base):
    """Persistent operator activity log. Secret values must never be written here."""
    __tablename__ = "saas_admin_action_logs"
    __table_args__ = (
        Index("ix_saas_admin_action_logs_created", "created_at", "id"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    action = Column(String(80), nullable=False)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(255), nullable=True)
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PaymentWebhookEvent(Base):
    """Idempotency and retry state for verified hosted-checkout webhook events."""

    __tablename__ = "payment_webhook_events"

    event_id = Column(String(255), primary_key=True)
    status = Column(String(40), nullable=False, default="email_pending")
    license_id = Column(
        Integer,
        ForeignKey("software_licenses.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    recipient_email = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
