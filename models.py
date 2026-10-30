import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, BigInteger, String, Float, Text, DateTime, Boolean, ForeignKey, func, Index, LargeBinary, UniqueConstraint, text
from sqlalchemy.orm import relationship
from database import Base


class SoftwareLicense(Base):
    __tablename__ = "software_licenses"
    __table_args__ = (Index("uq_software_licenses_account_email_lower", text("lower(account_email)"), unique=True),)

    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String(100), unique=True, nullable=False, index=True)
    client_name = Column(String(255), nullable=False)
    # Canonical verified billing identity: one normalized email owns one SaaS license.
    account_email = Column(String(255), nullable=True)
    tier = Column(String(50), default="starter")
    max_monthly_audits = Column(Integer, default=100)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    billing_period_ends_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    api_keys = relationship("APIKey", back_populates="license")
    leads = relationship("AuditLead", back_populates="license")
    audit_reservations = relationship("AuditQuotaReservation", back_populates="license")


class WhiteLabelBranding(Base):
    """Per-license white-label settings, accessible only to eligible plans."""

    __tablename__ = "white_label_branding"

    license_id = Column(
        Integer,
        ForeignKey("software_licenses.id", ondelete="CASCADE"),
        primary_key=True,
    )
    brand_name = Column(String(100), nullable=False)
    logo_url = Column(String(2048), nullable=True)
    primary_color = Column(String(7), nullable=False, default="#155a8a", server_default="#155a8a")
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

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
    mobile_score = Column(Integer, nullable=True)
    speed_index_sec = Column(Float, nullable=True)
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

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    action = Column(String(80), nullable=False)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(255), nullable=True)
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class SaaSOperationEvent(Base):
    """Minimal diagnostic events; store error classes and hostnames, never secrets or tracebacks."""
    __tablename__ = "saas_operation_events"
    __table_args__ = (
        Index("ix_saas_operation_events_created", "created_at", "id"),
        Index("ix_saas_operation_events_type_created", "event_type", "created_at"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    event_type = Column(String(80), nullable=False)
    license_id = Column(Integer, ForeignKey("software_licenses.id", ondelete="SET NULL"), nullable=True)
    domain = Column(String(255), nullable=True)
    error_type = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class WordPressLinkChallenge(Base):
    """Hashed, short-lived, single-use proof used to link a WordPress site to a license."""

    __tablename__ = "wordpress_link_challenges"
    __table_args__ = (
        Index("ix_wordpress_link_challenges_license_expires", "license_id", "expires_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(
        Integer,
        ForeignKey("software_licenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash = Column(String(64), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class WordPressSiteLink(Base):
    """A verified WordPress site and the local user who completed its one-time claim."""

    __tablename__ = "wordpress_site_links"
    __table_args__ = (
        UniqueConstraint("license_id", "site_url", name="uq_wordpress_site_links_license_site"),
        Index("ix_wordpress_site_links_license_linked", "license_id", "linked_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(
        Integer,
        ForeignKey("software_licenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    site_url = Column(String(255), nullable=False)
    wp_user_id = Column(Integer, nullable=False)
    wp_user_login = Column(String(60), nullable=False)
    wp_user_email = Column(String(254), nullable=False)
    linked_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

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
    transaction_id = Column(String(100), nullable=True, index=True)
    subscription_id = Column(String(100), nullable=True, index=True)
    paddle_customer_id = Column(String(100), nullable=True, index=True)
    recipient_email = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))



class AccountLoginChallenge(Base):
    """Short-lived one-time email code used to establish a customer account session."""
    __tablename__ = "account_login_challenges"
    __table_args__ = (
        Index("ix_account_login_challenges_email_created", "email", "created_at"),
        Index("ix_account_login_challenges_expires_at", "expires_at"),
    )

    id = Column(String(64), primary_key=True)
    email = Column(String(255), nullable=False, index=True)
    license_id = Column(Integer, ForeignKey("software_licenses.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class AccountSession(Base):
    """Opaque customer bearer session; only its SHA-256 token digest is persisted."""
    __tablename__ = "account_sessions"
    __table_args__ = (
        Index("ix_account_sessions_license_created", "license_id", "created_at"),
        Index("ix_account_sessions_email_created", "email", "created_at"),
        Index("ix_account_sessions_expires_at", "expires_at"),
    )

    token_hash = Column(String(64), primary_key=True)
    session_id = Column(String(32), nullable=False, unique=True, default=lambda: uuid.uuid4().hex)
    license_id = Column(Integer, ForeignKey("software_licenses.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
