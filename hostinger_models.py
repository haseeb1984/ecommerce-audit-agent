"""SQLAlchemy models for Hostinger's operational MySQL database.

Licensing, entitlements, and canonical payment events remain in PostgreSQL.
These tables hold customer-facing operational state and retryable projections.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Index, Integer, String, Text,
)
from hostinger_database import HostingerBase


class CustomerAccount(HostingerBase):
    __tablename__ = "customer_accounts"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    license_key = Column(String(100), nullable=False, unique=True, index=True)
    email = Column(String(254), nullable=True, index=True)
    display_name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=True)
    status = Column(String(24), nullable=False, default="active", index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class CustomerBillingEvent(HostingerBase):
    __tablename__ = "customer_billing_events"

    event_id = Column(String(255), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    recipient_email = Column(String(254), nullable=False)
    status = Column(String(40), nullable=False)
    transaction_id = Column(String(100), nullable=True, index=True)
    subscription_id = Column(String(100), nullable=True, index=True)
    paddle_customer_id = Column(String(100), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)


class CustomerLoginChallenge(HostingerBase):
    __tablename__ = "customer_login_challenges"

    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    challenge_hash = Column(String(255), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class CustomerEmailChangeChallenge(HostingerBase):
    __tablename__ = "customer_email_change_challenges"

    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    new_email = Column(String(254), nullable=False)
    challenge_hash = Column(String(255), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class CustomerSession(HostingerBase):
    __tablename__ = "customer_sessions"
    __table_args__ = (
        Index("ix_customer_sessions_license_revoked", "license_key", "revoked_at"),
        Index("ix_customer_sessions_expiry", "expires_at"),
    )

    token_hash = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class CustomerEmailIdentitySyncOutbox(HostingerBase):
    __tablename__ = "customer_email_identity_sync_outbox"
    __table_args__ = (
        Index("ix_customer_email_identity_outbox_due", "status", "next_attempt_at", "created_at"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    old_email = Column(String(254), nullable=False, index=True)
    new_email = Column(String(254), nullable=False)
    status = Column(String(20), nullable=False, default="pending", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_error = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    processed_at = Column(DateTime(timezone=True), nullable=True)


class WebsiteScanResult(HostingerBase):
    __tablename__ = "website_scan_results"
    __table_args__ = (
        Index("ix_website_scan_results_license_created", "license_key", "created_at"),
    )

    id = Column(String(64), primary_key=True)
    job_id = Column(String(64), nullable=False, unique=True, index=True)
    license_key = Column(String(100), nullable=False, index=True)
    website_id = Column(String(64), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    status = Column(String(24), nullable=False, index=True)
    overall_score = Column(Integer, nullable=True)
    finding_count = Column(Integer, nullable=False, default=0)
    findings_json = Column(Text, nullable=False)
    check_outcomes_json = Column(Text, nullable=False)
    coverage_json = Column(Text, nullable=False)
    summary_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
