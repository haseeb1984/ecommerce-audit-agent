"""Hostinger MySQL models for customer-facing SaaS operations.

No foreign keys cross into Supabase. license_key is the stable external
reference validated by the licensing service.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, ForeignKey, Index, Integer,
    String, Text, UniqueConstraint, func,
)
from hostinger_database import HostingerBase


def utcnow():
    return datetime.now(timezone.utc)


class CustomerAccount(HostingerBase):
    __tablename__ = "customer_accounts"
    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    email = Column(String(254), nullable=False, index=True)
    display_name = Column(String(255), nullable=True)
    status = Column(String(24), nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    __table_args__ = (
        UniqueConstraint("license_key", "email", name="uq_customer_accounts_license_email"),
        Index("ix_customer_accounts_status_created", "status", "created_at"),
    )


class CustomerLoginChallenge(HostingerBase):
    __tablename__ = "customer_login_challenges"
    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    email = Column(String(254), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class CustomerSession(HostingerBase):
    __tablename__ = "customer_sessions"
    token_hash = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    email = Column(String(254), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    public_id = Column(String(64), nullable=True, unique=True)
    user_agent = Column(String(500), nullable=True)


class CustomerEmailChangeChallenge(HostingerBase):
    __tablename__ = "customer_email_change_challenges"
    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    old_email = Column(String(254), nullable=False, index=True)
    new_email = Column(String(254), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class CustomerWebsite(HostingerBase):
    __tablename__ = "customer_websites"
    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    submitted_by = Column(String(254), nullable=True)
    url = Column(String(2048), nullable=False)
    normalized_url = Column(String(2048), nullable=False)
    normalized_url_hash = Column(String(64), nullable=False)
    host = Column(String(253), nullable=False, index=True)
    label = Column(String(160), nullable=True)
    status = Column(String(24), nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    __table_args__ = (
        UniqueConstraint("license_key", "normalized_url_hash", name="uq_customer_websites_license_url_hash"),
        Index("ix_customer_websites_license_status", "license_key", "status"),
    )


class ScanBatch(HostingerBase):
    __tablename__ = "scan_batches"
    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    requested_by = Column(String(254), nullable=True)
    package_tier = Column(String(50), nullable=False)
    request_id = Column(String(128), nullable=False)
    request_hash = Column(String(64), nullable=False)
    batch_number = Column(Integer, nullable=False)
    batch_size = Column(Integer, nullable=False, default=10)
    total_urls = Column(Integer, nullable=False, default=0)
    queued_count = Column(Integer, nullable=False, default=0)
    processing_count = Column(Integer, nullable=False, default=0)
    completed_count = Column(Integer, nullable=False, default=0)
    failed_count = Column(Integer, nullable=False, default=0)
    status = Column(String(24), nullable=False, default="queued", index=True)
    available_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        UniqueConstraint("license_key", "request_id", name="uq_scan_batches_license_request"),
        UniqueConstraint("license_key", "batch_number", "created_at", name="uq_scan_batches_sequence"),
        Index("ix_scan_batches_claim", "status", "available_at", "created_at"),
    )


class WebsiteScanJob(HostingerBase):
    __tablename__ = "website_scan_jobs"
    id = Column(String(64), primary_key=True)
    batch_id = Column(String(64), nullable=False, index=True)
    license_key = Column(String(100), nullable=False, index=True)
    website_id = Column(String(64), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    status = Column(String(24), nullable=False, default="queued", index=True)
    idempotency_key = Column(String(128), nullable=False, unique=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=3)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    locked_by = Column(String(128), nullable=True)
    last_error_code = Column(String(80), nullable=True)
    result_reference = Column(String(255), nullable=True)
    quota_reserved = Column(Boolean, nullable=False, default=False)
    quota_consumed = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        Index("ix_scan_jobs_batch_status", "batch_id", "status"),
        Index("ix_scan_jobs_claim", "status", "next_attempt_at", "created_at"),
        Index("ix_scan_jobs_license_created", "license_key", "created_at"),
    )


class CustomerUsageEvent(HostingerBase):
    __tablename__ = "customer_usage_events"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    license_key = Column(String(100), nullable=False, index=True)
    job_id = Column(String(64), nullable=True, index=True)
    event_key = Column(String(128), nullable=False, unique=True)
    event_type = Column(String(40), nullable=False)
    quantity = Column(Integer, nullable=False, default=1)
    package_tier = Column(String(50), nullable=False)
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (Index("ix_customer_usage_license_created", "license_key", "created_at"),)


class CustomerActivityEvent(HostingerBase):
    __tablename__ = "customer_activity_events"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    license_key = Column(String(100), nullable=False, index=True)
    actor_email = Column(String(254), nullable=True)
    event_type = Column(String(80), nullable=False)
    entity_type = Column(String(50), nullable=True)
    entity_id = Column(String(64), nullable=True)
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (Index("ix_customer_activity_license_created", "license_key", "created_at"),)


class WordPressInstallation(HostingerBase):
    __tablename__ = "wordpress_installations"
    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    site_url = Column(String(2048), nullable=False)
    site_host = Column(String(253), nullable=False)
    admin_email = Column(String(254), nullable=False)
    customer_email = Column(String(254), nullable=True)
    wordpress_version = Column(String(30), nullable=True)
    woocommerce_version = Column(String(30), nullable=True)
    plugin_version = Column(String(30), nullable=False)
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    disconnected_at = Column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        UniqueConstraint("license_key", "site_host", name="uq_wp_installations_license_host"),
        Index("ix_wp_installations_license_created", "license_key", "created_at"),
    )


class CustomerBranding(HostingerBase):
    __tablename__ = "customer_branding"
    license_key = Column(String(100), primary_key=True)
    brand_name = Column(String(100), nullable=False)
    logo_url = Column(String(2048), nullable=True)
    primary_color = Column(String(7), nullable=False, default="#155a8a")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class AdminCustomerNote(HostingerBase):
    __tablename__ = "admin_customer_notes"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    license_key = Column(String(100), nullable=False, index=True)
    customer_email = Column(String(254), nullable=False, index=True)
    note = Column(Text, nullable=False)
    created_by = Column(String(100), nullable=False, default="admin")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class CustomerReportFile(HostingerBase):
    __tablename__ = "customer_report_files"
    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    job_id = Column(String(64), nullable=True, index=True)
    report_name = Column(String(255), nullable=False)
    storage_key = Column(String(1024), nullable=False, unique=True)
    mime_type = Column(String(100), nullable=False, default="application/pdf")
    byte_size = Column(BigInteger, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
