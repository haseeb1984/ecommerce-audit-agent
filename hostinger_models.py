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


class CustomerLoginThrottle(HostingerBase):
    """Per-email serialization row for passwordless login rate-limit decisions."""
    __tablename__ = "customer_login_throttles"
    email = Column(String(254), primary_key=True)


class CustomerEmailChangeThrottle(HostingerBase):
    """Per-license serialization row for email-change request and verification."""
    __tablename__ = "customer_email_change_throttles"
    license_key = Column(String(100), primary_key=True)


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
    workspace_id = Column(String(64), ForeignKey("agency_client_workspaces.id", ondelete="SET NULL"), nullable=True, index=True)
    request_hash = Column(String(64), nullable=False)
    batch_number = Column(Integer, nullable=False)
    batch_size = Column(Integer, nullable=False, default=10)
    total_urls = Column(Integer, nullable=False, default=0)
    queued_count = Column(Integer, nullable=False, default=0)
    processing_count = Column(Integer, nullable=False, default=0)
    completed_count = Column(Integer, nullable=False, default=0)
    failed_count = Column(Integer, nullable=False, default=0)
    cancelled_count = Column(Integer, nullable=False, default=0)
    status = Column(String(24), nullable=False, default="queued", index=True)
    available_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        UniqueConstraint("license_key", "request_id", "batch_number", name="uq_scan_batches_request_sequence"),
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
    wordpress_user_id = Column(Integer, nullable=True)
    wordpress_user_login = Column(String(60), nullable=True)
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


class WordPressSiteLinkChallenge(HostingerBase):
    """Hashed, short-lived, single-use challenge binding a WordPress user to one license."""
    __tablename__ = "wordpress_site_link_challenges"
    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        Index("ix_wp_site_link_challenges_license", "license_key"),
        Index("ix_wp_site_link_challenges_expiry", "expires_at"),
        Index("ix_wp_site_link_challenges_created", "created_at"),
        Index("ix_wp_site_link_challenges_license_created", "license_key", "created_at"),
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
    storage_key = Column(String(1024), nullable=False)
    storage_key_hash = Column(String(64), nullable=False, unique=True)
    mime_type = Column(String(100), nullable=False, default="application/pdf")
    byte_size = Column(BigInteger, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class WebsiteScanResult(HostingerBase):
    """Customer-owned scan history; PDF bytes remain in Hostinger private file storage."""
    __tablename__ = "website_scan_results"
    id = Column(String(64), primary_key=True)
    job_id = Column(String(64), nullable=False, unique=True, index=True)
    license_key = Column(String(100), nullable=False, index=True)
    website_id = Column(String(64), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    status = Column(String(24), nullable=False, default="completed")
    overall_score = Column(Integer, nullable=True)
    finding_count = Column(Integer, nullable=False, default=0)
    findings_json = Column(Text, nullable=False, default="[]")
    check_outcomes_json = Column(Text, nullable=False, default="[]")
    coverage_json = Column(Text, nullable=False, default="{}")
    summary_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        Index("ix_website_scan_results_license_created", "license_key", "created_at"),
        Index("ix_website_scan_results_website_created", "website_id", "created_at"),
    )


class AdminActionLog(HostingerBase):
    """Sanitized administrator activity; operational audit trail stored in Hostinger."""
    __tablename__ = "admin_action_logs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    action = Column(String(80), nullable=False)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(255), nullable=True)
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        Index("ix_admin_action_logs_created", "created_at", "id"),
        Index("ix_admin_action_logs_entity", "entity_type", "entity_id", "created_at"),
    )


class CustomerBillingEvent(HostingerBase):
    """Customer-visible payment/subscription event mirror; license authority stays in PostgreSQL."""
    __tablename__ = "customer_billing_events"
    event_id = Column(String(255), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    recipient_email = Column(String(254), nullable=False, index=True)
    status = Column(String(40), nullable=False)
    transaction_id = Column(String(100), nullable=True, index=True)
    subscription_id = Column(String(100), nullable=True, index=True)
    paddle_customer_id = Column(String(100), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        Index("ix_customer_billing_license_created", "license_key", "created_at"),
        Index("ix_customer_billing_email_created", "recipient_email", "created_at"),
    )


class CustomerEmailIdentitySyncOutbox(HostingerBase):
    """Durable delivery of verified email changes to PostgreSQL billing records."""
    __tablename__ = "customer_email_identity_sync_outbox"
    id = Column(String(64), primary_key=True)
    license_key = Column(String(100), nullable=False, index=True)
    old_email = Column(String(254), nullable=False, index=True)
    new_email = Column(String(254), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="pending", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    last_error = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    processed_at = Column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        Index("ix_email_identity_outbox_due", "status", "next_attempt_at", "created_at"),
    )


class OperationalDiagnosticEvent(HostingerBase):
    """Sanitized service diagnostics; license identifiers are external keys, not PG FKs."""
    __tablename__ = "operational_diagnostic_events"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    event_type = Column(String(80), nullable=False)
    license_key = Column(String(100), nullable=True, index=True)
    domain = Column(String(255), nullable=True)
    error_type = Column(String(120), nullable=True)
    legacy_source_id = Column(BigInteger, nullable=True, unique=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        Index("ix_operational_diagnostic_created", "created_at", "id"),
        Index("ix_operational_diagnostic_type_created", "event_type", "created_at"),
    )


class AgencyAccount(HostingerBase):
    """Business-plan agency tenant; one agency owner per Business license."""
    __tablename__ = "agency_accounts"
    id = Column(String(64), primary_key=True)
    owner_license_key = Column(String(100), nullable=False, unique=True, index=True)
    owner_email = Column(String(254), nullable=False, index=True)
    status = Column(String(24), nullable=False, default="active", index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)


class AgencyClientWorkspace(HostingerBase):
    """Isolated client workspace owned by exactly one agency tenant."""
    __tablename__ = "agency_client_workspaces"
    id = Column(String(64), primary_key=True)
    agency_id = Column(String(64), ForeignKey("agency_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    display_name = Column(String(160), nullable=False)
    external_reference = Column(String(120), nullable=True)
    status = Column(String(24), nullable=False, default="active", index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    __table_args__ = (
        UniqueConstraint("agency_id", "external_reference", name="uq_agency_workspace_external_ref"),
        Index("ix_agency_workspace_tenant_status", "agency_id", "status", "created_at"),
    )


class AgencyClientWebsite(HostingerBase):
    """A client's store connection; each workspace has at most one active store."""
    __tablename__ = "agency_client_websites"
    id = Column(String(64), primary_key=True)
    agency_id = Column(String(64), ForeignKey("agency_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), ForeignKey("agency_client_workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    site_url = Column(String(2048), nullable=False)
    site_host = Column(String(253), nullable=False)
    admin_email = Column(String(254), nullable=True)
    connection_type = Column(String(24), nullable=False, default="wordpress_plugin")
    status = Column(String(20), nullable=False, default="pending", index=True)
    site_token_hash = Column(String(64), nullable=True, unique=True)
    plugin_version = Column(String(30), nullable=True)
    wordpress_version = Column(String(30), nullable=True)
    woocommerce_version = Column(String(30), nullable=True)
    connected_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    disconnected_at = Column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        UniqueConstraint("workspace_id", "site_host", name="uq_agency_workspace_site_host"),
        UniqueConstraint("agency_id", "site_host", name="uq_agency_site_host"),
        Index("ix_agency_client_site_tenant_workspace", "agency_id", "workspace_id", "status"),
    )


class AgencyWebsiteConnectChallenge(HostingerBase):
    """One-time owner-issued proof token used to authorize a client WordPress site."""
    __tablename__ = "agency_website_connect_challenges"
    id = Column(String(64), primary_key=True)
    agency_id = Column(String(64), ForeignKey("agency_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), ForeignKey("agency_client_workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class AgencyTeamLoginChallenge(HostingerBase):
    """Short-lived email OTP challenge for an accepted agency team member."""
    __tablename__ = "agency_team_login_challenges"
    id = Column(String(64), primary_key=True)
    agency_id = Column(String(64), ForeignKey("agency_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    team_member_id = Column(String(64), ForeignKey("agency_team_members.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(254), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (Index("ix_agency_team_login_email_active", "email", "consumed_at"),)


class AgencyTeamSession(HostingerBase):
    """Opaque revocable session for an agency team member, independent of owner license."""
    __tablename__ = "agency_team_sessions"
    token_hash = Column(String(64), primary_key=True)
    agency_id = Column(String(64), ForeignKey("agency_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    team_member_id = Column(String(64), ForeignKey("agency_team_members.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(254), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    user_agent = Column(String(500), nullable=True)


class AgencyTeamMember(HostingerBase):
    """Agency-level user invitation and role; workspace grants are separate."""
    __tablename__ = "agency_team_members"
    id = Column(String(64), primary_key=True)
    agency_id = Column(String(64), ForeignKey("agency_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(254), nullable=False)
    normalized_email = Column(String(254), nullable=False)
    role = Column(String(24), nullable=False, default="analyst")
    status = Column(String(24), nullable=False, default="invited", index=True)
    invited_by = Column(String(254), nullable=False)
    invitation_token_hash = Column(String(64), nullable=True, unique=True)
    invitation_expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    accepted_at = Column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        UniqueConstraint("agency_id", "normalized_email", name="uq_agency_team_normalized_email"),
        Index("ix_agency_team_tenant_status", "agency_id", "status"),
    )


class AgencyWorkspaceAccess(HostingerBase):
    """Explicit per-workspace authorization for an agency team member."""
    __tablename__ = "agency_workspace_access"
    id = Column(String(64), primary_key=True)
    agency_id = Column(String(64), ForeignKey("agency_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), ForeignKey("agency_client_workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    team_member_id = Column(String(64), ForeignKey("agency_team_members.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(24), nullable=False, default="viewer")
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        UniqueConstraint("workspace_id", "team_member_id", name="uq_agency_workspace_member"),
        Index("ix_agency_workspace_access_tenant", "agency_id", "workspace_id"),
    )


class AgencyUsageEvent(HostingerBase):
    """Tenant/workspace usage ledger for Business shared monthly audit accounting."""
    __tablename__ = "agency_usage_events"
    id = Column(String(64), primary_key=True)
    agency_id = Column(String(64), ForeignKey("agency_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), ForeignKey("agency_client_workspaces.id", ondelete="CASCADE"), nullable=True, index=True)
    event_type = Column(String(40), nullable=False)
    quantity = Column(Integer, nullable=False, default=1)
    period_start = Column(DateTime(timezone=True), nullable=False, index=True)
    period_end = Column(DateTime(timezone=True), nullable=False)
    source_reference = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (
        Index("ix_agency_usage_tenant_period", "agency_id", "period_start", "event_type"),
        UniqueConstraint("agency_id", "source_reference", name="uq_agency_usage_source_reference"),
    )
