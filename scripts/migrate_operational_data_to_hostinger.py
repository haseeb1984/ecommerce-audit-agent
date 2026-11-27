"""Copy legacy customer-operation records from Supabase PostgreSQL to Hostinger MySQL.

Safe by default: this command only reports source row counts. Pass --apply to
copy rows. It never deletes or modifies source PostgreSQL records, and existing
Hostinger rows are preserved. Apply only after both schemas are provisioned and
a database backup has been taken.
"""
import argparse
import asyncio
import hashlib
import logging
from datetime import datetime, timezone

from sqlalchemy import func, literal, select, tuple_, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal
from hostinger_database import HostingerAsyncSessionLocal
from models import (
    AccountEmailChangeChallenge,
    AccountLoginChallenge,
    AccountSession,
    PaymentWebhookEvent,
    SaaSAdminCustomerNote,
    SaaSAdminActionLog,
    SaaSOperationEvent,
    SoftwareLicense,
    WhiteLabelBranding,
    WordPressSite,
)
from hostinger_models import (
    AdminCustomerNote,
    AdminActionLog,
    CustomerAccount,
    CustomerBranding,
    CustomerEmailChangeChallenge,
    CustomerLoginChallenge,
    CustomerSession,
    CustomerBillingEvent,
    OperationalDiagnosticEvent,
    WordPressInstallation,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("operational_data_migration")


def _legacy_account_id(license_key: str, email: str) -> str:
    digest = hashlib.sha256(f"{license_key.lower()}:{email.lower()}".encode()).hexdigest()
    return f"legacy-{digest[:48]}"


def _migration_email(value: str | None, maximum: int = 254) -> str | None:
    """Normalize an email only when it fits the destination column without truncation."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if not normalized or len(normalized) > maximum:
        return None
    return normalized


def _wordpress_installation_payload(row, license_key_by_id):
    """Map a WordPress installation only when its required admin email is representable."""
    license_key = license_key_by_id.get(row.license_id)
    admin_email = _migration_email(row.admin_email)
    if not license_key or not admin_email:
        return None
    return {
        "id": row.id,
        "license_key": license_key,
        "site_url": row.site_url,
        "site_host": row.site_host,
        "admin_email": admin_email,
        "customer_email": _migration_email(row.customer_email),
        "wordpress_version": row.wordpress_version,
        "woocommerce_version": row.woocommerce_version,
        "plugin_version": row.plugin_version,
        "status": row.status,
        "created_at": row.created_at,
        "last_seen_at": row.last_seen_at,
        "disconnected_at": row.disconnected_at,
    }


async def _stream_rows(source: AsyncSession, model):
    """Yield source ORM rows without materializing the complete table."""
    result = await source.stream_scalars(
        select(model).execution_options(yield_per=MIGRATION_BATCH_SIZE)
    )
    try:
        async for row in result:
            yield row
    finally:
        await result.close()


def _normalized_value(value):
    """Normalize database-returned datetimes before cross-engine comparisons."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return value


def _mismatched_fields(existing, expected_values):
    """Return field names whose persisted target values differ from the source mapping."""
    return sorted(
        name for name, expected in expected_values.items()
        if _normalized_value(getattr(existing, name, None)) != _normalized_value(expected)
    )


def _verification_gaps(reports):
    """Return mapped rows missing from Hostinger or present with divergent fields."""
    gaps = {}
    for name, report in reports.items():
        missing = int(report.get("to_copy", 0))
        mismatched = int(report.get("field_mismatches", 0))
        if missing or mismatched:
            gaps[name] = {"missing": missing, "field_mismatches": mismatched}
    return gaps


def _apply_blockers(reports):
    """Identify source rows that apply could not safely migrate or reconcile."""
    blockers = {}
    unresolved_fields = (
        "unmapped",
        "overlength_or_empty_email",
        "ambiguous_license_mapping",
        "unmapped_email",
    )
    for name, report in reports.items():
        unresolved = {
            field: int(report.get(field, 0))
            for field in unresolved_fields
            if int(report.get(field, 0)) > 0
        }
        mismatched = int(report.get("field_mismatches", 0))
        if unresolved or mismatched:
            blockers[name] = {
                "unresolved": unresolved,
                "field_mismatches": mismatched,
            }
    return blockers


def _support_note_migration_statement():
    """Join notes to database-aggregated, unambiguous billing ownership."""
    normalized_billing_email = func.lower(func.trim(PaymentWebhookEvent.recipient_email)).label("email")
    billing_ownership = (
        select(
            normalized_billing_email,
            func.count(func.distinct(SoftwareLicense.license_key)).label("license_count"),
            func.min(SoftwareLicense.license_key).label("license_key"),
        )
        .join(SoftwareLicense, SoftwareLicense.id == PaymentWebhookEvent.license_id)
        .where(
            PaymentWebhookEvent.recipient_email.is_not(None),
            func.trim(PaymentWebhookEvent.recipient_email) != "",
        )
        .group_by(normalized_billing_email)
    ).subquery("billing_email_license_ownership")
    normalized_note_email = func.lower(func.trim(SaaSAdminCustomerNote.customer_email))
    return (
        select(
            SaaSAdminCustomerNote,
            billing_ownership.c.license_count,
            billing_ownership.c.license_key,
        )
        .outerjoin(billing_ownership, billing_ownership.c.email == normalized_note_email)
        .order_by(SaaSAdminCustomerNote.id.asc())
        .execution_options(yield_per=MIGRATION_BATCH_SIZE)
    )

def _account_candidate_statement():
    """Deduplicate legacy account identities in PostgreSQL before streaming."""
    sessions = (
        select(SoftwareLicense.license_key.label("license_key"),
            func.lower(func.trim(AccountSession.email)).label("email"),
            SoftwareLicense.client_name.label("display_name"),
            AccountSession.created_at.label("candidate_created_at"),
            AccountSession.created_at.label("candidate_updated_at"),
            literal(0).label("source_priority"),
        ).join(SoftwareLicense, SoftwareLicense.id == AccountSession.license_id)
        .where(AccountSession.email.is_not(None), func.trim(AccountSession.email) != "")
    )
    site_email = func.coalesce(func.nullif(func.trim(WordPressSite.customer_email), ""),
        func.nullif(func.trim(WordPressSite.admin_email), ""))
    sites = (
        select(SoftwareLicense.license_key.label("license_key"),
            func.lower(site_email).label("email"),
            SoftwareLicense.client_name.label("display_name"),
            WordPressSite.created_at.label("candidate_created_at"),
            WordPressSite.created_at.label("candidate_updated_at"),
            literal(1).label("source_priority"),
        ).join(SoftwareLicense, SoftwareLicense.id == WordPressSite.license_id)
        .where(site_email.is_not(None))
    )
    billing = (
        select(SoftwareLicense.license_key.label("license_key"),
            func.lower(func.trim(PaymentWebhookEvent.recipient_email)).label("email"),
            SoftwareLicense.client_name.label("display_name"),
            PaymentWebhookEvent.created_at.label("candidate_created_at"),
            func.coalesce(PaymentWebhookEvent.updated_at, PaymentWebhookEvent.created_at).label("candidate_updated_at"),
            literal(2).label("source_priority"),
        ).join(SoftwareLicense, SoftwareLicense.id == PaymentWebhookEvent.license_id)
        .where(PaymentWebhookEvent.recipient_email.is_not(None), func.trim(PaymentWebhookEvent.recipient_email) != "")
    )
    candidates = union_all(sessions, sites, billing).subquery("legacy_account_candidates")
    ranked = select(candidates.c.license_key, candidates.c.email, candidates.c.display_name,
        candidates.c.candidate_created_at, candidates.c.candidate_updated_at,
        func.row_number().over(partition_by=(candidates.c.license_key, candidates.c.email),
            order_by=(candidates.c.source_priority.asc(), candidates.c.candidate_updated_at.desc(),
                candidates.c.candidate_created_at.desc())).label("candidate_rank"),
    ).subquery("ranked_legacy_account_candidates")
    return (
        select(ranked.c.license_key, ranked.c.email, ranked.c.display_name,
            ranked.c.candidate_created_at, ranked.c.candidate_updated_at)
        .where(ranked.c.candidate_rank == 1)
        .order_by(ranked.c.license_key.asc(), ranked.c.email.asc())
        .execution_options(yield_per=MIGRATION_BATCH_SIZE)
    )

MIGRATION_BATCH_SIZE = 500


async def _copy_rows(source, target, source_model, target_model, transform, key_name, stage_missing: bool, resolve_license_keys: bool = False):
    """Stream source rows and reconcile target keys in bounded batches."""
    source_count = 0
    copied = 0
    skipped = 0
    already_present = 0
    unmapped = 0
    mismatch_count = 0
    mismatch_fields = set()
    batch = []

    async def reconcile_batch(rows):
        nonlocal copied, skipped, already_present, unmapped, mismatch_count
        expected_by_key = {}
        license_key_by_id = {}
        if resolve_license_keys:
            license_ids = {
                row.license_id for row in rows
                if getattr(row, "license_id", None) is not None
            }
            if license_ids:
                license_result = await source.execute(
                    select(SoftwareLicense.id, SoftwareLicense.license_key).where(
                        SoftwareLicense.id.in_(license_ids)
                    )
                )
                license_key_by_id = {
                    row.id: row.license_key for row in license_result
                }
        for row in rows:
            values = transform(row, license_key_by_id) if resolve_license_keys else transform(row)
            if values is None:
                skipped += 1
                unmapped += 1
                continue
            expected_by_key[values[key_name]] = values

        if not expected_by_key:
            return

        key_column = getattr(target_model, key_name)
        result = await target.execute(
            select(target_model).where(key_column.in_(list(expected_by_key)))
        )
        existing_by_key = {
            getattr(existing, key_name): existing
            for existing in result.scalars()
        }
        for key_value, values in expected_by_key.items():
            existing = existing_by_key.get(key_value)
            if existing is None:
                if stage_missing:
                    target.add(target_model(**values))
                copied += 1
                continue
            skipped += 1
            already_present += 1
            fields = _mismatched_fields(existing, values)
            if fields:
                mismatch_count += 1
                mismatch_fields.update(fields)

        if stage_missing:
            # Each committed batch is independently safe to replay: existing
            # target rows are never overwritten and source rows are retained.
            await target.commit()
            logger.info(
                "Committed operational migration batch: table=%s rows=%s",
                target_model.__tablename__, len(expected_by_key),
            )

    statement = select(source_model).execution_options(yield_per=MIGRATION_BATCH_SIZE)
    result = await source.stream_scalars(statement)
    try:
        async for row in result:
            source_count += 1
            batch.append(row)
            if len(batch) >= MIGRATION_BATCH_SIZE:
                await reconcile_batch(batch)
                batch.clear()
        if batch:
            await reconcile_batch(batch)
    finally:
        await result.close()

    return {
        "source": source_count,
        "to_copy": copied,
        "already_present_or_unmapped": skipped,
        "already_present": already_present,
        "unmapped": unmapped,
        "field_mismatches": mismatch_count,
        "mismatched_fields": sorted(mismatch_fields),
        "batch_size": MIGRATION_BATCH_SIZE,
    }


async def migrate(apply_changes: bool, verify_only: bool = False) -> bool:
    if AsyncSessionLocal is None or HostingerAsyncSessionLocal is None:
        raise RuntimeError("DATABASE_URL and HOSTINGER_DATABASE_URL must both be configured.")
    async with AsyncSessionLocal() as source, HostingerAsyncSessionLocal() as target:
        reports = {}

        # Restore identities from a database-side deduplicated union, avoiding
        # an unbounded Python dictionary of every distinct customer account.
        account_copied = 0
        account_skipped = 0
        account_mismatch_count = 0
        account_mismatch_fields = set()
        account_candidate_count = 0
        account_overlength_email_count = 0
        candidate_result = await source.stream(_account_candidate_statement())
        account_batch = []

        async def reconcile_account_batch(rows):
            nonlocal account_copied, account_skipped, account_mismatch_count
            nonlocal account_overlength_email_count
            expected_by_identity = {}
            for row in rows:
                normalized_email = _migration_email(row.email)
                if normalized_email is None:
                    account_overlength_email_count += 1
                    continue
                expected_by_identity[(row.license_key, normalized_email)] = {
                    "id": _legacy_account_id(row.license_key, normalized_email),
                    "license_key": row.license_key,
                    "email": normalized_email,
                    "display_name": row.display_name,
                    "status": "active",
                    "created_at": row.candidate_created_at,
                    "updated_at": row.candidate_updated_at,
                }
            if not expected_by_identity:
                return
            identity_keys = list(expected_by_identity)
            existing_result = await target.execute(
                select(CustomerAccount).where(
                    tuple_(CustomerAccount.license_key, CustomerAccount.email).in_(identity_keys)
                )
            )
            existing_by_identity = {
                (row.license_key, row.email): row for row in existing_result.scalars()
            }
            for identity, expected_account in expected_by_identity.items():
                existing = existing_by_identity.get(identity)
                if existing is None:
                    if apply_changes:
                        target.add(CustomerAccount(**expected_account))
                    account_copied += 1
                else:
                    account_skipped += 1
                    fields = _mismatched_fields(existing, expected_account)
                    if fields:
                        account_mismatch_count += 1
                        account_mismatch_fields.update(fields)
            if apply_changes:
                await target.commit()
                logger.info("Committed customer-account migration batch: rows=%s", len(expected_by_identity))

        try:
            async for row in candidate_result:
                account_candidate_count += 1
                account_batch.append(row)
                if len(account_batch) >= MIGRATION_BATCH_SIZE:
                    await reconcile_account_batch(account_batch)
                    account_batch.clear()
            if account_batch:
                await reconcile_account_batch(account_batch)
        finally:
            await candidate_result.close()
        reports["customer_accounts"] = {
            "source_candidates": account_candidate_count,
            "overlength_or_empty_email": account_overlength_email_count,
            "to_copy": account_copied,
            "already_present": account_skipped,
            "field_mismatches": account_mismatch_count,
            "mismatched_fields": sorted(account_mismatch_fields),
        }

        reports["customer_login_challenges"] = await _copy_rows(
            source, target, AccountLoginChallenge, CustomerLoginChallenge,
            lambda row, license_key_by_id: ({
                "id": row.id,
                "license_key": license_key_by_id.get(row.license_id),
                "email": _migration_email(row.email),
                "code_hash": row.code_hash,
                "expires_at": row.expires_at,
                "attempts": row.attempts,
                "consumed_at": row.consumed_at,
                "created_at": row.created_at,
            } if license_key_by_id.get(row.license_id) and _migration_email(row.email) else None),
            "id",
            stage_missing=apply_changes,
            resolve_license_keys=True,
        )
        reports["customer_sessions"] = await _copy_rows(
            source, target, AccountSession, CustomerSession,
            lambda row, license_key_by_id: ({
                "token_hash": row.token_hash,
                "license_key": license_key_by_id.get(row.license_id),
                "email": _migration_email(row.email),
                "expires_at": row.expires_at,
                "revoked_at": row.revoked_at,
                "created_at": row.created_at,
                "last_seen_at": row.last_seen_at,
                "public_id": row.public_id,
                "user_agent": row.user_agent,
            } if license_key_by_id.get(row.license_id) and _migration_email(row.email) else None),
            "token_hash",
            stage_missing=apply_changes,
            resolve_license_keys=True,
        )
        reports["customer_email_change_challenges"] = await _copy_rows(
            source, target, AccountEmailChangeChallenge, CustomerEmailChangeChallenge,
            lambda row, license_key_by_id: ({
                "id": row.id,
                "license_key": license_key_by_id.get(row.license_id),
                "old_email": _migration_email(row.old_email),
                "new_email": _migration_email(row.new_email),
                "code_hash": row.code_hash,
                "expires_at": row.expires_at,
                "attempts": row.attempts,
                "consumed_at": row.consumed_at,
                "created_at": row.created_at,
            } if license_key_by_id.get(row.license_id) and _migration_email(row.old_email) and _migration_email(row.new_email) else None),
            "id",
            stage_missing=apply_changes,
            resolve_license_keys=True,
        )
        reports["wordpress_installations"] = await _copy_rows(
            source, target, WordPressSite, WordPressInstallation,
            _wordpress_installation_payload,
            "id",
            stage_missing=apply_changes,
            resolve_license_keys=True,
        )
        reports["customer_branding"] = await _copy_rows(
            source, target, WhiteLabelBranding, CustomerBranding,
            lambda row, license_key_by_id: ({
                "license_key": license_key_by_id.get(row.license_id),
                "brand_name": row.brand_name,
                "logo_url": row.logo_url,
                "primary_color": row.primary_color,
                "updated_at": row.updated_at,
            } if license_key_by_id.get(row.license_id) else None),
            "license_key",
            stage_missing=apply_changes,
            resolve_license_keys=True,
        )

        reports["customer_billing_events"] = await _copy_rows(
            source, target, PaymentWebhookEvent, CustomerBillingEvent,
            lambda row, license_key_by_id: ({
                "event_id": row.event_id,
                "license_key": license_key_by_id.get(row.license_id),
                "recipient_email": _migration_email(row.recipient_email),
                "status": row.status,
                "transaction_id": row.transaction_id,
                "subscription_id": row.subscription_id,
                "paddle_customer_id": row.paddle_customer_id,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            } if license_key_by_id.get(row.license_id) and _migration_email(row.recipient_email) else None),
            "event_id",
            stage_missing=apply_changes,
            resolve_license_keys=True,
        )
        reports["admin_action_logs"] = await _copy_rows(
            source, target, SaaSAdminActionLog, AdminActionLog,
            lambda row: ({
                "id": row.id,
                "action": row.action,
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "details_json": row.details_json,
                "created_at": row.created_at,
            }),
            "id",
            stage_missing=apply_changes,
        )
        reports["operational_diagnostic_events"] = await _copy_rows(
            source, target, SaaSOperationEvent, OperationalDiagnosticEvent,
            lambda row, license_key_by_id: ({
                "legacy_source_id": row.id,
                "event_type": row.event_type,
                "license_key": license_key_by_id.get(row.license_id),
                "domain": row.domain,
                "error_type": row.error_type,
                "created_at": row.created_at,
            }),
            "legacy_source_id",
            stage_missing=apply_changes,
            resolve_license_keys=True,
        )

        # Resolve each note's email ownership in SQL; no email->license map is
        # materialized in Python, even when the legacy billing table is large.
        note_copied = 0
        note_already_present = 0
        note_ambiguous = 0
        note_unmapped = 0
        note_mismatch_count = 0
        note_mismatch_fields = set()
        note_source_count = 0
        note_batch = []

        async def reconcile_note_batch(rows):
            nonlocal note_copied, note_already_present, note_ambiguous, note_unmapped
            nonlocal note_mismatch_count
            expected_by_id = {}
            for joined_row in rows:
                row = joined_row[0]
                license_count = joined_row[1]
                license_key = joined_row[2]
                if license_count is None or license_count == 0:
                    note_unmapped += 1
                    continue
                if license_count > 1:
                    note_ambiguous += 1
                    continue
                email = row.customer_email.strip().lower()
                if not license_key:
                    note_unmapped += 1
                    continue
                expected_by_id[row.id] = {
                    "id": row.id,
                    "license_key": license_key,
                    "customer_email": email,
                    "note": row.note,
                    "created_by": row.created_by,
                    "created_at": row.created_at,
                }
            if not expected_by_id:
                return
            existing_result = await target.execute(
                select(AdminCustomerNote).where(
                    AdminCustomerNote.id.in_(list(expected_by_id))
                )
            )
            existing_by_id = {row.id: row for row in existing_result.scalars()}
            for note_id, expected_note in expected_by_id.items():
                existing = existing_by_id.get(note_id)
                if existing is None:
                    if apply_changes:
                        target.add(AdminCustomerNote(**expected_note))
                    note_copied += 1
                else:
                    note_already_present += 1
                    fields = _mismatched_fields(existing, expected_note)
                    if fields:
                        note_mismatch_count += 1
                        note_mismatch_fields.update(fields)
            if apply_changes:
                await target.commit()
                logger.info("Committed support-note migration batch: rows=%s", len(expected_by_id))

        note_result = await source.stream(_support_note_migration_statement())
        try:
            async for row in note_result:
                note_source_count += 1
                note_batch.append(row)
                if len(note_batch) >= MIGRATION_BATCH_SIZE:
                    await reconcile_note_batch(note_batch)
                    note_batch.clear()
            if note_batch:
                await reconcile_note_batch(note_batch)
        finally:
            await note_result.close()
        reports["admin_customer_notes"] = {
            "source": note_source_count,
            "to_copy": note_copied,
            "already_present": note_already_present,
            "ambiguous_license_mapping": note_ambiguous,
            "unmapped_email": note_unmapped,
            "field_mismatches": note_mismatch_count,
            "mismatched_fields": sorted(note_mismatch_fields),
        }

        for name, report in reports.items():
            logger.info("%s: %s", name, report)
        if apply_changes:
            await target.commit()
            blockers = _apply_blockers(reports)
            if blockers:
                for name, details in blockers.items():
                    logger.error("%s: migration requires manual reconciliation: %s", name, details)
                logger.error(
                    "Operational migration applied partially. All committed batches are retained; "
                    "unresolved rows and existing field mismatches must be reconciled before cutover."
                )
                return False
            logger.info("Hostinger operational records copied. PostgreSQL source records were retained.")
            return True

        # Verification uses the same complete source-to-target mapping as the
        # dry run, but turns any still-missing mapped row into a failing result.
        # The transaction is always rolled back; this mode never writes.
        await target.rollback()
        if verify_only:
            gaps = _verification_gaps(reports)
            for name, counts in gaps.items():
                if counts["missing"]:
                    logger.error(
                        "%s: %s mapped source rows are still missing in Hostinger",
                        name, counts["missing"],
                    )
                if counts["field_mismatches"]:
                    logger.error(
                        "%s: %s existing target rows have divergent mapped fields",
                        name, counts["field_mismatches"],
                    )
            if gaps:
                logger.error("Operational migration verification FAILED. No records were written or overwritten.")
                return False
            logger.info("Operational migration verification PASSED. All mapped source rows are present and field-matched in Hostinger.")
            return True

        blockers = _apply_blockers(reports)
        if blockers:
            for name, details in blockers.items():
                logger.error(
                    "%s: migration preflight requires manual reconciliation: %s",
                    name, details,
                )
            logger.error(
                "Dry run found migration blockers. No Hostinger records were written; "
                "resolve the reported issues before applying."
            )
            return False

        logger.info("Dry run only. No Hostinger records were written; no migration blockers detected.")
        return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--apply",
        action="store_true",
        help="Write missing records to Hostinger. Default behavior is dry-run only.",
    )
    modes.add_argument(
        "--verify",
        action="store_true",
        help="Read-only check that every mappable PostgreSQL source record already exists in Hostinger.",
    )
    args = parser.parse_args()
    if args.apply:
        # Run the complete source-to-target reconciliation before the first
        # INSERT. This prevents known mapping/mismatch blockers from producing
        # an avoidable partially applied migration. Keep source writes frozen
        # between preflight and apply so the reviewed snapshot does not drift.
        logger.info("Running read-only preflight before any Hostinger writes.")
        preflight_ok = asyncio.run(migrate(apply_changes=False))
        if not preflight_ok:
            logger.error("Apply aborted before writes. Resolve preflight blockers and rerun.")
            raise SystemExit(1)
        verified = asyncio.run(migrate(apply_changes=True))
    else:
        verified = asyncio.run(migrate(apply_changes=False, verify_only=args.verify))

    if (args.apply or args.verify) and not verified:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
