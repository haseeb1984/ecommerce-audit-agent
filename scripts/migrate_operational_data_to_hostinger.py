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
from itertools import islice
from datetime import datetime, timezone

from sqlalchemy import select, tuple_
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


async def _license_map(source: AsyncSession) -> dict[int, SoftwareLicense]:
    """Load only the license identity fields needed for tenant mapping."""
    result = await source.stream(
        select(SoftwareLicense.id, SoftwareLicense.license_key, SoftwareLicense.client_name)
        .execution_options(yield_per=MIGRATION_BATCH_SIZE)
    )
    licenses = {}
    try:
        async for row in result:
            licenses[row.id] = row
    finally:
        await result.close()
    return licenses


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


def _billing_license_map(billing_rows, license_key_by_id):
    """Resolve email ownership only when every billing event agrees on one license."""
    candidates = {}
    for row in billing_rows:
        email = (row.recipient_email or "").strip().lower()
        license_key = license_key_by_id.get(row.license_id)
        if email and license_key:
            candidates.setdefault(email, set()).add(license_key)
    return _resolve_billing_license_candidates(candidates)


def _resolve_billing_license_candidates(candidates):
    resolved = {
        email: next(iter(license_keys))
        for email, license_keys in candidates.items()
        if len(license_keys) == 1
    }
    ambiguous = {
        email for email, license_keys in candidates.items()
        if len(license_keys) > 1
    }
    return resolved, ambiguous


MIGRATION_BATCH_SIZE = 500


async def _copy_rows(source, target, source_model, target_model, transform, key_name, stage_missing: bool):
    """Stream source rows and reconcile target keys in bounded batches."""
    source_count = 0
    copied = 0
    skipped = 0
    mismatch_count = 0
    mismatch_fields = set()
    batch = []

    async def reconcile_batch(rows):
        nonlocal copied, skipped, mismatch_count
        expected_by_key = {}
        for row in rows:
            values = transform(row)
            if values is None:
                skipped += 1
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
        "field_mismatches": mismatch_count,
        "mismatched_fields": sorted(mismatch_fields),
        "batch_size": MIGRATION_BATCH_SIZE,
    }


async def migrate(apply_changes: bool, verify_only: bool = False) -> bool:
    if AsyncSessionLocal is None or HostingerAsyncSessionLocal is None:
        raise RuntimeError("DATABASE_URL and HOSTINGER_DATABASE_URL must both be configured.")
    async with AsyncSessionLocal() as source, HostingerAsyncSessionLocal() as target:
        licenses = await _license_map(source)
        license_key_by_id = {key: value.license_key for key, value in licenses.items()}
        reports = {}

        # Restore customer account identities first, deriving them from legacy
        # sessions, linked WordPress installations and verified billing emails.
        account_candidates = {}
        async for row in _stream_rows(source, AccountSession):
            license_key = license_key_by_id.get(row.license_id)
            if license_key:
                account_candidates[(license_key, row.email.lower())] = (
                    row.email.lower(), licenses[row.license_id].client_name, row.created_at
                )
        async for row in _stream_rows(source, WordPressSite):
            license_key = license_key_by_id.get(row.license_id)
            email = (row.customer_email or row.admin_email or "").strip().lower()
            if license_key and email:
                account_candidates.setdefault(
                    (license_key, email), (email, licenses[row.license_id].client_name, row.created_at)
                )

        billing_license_candidates = {}
        billing_statement = (
            select(PaymentWebhookEvent)
            .where(PaymentWebhookEvent.license_id.is_not(None))
            .order_by(PaymentWebhookEvent.updated_at.desc(), PaymentWebhookEvent.created_at.desc())
            .execution_options(yield_per=MIGRATION_BATCH_SIZE)
        )
        billing_result = await source.stream_scalars(billing_statement)
        try:
            async for row in billing_result:
                license_key = license_key_by_id.get(row.license_id)
                email = (row.recipient_email or "").strip().lower()
                if license_key and email:
                    account_candidates.setdefault(
                        (license_key, email),
                        (email, licenses[row.license_id].client_name, row.created_at)
                    )
                    billing_license_candidates.setdefault(email, set()).add(license_key)
        finally:
            await billing_result.close()

        account_copied = 0
        account_skipped = 0
        account_mismatch_count = 0
        account_mismatch_fields = set()
        account_candidate_iterator = iter(account_candidates.items())
        while True:
            candidate_batch = list(islice(account_candidate_iterator, MIGRATION_BATCH_SIZE))
            if not candidate_batch:
                break
            expected_by_identity = {}
            for (license_key, email), (normalized_email, display_name, created_at) in candidate_batch:
                expected_by_identity[(license_key, email)] = {
                    "id": _legacy_account_id(license_key, normalized_email),
                    "license_key": license_key,
                    "email": normalized_email,
                    "display_name": display_name,
                    "status": "active",
                    "created_at": created_at,
                    "updated_at": created_at,
                }
            identity_keys = list(expected_by_identity)
            existing_result = await target.execute(
                select(CustomerAccount).where(
                    tuple_(CustomerAccount.license_key, CustomerAccount.email).in_(identity_keys)
                )
            )
            existing_by_identity = {
                (row.license_key, row.email): row
                for row in existing_result.scalars()
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
                logger.info(
                    "Committed customer-account migration batch: rows=%s",
                    len(expected_by_identity),
                )
        reports["customer_accounts"] = {
            "source_candidates": len(account_candidates),
            "to_copy": account_copied,
            "already_present": account_skipped,
            "field_mismatches": account_mismatch_count,
            "mismatched_fields": sorted(account_mismatch_fields),
        }

        reports["customer_login_challenges"] = await _copy_rows(
            source, target, AccountLoginChallenge, CustomerLoginChallenge,
            lambda row: ({
                "id": row.id,
                "license_key": license_key_by_id.get(row.license_id),
                "email": row.email.lower(),
                "code_hash": row.code_hash,
                "expires_at": row.expires_at,
                "attempts": row.attempts,
                "consumed_at": row.consumed_at,
                "created_at": row.created_at,
            } if license_key_by_id.get(row.license_id) else None),
            "id",
            stage_missing=apply_changes,
        )
        reports["customer_sessions"] = await _copy_rows(
            source, target, AccountSession, CustomerSession,
            lambda row: ({
                "token_hash": row.token_hash,
                "license_key": license_key_by_id.get(row.license_id),
                "email": row.email.lower(),
                "expires_at": row.expires_at,
                "revoked_at": row.revoked_at,
                "created_at": row.created_at,
                "last_seen_at": row.last_seen_at,
                "public_id": row.public_id,
                "user_agent": row.user_agent,
            } if license_key_by_id.get(row.license_id) else None),
            "token_hash",
            stage_missing=apply_changes,
        )
        reports["customer_email_change_challenges"] = await _copy_rows(
            source, target, AccountEmailChangeChallenge, CustomerEmailChangeChallenge,
            lambda row: ({
                "id": row.id,
                "license_key": license_key_by_id.get(row.license_id),
                "old_email": row.old_email.lower(),
                "new_email": row.new_email.lower(),
                "code_hash": row.code_hash,
                "expires_at": row.expires_at,
                "attempts": row.attempts,
                "consumed_at": row.consumed_at,
                "created_at": row.created_at,
            } if license_key_by_id.get(row.license_id) else None),
            "id",
            stage_missing=apply_changes,
        )
        reports["wordpress_installations"] = await _copy_rows(
            source, target, WordPressSite, WordPressInstallation,
            lambda row: ({
                "id": row.id,
                "license_key": license_key_by_id.get(row.license_id),
                "site_url": row.site_url,
                "site_host": row.site_host,
                "admin_email": row.admin_email,
                "customer_email": row.customer_email,
                "wordpress_version": row.wordpress_version,
                "woocommerce_version": row.woocommerce_version,
                "plugin_version": row.plugin_version,
                "status": row.status,
                "created_at": row.created_at,
                "last_seen_at": row.last_seen_at,
                "disconnected_at": row.disconnected_at,
            } if license_key_by_id.get(row.license_id) else None),
            "id",
            stage_missing=apply_changes,
        )
        reports["customer_branding"] = await _copy_rows(
            source, target, WhiteLabelBranding, CustomerBranding,
            lambda row: ({
                "license_key": license_key_by_id.get(row.license_id),
                "brand_name": row.brand_name,
                "logo_url": row.logo_url,
                "primary_color": row.primary_color,
                "updated_at": row.updated_at,
            } if license_key_by_id.get(row.license_id) else None),
            "license_key",
            stage_missing=apply_changes,
        )

        reports["customer_billing_events"] = await _copy_rows(
            source, target, PaymentWebhookEvent, CustomerBillingEvent,
            lambda row: ({
                "event_id": row.event_id,
                "license_key": license_key_by_id.get(row.license_id),
                "recipient_email": (row.recipient_email or "").strip().lower()[:254],
                "status": row.status[:40],
                "transaction_id": row.transaction_id,
                "subscription_id": row.subscription_id,
                "paddle_customer_id": row.paddle_customer_id,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            } if license_key_by_id.get(row.license_id) else None),
            "event_id",
            stage_missing=apply_changes,
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
            lambda row: ({
                "legacy_source_id": row.id,
                "event_type": row.event_type,
                "license_key": license_key_by_id.get(row.license_id),
                "domain": row.domain,
                "error_type": row.error_type,
                "created_at": row.created_at,
            }),
            "legacy_source_id",
            stage_missing=apply_changes,
        )

        # Legacy support notes were keyed only by email. Associate each note with
        # the most recently linked license when that mapping is unambiguous.
        billing_by_email, ambiguous_billing_emails = _resolve_billing_license_candidates(
            billing_license_candidates
        )
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
            for row in rows:
                email = row.customer_email.strip().lower()
                if email in ambiguous_billing_emails:
                    note_ambiguous += 1
                    continue
                license_key = billing_by_email.get(email)
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
                logger.info(
                    "Committed support-note migration batch: rows=%s",
                    len(expected_by_id),
                )

        async for row in _stream_rows(source, SaaSAdminCustomerNote):
            note_source_count += 1
            note_batch.append(row)
            if len(note_batch) >= MIGRATION_BATCH_SIZE:
                await reconcile_note_batch(note_batch)
                note_batch.clear()
        if note_batch:
            await reconcile_note_batch(note_batch)
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

        logger.info("Dry run only. No Hostinger records were written.")
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
    verified = asyncio.run(migrate(apply_changes=args.apply, verify_only=args.verify))
    if args.verify and not verified:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
