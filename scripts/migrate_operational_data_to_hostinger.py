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

from sqlalchemy import select
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
    WordPressInstallation,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("operational_data_migration")


def _legacy_account_id(license_key: str, email: str) -> str:
    digest = hashlib.sha256(f"{license_key.lower()}:{email.lower()}".encode()).hexdigest()
    return f"legacy-{digest[:48]}"


async def _license_map(source: AsyncSession) -> dict[int, SoftwareLicense]:
    rows = (await source.execute(select(SoftwareLicense))).scalars().all()
    return {row.id: row for row in rows}


async def _copy_rows(source, target, source_model, target_model, transform, key_name):
    rows = (await source.execute(select(source_model))).scalars().all()
    copied = 0
    skipped = 0
    for row in rows:
        values = transform(row)
        if values is None:
            skipped += 1
            continue
        key_value = values[key_name]
        existing = await target.get(target_model, key_value)
        if existing is None:
            target.add(target_model(**values))
            copied += 1
        else:
            skipped += 1
    return {"source": len(rows), "to_copy": copied, "already_present_or_unmapped": skipped}


async def migrate(apply_changes: bool) -> None:
    if AsyncSessionLocal is None or HostingerAsyncSessionLocal is None:
        raise RuntimeError("DATABASE_URL and HOSTINGER_DATABASE_URL must both be configured.")
    async with AsyncSessionLocal() as source, HostingerAsyncSessionLocal() as target:
        licenses = await _license_map(source)
        license_key_by_id = {key: value.license_key for key, value in licenses.items()}
        reports = {}

        # Restore customer account identities first, deriving them from legacy
        # sessions, linked WordPress installations and verified billing emails.
        account_candidates = {}
        legacy_sessions = (await source.execute(select(AccountSession))).scalars().all()
        for row in legacy_sessions:
            license_key = license_key_by_id.get(row.license_id)
            if license_key:
                account_candidates[(license_key, row.email.lower())] = (
                    row.email.lower(), licenses[row.license_id].client_name, row.created_at
                )
        legacy_sites = (await source.execute(select(WordPressSite))).scalars().all()
        for row in legacy_sites:
            license_key = license_key_by_id.get(row.license_id)
            email = (row.customer_email or row.admin_email or "").strip().lower()
            if license_key and email:
                account_candidates.setdefault(
                    (license_key, email), (email, licenses[row.license_id].client_name, row.created_at)
                )
        billing_rows = (await source.execute(
            select(PaymentWebhookEvent)
            .where(PaymentWebhookEvent.license_id.is_not(None))
            .order_by(PaymentWebhookEvent.updated_at.desc(), PaymentWebhookEvent.created_at.desc())
        )).scalars().all()
        for row in billing_rows:
            license_key = license_key_by_id.get(row.license_id)
            email = (row.recipient_email or "").strip().lower()
            if license_key and email:
                account_candidates.setdefault(
                    (license_key, email), (email, licenses[row.license_id].client_name, row.created_at)
                )

        account_copied = 0
        account_skipped = 0
        for (license_key, email), (normalized_email, display_name, created_at) in account_candidates.items():
            existing = await target.scalar(select(CustomerAccount).where(
                CustomerAccount.license_key == license_key,
                CustomerAccount.email == normalized_email,
            ).limit(1))
            if existing is None:
                target.add(CustomerAccount(
                    id=_legacy_account_id(license_key, normalized_email),
                    license_key=license_key,
                    email=normalized_email,
                    display_name=display_name,
                    status="active",
                    created_at=created_at,
                    updated_at=created_at,
                ))
                account_copied += 1
            else:
                account_skipped += 1
        reports["customer_accounts"] = {
            "source_candidates": len(account_candidates),
            "to_copy": account_copied,
            "already_present": account_skipped,
        }

        reports["customer_billing_events"] = await _copy_rows(
            source, target, PaymentWebhookEvent, CustomerBillingEvent,
            lambda row: ({
                "event_id": row.event_id,
                "license_key": license_key_by_id.get(row.license_id),
                "recipient_email": row.recipient_email.strip().lower()[:254],
                "status": row.status[:40],
                "transaction_id": row.transaction_id,
                "subscription_id": row.subscription_id,
                "paddle_customer_id": row.paddle_customer_id,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            } if license_key_by_id.get(row.license_id) else None),
            "event_id",
        )
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
        )

        reports["customer_billing_events"] = await _copy_rows(
            source, target, PaymentWebhookEvent, CustomerBillingEvent,
            lambda row: ({
                "event_id": row.event_id,
                "license_key": license_key_by_id.get(row.license_id),
                "recipient_email": row.recipient_email[:254],
                "status": row.status[:40],
                "transaction_id": row.transaction_id,
                "subscription_id": row.subscription_id,
                "paddle_customer_id": row.paddle_customer_id,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            } if license_key_by_id.get(row.license_id) else None),
            "event_id",
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
        )

        # Legacy support notes were keyed only by email. Associate each note with
        # the most recently linked license when that mapping is unambiguous.
        billing_by_email = {}
        for row in billing_rows:
            email = (row.recipient_email or "").strip().lower()
            license_key = license_key_by_id.get(row.license_id)
            if email and license_key:
                billing_by_email.setdefault(email, license_key)
        note_rows = (await source.execute(select(SaaSAdminCustomerNote))).scalars().all()
        note_copied = 0
        note_skipped = 0
        for row in note_rows:
            email = row.customer_email.strip().lower()
            license_key = billing_by_email.get(email)
            if not license_key:
                note_skipped += 1
                continue
            existing = await target.get(AdminCustomerNote, row.id)
            if existing is None:
                target.add(AdminCustomerNote(
                    id=row.id,
                    license_key=license_key,
                    customer_email=email,
                    note=row.note,
                    created_by=row.created_by,
                    created_at=row.created_at,
                ))
                note_copied += 1
            else:
                note_skipped += 1
        reports["admin_customer_notes"] = {
            "source": len(note_rows),
            "to_copy": note_copied,
            "already_present_or_unmapped": note_skipped,
        }

        reports["admin_action_logs"] = await _copy_rows(
            source, target, SaaSAdminActionLog, AdminActionLog,
            lambda row: {
                "id": row.id,
                "action": row.action,
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "details_json": row.details_json or "{}",
                "created_at": row.created_at,
            },
            "id",
        )

        for name, report in reports.items():
            logger.info("%s: %s", name, report)
        if apply_changes:
            await target.commit()
            logger.info("Hostinger operational records copied. PostgreSQL source records were retained.")
        else:
            await target.rollback()
            logger.info("Dry run only. No Hostinger records were written.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write missing records to Hostinger. Default behavior is dry-run only.",
    )
    args = parser.parse_args()
    asyncio.run(migrate(apply_changes=args.apply))


if __name__ == "__main__":
    main()
