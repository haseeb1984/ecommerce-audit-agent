# Ecommerce Audit Agent — Release Roadmap

This roadmap summarizes the current acceptance order. Detailed implementation status is maintained in the SaaS implementation checklist and current phase gap matrix.

1. Keep repository CI green. Run the full test suite, dependency audit, Python compilation, PHP lint for both WordPress deliverables, frontend JavaScript syntax checks and synthetic PDF generation on the exact working-branch head.
2. Verify staging data boundaries. Validate Hostinger MySQL operational schema and Supabase PostgreSQL licensing/audit/billing schema independently. Reconcile counts and ownership without cross-database SQL or foreign keys.
3. Verify private report storage. Exercise the PHP storage bridge, private object permissions, report metadata, download authorization, logo lifecycle and cleanup/retry paths using non-production data.
4. Verify customer and agency isolation. Test account/session ownership, role/workspace grants, quota reservation, worker lease loss/recovery, billing mirrors and admin lifecycle actions against staging databases.
5. Verify WordPress deliverables. Install the customer plugin and public marketing theme separately. Configure the marketing contact HMAC secret and recipient in Vercel, confirm SMTP delivery in a controlled inbox, and configure public contact/WhatsApp settings.
6. Run controlled audit/report acceptance. Use approved public test stores to verify bounded crawl, evidence accuracy, unavailable-check semantics, PDF layout, screenshot embedding and private report retrieval.
7. Release only after operator approval. Back up first, review separate database migrations, apply them through the approved process, verify production health, and obtain explicit approval before merging to main or deploying.

No production deployment, DNS change, live migration or real SMTP send is implied by this roadmap.
