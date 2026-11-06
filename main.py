async def logout_agency_team_session(response: Response, identity=Depends(require_agency_team_session),
                                     operational_db: AsyncSession = Depends(get_hostinger_db)):
    identity["session"].revoked_at = datetime.now(timezone.utc)
    await operational_db.commit()
    response.headers["Cache-Control"] = "no-store, private"
    return {"status": "logged_out"}


@app.get("/api/v1/agency/team/workspaces/{workspace_id}/audit-results")
async def list_agency_team_workspace_audit_results(
    workspace_id: str,
    response: Response,
    batch_id: str | None = Query(default=None, min_length=1, max_length=64),
    limit: int = Query(25, ge=1, le=25),
    offset: int = Query(0, ge=0, le=1000000),
    identity=Depends(require_agency_team_session),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Return structured audit evidence only within a teammate's explicitly granted workspace."""
    from sqlalchemy import select
    # The session dependency already holds agency/member locks. Continue in the
    # shared lifecycle order: workspace -> grant, matching grant revocation.
    workspace = await operational_db.scalar(select(AgencyClientWorkspace).where(
        AgencyClientWorkspace.id == workspace_id,
        AgencyClientWorkspace.agency_id == identity["agency"].id,
        AgencyClientWorkspace.status == "active",
    ).with_for_update())
    if workspace is None:
        raise HTTPException(status_code=404, detail="Active client workspace not found.")
    grant = await operational_db.scalar(select(AgencyWorkspaceAccess).where(
        AgencyWorkspaceAccess.agency_id == identity["agency"].id,
        AgencyWorkspaceAccess.team_member_id == identity["member"].id,
        AgencyWorkspaceAccess.workspace_id == workspace.id,
    ).with_for_update())
    if grant is None:
        raise HTTPException(status_code=403, detail="You do not have access to this client workspace.")
    statement = select(WebsiteScanJob, WebsiteScanResult).join(
        ScanBatch, ScanBatch.id == WebsiteScanJob.batch_id
    ).outerjoin(WebsiteScanResult, WebsiteScanResult.job_id == WebsiteScanJob.id).where(
        ScanBatch.license_key == identity["agency"].owner_license_key,
        ScanBatch.workspace_id == workspace.id,
    )
    if batch_id:
        statement = statement.where(ScanBatch.id == batch_id)
    rows = (await operational_db.execute(
        statement.order_by(WebsiteScanJob.created_at.desc()).offset(offset).limit(limit)
    )).all()
    def decoded(raw, fallback):
        try:
            return json.loads(raw) if raw else fallback
        except (TypeError, ValueError):
            return fallback
    def decoded_list(raw, maximum):
        value = decoded(raw, [])
        return value[:maximum] if isinstance(value, list) else []
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"workspace_id": workspace.id, "workspace_name": workspace.display_name, "items": [{
        "job_id": job.id, "batch_id": job.batch_id, "url": job.target_url,
        "status": job.status, "attempt_count": job.attempt_count,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "result": ({
            "status": result.status, "overall_score": result.overall_score,
            "finding_count": result.finding_count,
            "findings": decoded_list(result.findings_json, 200),
            "check_outcomes": decoded_list(result.check_outcomes_json, 300),
            "coverage": decoded(result.coverage_json, {}),
            "summary": decoded(result.summary_json, {}),
            "created_at": result.created_at.isoformat() if result.created_at else None,
        } if result is not None else None),
    } for job, result in rows], "limit": limit, "offset": offset}


@app.get("/api/v1/agency/team/workspaces")
async def list_agency_team_workspaces(response: Response, identity=Depends(require_agency_team_session),
                                      operational_db: AsyncSession = Depends(get_hostinger_db)):
    from sqlalchemy import select
    rows = (await operational_db.execute(
        select(AgencyClientWorkspace, AgencyWorkspaceAccess.role)
        .join(AgencyWorkspaceAccess, AgencyWorkspaceAccess.workspace_id == AgencyClientWorkspace.id)
        .where(
            AgencyWorkspaceAccess.agency_id == identity["agency"].id,
            AgencyWorkspaceAccess.team_member_id == identity["member"].id,
            AgencyClientWorkspace.agency_id == identity["agency"].id,
            AgencyClientWorkspace.status == "active",
        ).order_by(AgencyClientWorkspace.display_name.asc()).limit(500)
    )).all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"items": [{"id": workspace.id, "display_name": workspace.display_name, "role": role}
                      for workspace, role in rows]}


@app.get("/api/v1/agency/team/workspaces/{workspace_id}/audits")
async def list_agency_team_workspace_audits(workspace_id: str, response: Response,
                                            limit: int = Query(50, ge=1, le=200),
                                            offset: int = Query(0, ge=0, le=1000000),
                                            identity=Depends(require_agency_team_session),
                                            operational_db: AsyncSession = Depends(get_hostinger_db)):
    """List only audit batches in workspaces explicitly granted to the signed-in teammate."""
    from sqlalchemy import select
    # The session dependency already holds agency/member locks. Continue in the
    # shared lifecycle order: workspace -> grant, matching grant revocation.
    workspace = await operational_db.scalar(select(AgencyClientWorkspace).where(
        AgencyClientWorkspace.id == workspace_id,
        AgencyClientWorkspace.agency_id == identity["agency"].id,
        AgencyClientWorkspace.status == "active",
    ).with_for_update())
    if workspace is None:
        raise HTTPException(status_code=404, detail="Client workspace not found.")
    grant = await operational_db.scalar(select(AgencyWorkspaceAccess).where(
        AgencyWorkspaceAccess.agency_id == identity["agency"].id,
        AgencyWorkspaceAccess.team_member_id == identity["member"].id,
        AgencyWorkspaceAccess.workspace_id == workspace.id,
    ).with_for_update())
    if grant is None:
        raise HTTPException(status_code=403, detail="You do not have access to this client workspace.")
    batches = (await operational_db.execute(select(ScanBatch).where(
        ScanBatch.license_key == identity["agency"].owner_license_key,
        ScanBatch.workspace_id == workspace.id,
    ).order_by(ScanBatch.created_at.desc(), ScanBatch.batch_number.desc()).offset(offset).limit(limit))).scalars().all()
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"workspace_id": workspace.id, "workspace_name": workspace.display_name, "items": [{
        "id": item.id, "batch_number": item.batch_number, "total_urls": item.total_urls,
        "queued": item.queued_count, "processing": item.processing_count,
        "completed": item.completed_count, "failed": item.failed_count,
        "cancelled": item.cancelled_count, "status": item.status,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "completed_at": item.completed_at.isoformat() if item.completed_at else None,
    } for item in batches], "limit": limit, "offset": offset}


@app.post("/api/v1/agency/team/workspaces/{workspace_id}/scan-batches", status_code=202)
async def submit_agency_team_workspace_scans(
    workspace_id: str,
    payload: AgencyTeamScanSubmission,
    request: Request,
    response: Response,
    identity=Depends(require_agency_team_session),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Let assigned agency admins/analysts queue client scans under the shared Business allowance."""
    from sqlalchemy import select
    from scan_api import _normalize_bulk_target, _validate_single_site_submission
    from scan_queue import enqueue_scan_request

    # Continue the session dependency's agency -> member locks with
    # workspace -> grant -> site, matching owner disconnect and grant revocation.
    workspace = await operational_db.scalar(select(AgencyClientWorkspace).where(
        AgencyClientWorkspace.id == workspace_id,
        AgencyClientWorkspace.agency_id == identity["agency"].id,
        AgencyClientWorkspace.status == "active",
    ).with_for_update())
    if workspace is None:
        raise HTTPException(status_code=404, detail="Active client workspace not found.")
    grant = await operational_db.scalar(select(AgencyWorkspaceAccess).where(
        AgencyWorkspaceAccess.agency_id == identity["agency"].id,
        AgencyWorkspaceAccess.team_member_id == identity["member"].id,
        AgencyWorkspaceAccess.workspace_id == workspace.id,
    ).with_for_update())
    if grant is None:
        raise HTTPException(status_code=403, detail="You do not have access to this client workspace.")
    if grant.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Your workspace role is read-only and cannot submit audits.")

    site = await operational_db.scalar(select(AgencyClientWebsite).where(
        AgencyClientWebsite.agency_id == identity["agency"].id,
        AgencyClientWebsite.workspace_id == workspace.id,
        AgencyClientWebsite.status == "active",
    ).with_for_update())
    if site is None:
        raise HTTPException(status_code=409, detail="Connect and verify this client's WordPress website before submitting audits.")

    normalized = []
    invalid_indexes = []
    for index, raw_url in enumerate(payload.urls):
        try:
            normalized.append(_normalize_bulk_target(raw_url))
        except (ValueError, TypeError):
            invalid_indexes.append(index)
    if invalid_indexes:
        raise HTTPException(status_code=422, detail={
            "message": "One or more website URLs are invalid.",
            "invalid_url_indexes": invalid_indexes[:100],
            "invalid_count": len(invalid_indexes),
        })
    try:
        _validate_single_site_submission(normalized)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    for target in normalized:
        parsed_target = urlsplit(target)
        submitted_host = (parsed_target.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        if parsed_target.scheme.lower() != "https" or submitted_host != site.site_host:
            raise HTTPException(status_code=422, detail="Every audit URL must use HTTPS and belong to the WordPress website connected to this workspace.")

    owner_license = identity["owner_license"]
    try:
        result = await enqueue_scan_request(
            operational_db,
            license_key=owner_license.license_key,
            package_tier=owner_license.tier,
            urls=normalized,
            request_id=payload.request_id,
            requested_by=identity["member"].email,
            workspace_id=workspace.id,
            batch_size=10,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Agency scan queue is temporarily unavailable.") from exc
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "status": "accepted",
        "workspace_id": workspace.id,
        "workspace_name": workspace.display_name,
        "message": "Client audit URLs have been queued under the shared Business allowance.",
        **result,
    }


@app.get("/api/v1/account/agency/clients/{workspace_id}/audit-results")
async def list_business_agency_client_audit_results(
    workspace_id: str,
    response: Response,
    batch_id: str | None = Query(default=None, min_length=1, max_length=64),
    limit: int = Query(25, ge=1, le=25),
    offset: int = Query(0, ge=0, le=1000000),
    license_obj: SoftwareLicense = Depends(verify_customer_account),
    operational_db: AsyncSession = Depends(get_hostinger_db),
):
    """Return saved structured audit findings/evidence for one owner's client workspace."""
    if not plan_features(license_obj.tier)["agency_management"]:
        raise HTTPException(status_code=403, detail="Agency client audit results are available on the Business plan.")
    from sqlalchemy import select
    agency = await operational_db.scalar(select(AgencyAccount).where(
        AgencyAccount.owner_license_key == license_obj.license_key,
        AgencyAccount.status == "active",
    ))
    if agency is None:
        raise HTTPException(status_code=404, detail="Business agency workspace was not found.")
    workspace = await operational_db.scalar(select(AgencyClientWorkspace).where(
        AgencyClientWorkspace.id == workspace_id,
        AgencyClientWorkspace.agency_id == agency.id,
        AgencyClientWorkspace.status == "active",
    ))
    if workspace is None:
        raise HTTPException(status_code=404, detail="Active client workspace was not found.")
    statement = select(WebsiteScanJob, WebsiteScanResult).join(
        ScanBatch, ScanBatch.id == WebsiteScanJob.batch_id
    ).outerjoin(WebsiteScanResult, WebsiteScanResult.job_id == WebsiteScanJob.id).where(
        ScanBatch.license_key == license_obj.license_key,
        ScanBatch.workspace_id == workspace.id,
    )
    if batch_id:
        statement = statement.where(ScanBatch.id == batch_id)
    rows = (await operational_db.execute(
        statement.order_by(WebsiteScanJob.created_at.desc()).offset(offset).limit(limit)
    )).all()
    def decoded(raw, fallback):
        try:
            return json.loads(raw) if raw else fallback
        except (TypeError, ValueError):
            return fallback
    def decoded_list(raw, maximum):
        value = decoded(raw, [])
        return value[:maximum] if isinstance(value, list) else []
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {"workspace_id": workspace.id, "workspace_name": workspace.display_name, "items": [{
        "job_id": job.id, "batch_id": job.batch_id, "url": job.target_url,
        "status": job.status, "attempt_count": job.attempt_count,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,