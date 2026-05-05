from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.api_request import APIRequest
from app.models.project import Project
from app.models.scan_result import ScanResult, ScanStatus, Severity, VulnType
from app.schemas import (
    APIRequestCreate, APIRequestOut,
    ScanStartRequest, ScanResultOut, ScanStatusResponse
)
from app.worker.tasks import run_scan_task
from typing import List
import json
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["Scans"])
requests_router = APIRouter(prefix="/api/requests", tags=["API Requests"])


# ---------- API Request Management ----------

@requests_router.post("", response_model=APIRequestOut, status_code=201)
async def create_api_request(
    payload: APIRequestCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Verify project ownership
    proj = await db.execute(
        select(Project).where(Project.id == payload.project_id, Project.user_id == current_user.id)
    )
    if not proj.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    # Parse the raw request to extract metadata
    from app.scanner.request_parser import parse_raw_request
    from app.scanner.api_detector import detect_api_type
    try:
        parsed = parse_raw_request(payload.raw_request)
        api_type = detect_api_type(parsed)
        method = parsed.method
        url = parsed.url
        headers = parsed.headers
        body = parsed.body
    except Exception:
        api_type = "REST"
        method = "GET"
        url = ""
        headers = {}
        body = ""

    api_req = APIRequest(
        project_id=payload.project_id,
        name=payload.name,
        raw_request=payload.raw_request,
        method=method,
        url=url,
        headers=headers,
        body=body,
        api_type=api_type,
        user_tokens=[t.model_dump() for t in (payload.user_tokens or [])],
    )
    db.add(api_req)
    await db.commit()
    await db.refresh(api_req)
    return api_req


@requests_router.get("/project/{project_id}", response_model=List[APIRequestOut])
async def list_requests(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    proj = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
    )
    if not proj.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    result = await db.execute(
        select(APIRequest).where(APIRequest.project_id == project_id)
    )
    return result.scalars().all()


# ---------- Scan Control ----------

@router.post("/start", status_code=202)
async def start_scan(
    payload: ScanStartRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Get API request and verify ownership
    result = await db.execute(
        select(APIRequest).where(APIRequest.id == payload.api_request_id)
    )
    api_req = result.scalar_one_or_none()
    if not api_req:
        raise HTTPException(status_code=404, detail="API Request not found")

    proj = await db.execute(
        select(Project).where(Project.id == api_req.project_id, Project.user_id == current_user.id)
    )
    if not proj.scalar_one_or_none():
        raise HTTPException(status_code=403, detail="Forbidden")

    # Dispatch Celery task
    logger.info(f"Queuing scan for API Request {api_req.id} (Modules: {payload.enabled_modules})")
    try:
        task = run_scan_task.delay(
            raw_request=api_req.raw_request,
            user_tokens=api_req.user_tokens or [],
            enabled_modules=payload.enabled_modules,
            scan_meta={"api_request_id": api_req.id, "user_id": current_user.id},
        )
    except Exception as exc:
        logger.error(f"Failed to queue scan task: {exc}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to queue scan task. Is Redis running? Error: {exc}"
        )

    # Create initial placeholder scan result record
    scan_result = ScanResult(
        api_request_id=api_req.id,
        scan_id=task.id,
        status=ScanStatus.PENDING.value,  # .value → plain string, not Enum repr
    )
    db.add(scan_result)
    await db.commit()

    return {"scan_id": task.id, "status": "PENDING", "message": "Scan queued"}


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.worker.celery_app import celery_app as celery
    task_result = celery.AsyncResult(scan_id)

    state = task_result.state
    progress = 0
    message = "Waiting..."
    findings_count = 0

    if state == "PROGRESS":
        meta = task_result.info or {}
        progress = meta.get("progress", 0)
        message = meta.get("message", "Running...")
    elif state == "SUCCESS":
        progress = 100
        message = "Scan completed"
        result_data = task_result.result or {}
        findings_count = len(result_data.get("findings", []))

        # Persist findings to DB
        await _persist_findings(scan_id, result_data, db)
    elif state == "FAILURE":
        message = str(task_result.info)
        progress = 0

    # Count stored findings
    count_result = await db.execute(
        select(ScanResult).where(
            ScanResult.scan_id == scan_id,
            ScanResult.vuln_type.isnot(None)
        )
    )
    findings_count = len(count_result.scalars().all())

    return ScanStatusResponse(
        scan_id=scan_id,
        status=state,
        progress=progress,
        findings_count=findings_count,
        message=message,
    )


@router.get("/{scan_id}/results", response_model=List[ScanResultOut])
async def get_scan_results(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.scan_id == scan_id,
            ScanResult.vuln_type.isnot(None),
        )
    )
    findings = result.scalars().all()
    logger.info(f"Fetched {len(findings)} findings for scan {scan_id}")
    return findings


@router.get("/project/{project_id}", response_model=List[ScanResultOut])
async def list_project_findings(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Verify project ownership
    proj = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
    )
    if not proj.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    # Get all results for all requests in this project
    result = await db.execute(
        select(ScanResult)
        .join(APIRequest, ScanResult.api_request_id == APIRequest.id)
        .where(
            APIRequest.project_id == project_id,
            ScanResult.vuln_type.isnot(None)
        )
    )
    return result.scalars().all()


@router.get("/{scan_id}/graph")
async def get_access_graph(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.worker.celery_app import celery_app as celery
    task_result = celery.AsyncResult(scan_id)
    if task_result.state == "SUCCESS":
        return task_result.result.get("access_graph", {})
    return {"message": "Scan not complete yet"}


async def _persist_findings(scan_id: str, result_data: dict, db: AsyncSession):
    """Save scan findings to the database (idempotent)."""
    # Check if already persisted (look for rows that HAVE findings)
    existing = await db.execute(
        select(ScanResult).where(
            ScanResult.scan_id == scan_id,
            ScanResult.vuln_type.isnot(None)
        )
    )
    if existing.scalars().first():
        logger.info(f"Scan {scan_id} results already persisted. Skipping.")
        return  # Already saved

    # Get the placeholder record
    placeholder = await db.execute(
        select(ScanResult).where(
            ScanResult.scan_id == scan_id,
            ScanResult.vuln_type.is_(None),
        )
    )
    placeholder_record = placeholder.scalar_one_or_none()
    
    if not placeholder_record:
        logger.warning(f"No placeholder found for scan {scan_id}. Finding another record for the same scan if possible.")
        # Try to find ANY record for this scan to get the api_request_id
        alt = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
        placeholder_record = alt.scalars().first()
        
    if not placeholder_record:
        logger.error(f"Abandoning persistence for {scan_id}: No database record found to link findings to.")
        return

    api_request_id = placeholder_record.api_request_id

    for finding in result_data.get("findings", []):
        vuln_type = finding.get("vuln_type", "INFO")
        severity = finding.get("severity", "INFO")
        try:
            vuln_enum = VulnType(vuln_type)
        except ValueError:
            vuln_enum = VulnType.INFO
        try:
            sev_enum = Severity(severity)
        except ValueError:
            sev_enum = Severity.INFO

        record = ScanResult(
            api_request_id=api_request_id,
            scan_id=scan_id,
            status=ScanStatus.COMPLETED.value,   # .value → plain "COMPLETED" string
            endpoint=finding.get("endpoint"),
            method=finding.get("method"),
            vuln_type=vuln_enum.value,            # .value → plain "IDOR" etc.
            severity=sev_enum.value,              # .value → plain "HIGH" etc.
            original_request=finding.get("original_request"),
            modified_request=finding.get("modified_request"),
            original_response=finding.get("original_response"),
            modified_response=finding.get("modified_response"),
            response_diff=finding.get("response_diff"),
            similarity_score=finding.get("similarity_score"),
            explanation=finding.get("explanation"),
            fix_suggestion=finding.get("fix_suggestion"),
            cwe_id=finding.get("cwe_id"),
            owasp_ref=finding.get("owasp_ref"),
            ai_risk_score=finding.get("ai_risk_score"),
            ai_severity=finding.get("ai_severity"),
            ai_confidence=finding.get("ai_confidence"),
            ai_reasoning=finding.get("ai_reasoning"),
        )
        db.add(record)

    await db.commit()
