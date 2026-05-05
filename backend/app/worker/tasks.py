import asyncio
import logging
from app.worker.celery_app import celery_app
from app.scanner.engine import run_scan

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="run_scan_task")
def run_scan_task(
    self,
    raw_request: str,
    user_tokens: list,
    enabled_modules: list,
    scan_meta: dict,
):
    """
    Celery task that runs the BAC scan asynchronously.
    
    Uses asyncio.run() to execute the async scan engine within a sync Celery task.
    Progress is stored in Celery task meta for frontend polling.
    """
    task_id = self.request.id

    def update_progress(progress: int, message: str):
        self.update_state(
            state="PROGRESS",
            meta={"progress": progress, "message": message, "findings": []}
        )

    async def _run():
        async def progress_callback(progress: int, msg: str):
            update_progress(progress, msg)

        return await run_scan(
            raw_request=raw_request,
            user_tokens=user_tokens,
            enabled_modules=enabled_modules,
            progress_callback=progress_callback,
        )

    try:
        self.update_state(state="PROGRESS", meta={"progress": 0, "message": "Starting scan..."})
        result = asyncio.run(_run())
        return {
            "status": "COMPLETED",
            "findings": result["findings"],
            "access_graph": result["access_graph"],
            "api_type": result["api_type"],
            "total_modules_run": result["total_modules_run"],
            "scan_meta": scan_meta,
        }
    except Exception as e:
        logger.error(f"Scan task {task_id} failed: {e}")
        raise
