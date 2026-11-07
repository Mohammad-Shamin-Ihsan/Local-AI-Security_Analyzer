"""Analysis endpoints for starting, monitoring, and cancelling local inference."""
import asyncio
import uuid
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.config import Config
from src.models.database import Database
from src.services.analysis_engine import AnalysisEngine
from src.services.correlation_engine import CorrelationEngine
from src.services.ollama_client import OllamaClient
from src.services.report_generator import ReportGenerator


router = APIRouter(prefix="/api", tags=["analysis"])
db_instance: Optional[Database] = None
ollama_instance: Optional[OllamaClient] = None
active_task: Optional[asyncio.Task[None]] = None
active_analysis_id: Optional[str] = None
progress_by_id: dict[str, dict[str, Any]] = {}


class AnalyzeRequest(BaseModel):
    upload_id: str


class AnalyzeResponse(BaseModel):
    analysis_id: str
    status: str


class ProgressResponse(BaseModel):
    analysis_id: str
    status: str
    processed_chunks: int
    total_chunks: int
    finding_count: int
    error: Optional[str] = None


class FindingsResponse(BaseModel):
    analysis_id: str
    findings: list
    total_findings: int
    summary: Optional[dict] = None
    statistics: Optional[dict] = None
    raw_findings: Optional[list] = None


def set_global_instances(db: Database, ollama: OllamaClient) -> None:
    global db_instance, ollama_instance
    db_instance = db
    ollama_instance = ollama


@router.post("/analyze", response_model=AnalyzeResponse)
async def start_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    global active_task, active_analysis_id

    try:
        normalized_upload_id = str(uuid.UUID(request.upload_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Upload not found") from exc
    uploaded_files = [
        Config.UPLOAD_DIR / f"{normalized_upload_id}{extension}"
        for extension in (".log", ".txt")
        if (Config.UPLOAD_DIR / f"{normalized_upload_id}{extension}").is_file()
    ]
    if not uploaded_files:
        raise HTTPException(status_code=404, detail="Upload not found")
    if db_instance is None or ollama_instance is None:
        raise HTTPException(status_code=503, detail="Analysis service not initialized")
    if active_task is not None and not active_task.done():
        raise HTTPException(
            status_code=409,
            detail="An analysis is already running; wait for it or cancel it first."
        )
    if not await ollama_instance.test_connection():
        raise HTTPException(
            status_code=503,
            detail=(
                f"Ollama or model '{Config.OLLAMA_MODEL}' is unavailable. "
                f"Run: ollama pull {Config.OLLAMA_MODEL}"
            )
        )

    analysis_id = str(uuid.uuid4())
    file_path = uploaded_files[0]
    progress_by_id[analysis_id] = {
        "analysis_id": analysis_id,
        "status": "queued",
        "processed_chunks": 0,
        "total_chunks": 0,
        "finding_count": 0,
    }
    active_analysis_id = analysis_id

    async def run_analysis() -> None:
        try:
            engine = AnalysisEngine(db_instance, ollama_instance)

            def report_progress(chunk_id: int, total: int, finding_count: int) -> None:
                progress_by_id[analysis_id] = {
                    "analysis_id": analysis_id,
                    "status": "running",
                    "processed_chunks": chunk_id + 1,
                    "total_chunks": total,
                    "finding_count": finding_count,
                }

            progress_by_id[analysis_id]["status"] = "running"
            result = await engine.analyze_log_file(
                analysis_id=analysis_id,
                file_path=str(file_path),
                progress_callback=report_progress,
            )
            progress_by_id[analysis_id] = {
                "analysis_id": analysis_id,
                "status": result["status"],
                "processed_chunks": result["processed_chunks"],
                "total_chunks": result["total_chunks"],
                "finding_count": result["total_findings"],
                "error": (
                    f"{len(result['failed_chunks'])} chunk(s) failed"
                    if result["failed_chunks"] else None
                ),
            }
        except asyncio.CancelledError:
            await db_instance.complete_analysis(
                analysis_id, success=False, error_message="Cancelled by user"
            )
            progress_by_id[analysis_id]["status"] = "cancelled"
            progress_by_id[analysis_id]["error"] = "Cancelled by user"
        except Exception as exc:
            await db_instance.complete_analysis(
                analysis_id, success=False, error_message=str(exc)
            )
            progress_by_id[analysis_id].update({
                "status": "failed",
                "error": str(exc),
            })
        finally:
            global active_task, active_analysis_id
            active_task = None
            active_analysis_id = None

    active_task = asyncio.create_task(run_analysis())
    return AnalyzeResponse(analysis_id=analysis_id, status="started")


@router.get("/progress/{analysis_id}", response_model=ProgressResponse)
async def get_progress(analysis_id: str) -> ProgressResponse:
    progress = progress_by_id.get(analysis_id)
    if progress is None:
        if db_instance is None:
            raise HTTPException(status_code=404, detail="Analysis not found")
        db_progress = await db_instance.get_analysis_progress(analysis_id)
        if not db_progress:
            raise HTTPException(status_code=404, detail="Analysis not found")
        findings = await db_instance.get_all_findings(analysis_id)
        return ProgressResponse(
            analysis_id=analysis_id,
            status=db_progress.get("status", "unknown"),
            processed_chunks=db_progress.get("processed_chunks", 0),
            total_chunks=db_progress.get("total_chunks", 0),
            finding_count=len(findings),
            error=db_progress.get("error_message"),
        )
    return ProgressResponse(**progress)


@router.post("/cancel/{analysis_id}")
async def cancel_analysis(analysis_id: str) -> dict[str, str]:
    if active_analysis_id != analysis_id or active_task is None or active_task.done():
        raise HTTPException(status_code=404, detail="Running analysis not found")
    active_task.cancel()
    return {"analysis_id": analysis_id, "status": "cancelling"}


@router.get("/findings/{analysis_id}", response_model=FindingsResponse)
async def get_findings(analysis_id: str) -> FindingsResponse:
    if db_instance is None:
        raise HTTPException(status_code=503, detail="Database not initialized")
    raw_findings = await db_instance.get_all_findings(analysis_id)
    if not await db_instance.get_analysis_progress(analysis_id):
        raise HTTPException(status_code=404, detail="Analysis not found")

    correlation = CorrelationEngine()
    for finding in raw_findings:
        correlation.add_findings([finding], finding.get("chunk_id", 0))
    report = ReportGenerator().generate_report(
        raw_findings, correlation.get_all_patterns()
    )
    findings = report["attack_findings"]
    return FindingsResponse(
        analysis_id=analysis_id,
        findings=findings,
        total_findings=len(findings),
        summary=report["summary"],
        statistics=report["statistics"],
        raw_findings=raw_findings,
    )
