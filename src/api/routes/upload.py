"""
File upload endpoints.
Handles secure log file uploads with validation.
"""
from fastapi import APIRouter, UploadFile, File, HTTPException
from pathlib import Path
import uuid
import aiofiles
from pydantic import BaseModel

from src.config import Config
from src.services.log_chunker import LogChunker


router = APIRouter(prefix="/api", tags=["upload"])


def _uploaded_file(upload_id: str) -> Path:
    try:
        normalized_id = str(uuid.UUID(upload_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Upload not found") from exc

    for extension in (".log", ".txt"):
        candidate = Config.UPLOAD_DIR / f"{normalized_id}{extension}"
        if candidate.is_file():
            return candidate
    raise HTTPException(status_code=404, detail="Upload not found")


class UploadResponse(BaseModel):
    """Response model for file upload."""
    upload_id: str
    filename: str
    file_size: int
    file_path: str


class ValidationRequest(BaseModel):
    """Request model for validation."""
    upload_id: str


class ChunkPreview(BaseModel):
    """Preview of a single chunk."""
    chunk_id: int
    lines: str
    token_count: int
    entry_count: int
    has_malformed: bool
    has_oversized: bool


class ValidationResponse(BaseModel):
    """Response model for validation."""
    valid: bool
    total_lines: int
    total_chunks: int
    estimated_tokens: int
    chunk_preview: list[ChunkPreview]
    warnings: list[str]


@router.post("/upload", response_model=UploadResponse)
async def upload_log_file(file: UploadFile = File(...)):
    """
    Upload a log file for analysis.

    Validates:
    - File extension (.log or .txt only)
    - File size (max 100MB)
    - UTF-8 encoding

    Returns:
        Upload metadata with unique ID
    """
    # Validate file extension
    allowed_extensions = {'.log', '.txt'}
    if not file.filename:
        raise HTTPException(status_code=400, detail="A filename is required")
    file_ext = Path(file.filename).suffix.lower()

    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Only {', '.join(allowed_extensions)} files allowed."
        )

    # Generate unique upload ID
    upload_id = str(uuid.uuid4())

    # Sanitize filename and create safe path
    safe_filename = f"{upload_id}{file_ext}"
    file_path = Config.UPLOAD_DIR / safe_filename

    # Stream file to disk with size checking
    file_size = 0
    max_size = Config.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    try:
        async with aiofiles.open(file_path, 'wb') as f:
            while chunk := await file.read(8192):  # 8KB chunks
                file_size += len(chunk)

                if file_size > max_size:
                    # Clean up partial file
                    file_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Maximum size: {Config.MAX_UPLOAD_SIZE_MB}MB"
                    )

                await f.write(chunk)
    except Exception as e:
        # Clean up on any error
        file_path.unlink(missing_ok=True)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

    # Validate the full stream without loading a second full copy into memory.
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for _ in f:
                pass
    except UnicodeDecodeError:
        file_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400,
            detail="File must be valid UTF-8 text"
        )

    return UploadResponse(
        upload_id=upload_id,
        filename=file.filename,
        file_size=file_size,
        file_path=str(file_path)
    )


@router.post("/validate", response_model=ValidationResponse)
async def validate_log_file(request: ValidationRequest):
    """
    Validate uploaded log file and preview chunking.

    Does not perform AI analysis - just validates format and shows
    how the file will be chunked.

    Returns:
        Chunking statistics and preview
    """
    file_path = _uploaded_file(request.upload_id)

    try:
        # Parse and chunk the file
        chunker = LogChunker()
        chunks = chunker.parse_log_file(file_path)

        # Calculate statistics
        total_lines = max(
            (chunk.end_line for chunk in chunks if chunk.entries),
            default=0,
        )
        total_chunks = len(chunks)
        estimated_tokens = sum(chunk.token_count for chunk in chunks)

        # Generate warnings
        warnings = []
        for chunk in chunks:
            if chunk.has_oversized_entries:
                warnings.append(
                    f"Chunk {chunk.chunk_id}: Contains oversized entry "
                    f"(line {chunk.start_line}, {chunk.token_count} tokens)"
                )
            if chunk.has_malformed_entries:
                malformed_lines = [
                    str(e.line_number)
                    for e in chunk.entries
                    if e.is_malformed
                ]
                warnings.append(
                    f"Chunk {chunk.chunk_id}: Contains malformed JSON "
                    f"(lines {', '.join(malformed_lines)})"
                )

        # Create preview (first 3 chunks)
        preview = []
        for chunk in chunks[:3]:
            preview.append(ChunkPreview(
                chunk_id=chunk.chunk_id,
                lines=f"{chunk.start_line}-{chunk.end_line}" if chunk.entries else "empty",
                token_count=chunk.token_count,
                entry_count=len(chunk.entries),
                has_malformed=chunk.has_malformed_entries,
                has_oversized=chunk.has_oversized_entries
            ))

        return ValidationResponse(
            valid=True,
            total_lines=total_lines,
            total_chunks=total_chunks,
            estimated_tokens=estimated_tokens,
            chunk_preview=preview,
            warnings=warnings
        )

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Validation failed: {str(e)}"
        )
