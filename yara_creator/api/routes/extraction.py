"""String extraction API routes"""

import aiofiles
from fastapi import APIRouter, UploadFile, File, Form
from ..models.responses import ExtractionResponse
from ...core.services.extraction_service import ExtractionService
from ... import config

router = APIRouter(prefix="/api/extract", tags=["extraction"])
extraction_service = ExtractionService()


@router.post("/file", response_model=ExtractionResponse)
async def extract_from_file(
    file: UploadFile = File(...),
    min_length: int = Form(4),
    include_unicode: bool = Form(True),
    include_pe_info: bool = Form(True),
    classify_strings: bool = Form(True)
) -> ExtractionResponse:
    """Extract strings and PE info from uploaded file"""
    # Read file content
    content = await file.read()

    if len(content) > config.MAX_UPLOAD_SIZE:
        return ExtractionResponse(
            success=False,
            filename=file.filename or "unknown",
            file_size=len(content),
            error=f"File too large. Maximum size is {config.MAX_UPLOAD_SIZE // (1024*1024)}MB"
        )

    return extraction_service.extract(
        data=content,
        filename=file.filename or "unknown",
        min_length=min_length,
        include_unicode=include_unicode,
        include_pe_info=include_pe_info,
        classify_strings=classify_strings
    )


@router.post("/path", response_model=ExtractionResponse)
async def extract_from_path(
    file_path: str = Form(...),
    min_length: int = Form(4),
    include_unicode: bool = Form(True),
    include_pe_info: bool = Form(True),
    classify_strings: bool = Form(True)
) -> ExtractionResponse:
    """Extract strings and PE info from file path"""
    try:
        async with aiofiles.open(file_path, 'rb') as f:
            content = await f.read()

        return extraction_service.extract(
            data=content,
            filename=file_path,
            min_length=min_length,
            include_unicode=include_unicode,
            include_pe_info=include_pe_info,
            classify_strings=classify_strings
        )
    except FileNotFoundError:
        return ExtractionResponse(
            success=False,
            filename=file_path,
            file_size=0,
            error="File not found"
        )
    except PermissionError:
        return ExtractionResponse(
            success=False,
            filename=file_path,
            file_size=0,
            error="Permission denied"
        )
