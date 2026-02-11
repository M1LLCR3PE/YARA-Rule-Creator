"""Rule testing API routes"""

import aiofiles
from fastapi import APIRouter, UploadFile, File, Form
from ..models.requests import TestRequest
from ..models.responses import TestResponse
from ...core.services.testing_service import TestingService

router = APIRouter(prefix="/api/test", tags=["testing"])
testing_service = TestingService()


@router.post("/file", response_model=TestResponse)
async def test_on_file(
    rule_content: str = Form(...),
    file: UploadFile = File(...)
) -> TestResponse:
    """Test a YARA rule against an uploaded file"""
    content = await file.read()

    return testing_service.test_data(
        rule_content=rule_content,
        data=content,
        filename=file.filename or "unknown"
    )


@router.post("/path", response_model=TestResponse)
async def test_on_path(request: TestRequest) -> TestResponse:
    """Test a YARA rule against a file or directory path"""
    return await testing_service.test_path(
        rule_content=request.rule_content,
        target_path=request.target_path
    )


@router.post("/sample")
async def test_with_sample(rule_content: str = Form(...)):
    """Test a YARA rule with a simple sample string"""
    # Create a simple test sample
    test_sample = b"This is a test sample for YARA rule testing. MZ\x90\x00"

    return testing_service.test_data(
        rule_content=rule_content,
        data=test_sample,
        filename="test_sample.bin"
    )
