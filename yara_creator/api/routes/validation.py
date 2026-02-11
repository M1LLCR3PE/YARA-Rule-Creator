"""Validation API routes"""

from fastapi import APIRouter
from ..models.requests import ValidationRequest
from ..models.responses import ValidationResponse
from ...core.services.validation_service import ValidationService

router = APIRouter(prefix="/api/validate", tags=["validation"])
validation_service = ValidationService()


@router.post("", response_model=ValidationResponse)
async def validate_rule(request: ValidationRequest) -> ValidationResponse:
    """Validate a YARA rule for syntax and quality"""
    return validation_service.validate(request.rule_content)


@router.post("/compile")
async def compile_check(request: ValidationRequest):
    """Quick compile check only (no quality warnings)"""
    return validation_service.compile_check(request.rule_content)
