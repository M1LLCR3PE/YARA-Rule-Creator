"""Template generation API routes"""

from fastapi import APIRouter
from ..models.requests import TemplateRequest
from ..models.responses import TemplateResponse
from ...core.services.template_service import TemplateService

router = APIRouter(prefix="/api/template", tags=["templates"])
template_service = TemplateService()


@router.post("/generate", response_model=TemplateResponse)
async def generate_template(request: TemplateRequest) -> TemplateResponse:
    """Generate a YARA rule template based on the specified type"""
    return template_service.generate(
        template_type=request.template_type,
        rule_name=request.rule_name,
        author=request.author,
        description=request.description,
        tags=request.tags
    )


@router.get("/types")
async def get_template_types():
    """Get available template types"""
    return {
        "types": [
            {"id": "basic", "name": "Basic", "description": "Simple rule with condition"},
            {"id": "strings", "name": "Strings", "description": "String-based detection rule"},
            {"id": "pe_imports", "name": "PE Imports", "description": "PE import-based detection"},
            {"id": "behavioral", "name": "Behavioral", "description": "Behavior pattern detection"}
        ]
    }
