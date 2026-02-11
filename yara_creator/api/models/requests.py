"""Request models for API endpoints"""

from typing import Optional, List
from pydantic import BaseModel, Field


class TemplateRequest(BaseModel):
    """Request model for template generation"""
    template_type: str = Field(..., description="Type: basic, strings, pe_imports, behavioral")
    rule_name: str = Field(..., description="Name of the YARA rule")
    author: Optional[str] = Field(None, description="Rule author")
    description: Optional[str] = Field(None, description="Rule description")
    tags: Optional[List[str]] = Field(None, description="Optional tags for the rule")


class ValidationRequest(BaseModel):
    """Request model for rule validation"""
    rule_content: str = Field(..., description="YARA rule content to validate")


class TestRequest(BaseModel):
    """Request model for rule testing"""
    rule_content: str = Field(..., description="YARA rule content to test")
    target_path: str = Field(..., description="File or directory path to scan")


class ExtractionRequest(BaseModel):
    """Request model for string extraction options"""
    min_length: int = Field(4, ge=1, le=100, description="Minimum string length")
    include_unicode: bool = Field(True, description="Include Unicode strings")
    include_pe_info: bool = Field(True, description="Include PE information")
    classify_strings: bool = Field(True, description="Auto-classify interesting strings")
