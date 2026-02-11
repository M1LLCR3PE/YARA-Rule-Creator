"""Response models for API endpoints"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class TemplateResponse(BaseModel):
    """Response model for template generation"""
    success: bool
    rule_content: str
    message: Optional[str] = None


class ValidationError(BaseModel):
    """Model for a validation error"""
    line: Optional[int] = None
    column: Optional[int] = None
    message: str
    severity: str = "error"  # error, warning, info


class ValidationResponse(BaseModel):
    """Response model for rule validation"""
    valid: bool
    errors: List[ValidationError] = []
    warnings: List[ValidationError] = []
    parsed_rules: Optional[List[Dict[str, Any]]] = None


class ExtractedString(BaseModel):
    """Model for an extracted string"""
    value: str
    encoding: str  # ascii, unicode
    offset: int
    length: int
    category: Optional[str] = None  # url, api, registry, path, etc.


class PEInfo(BaseModel):
    """Model for PE file information"""
    imports: Dict[str, List[str]] = {}
    exports: List[str] = []
    sections: List[Dict[str, Any]] = []
    entry_point: Optional[int] = None
    timestamp: Optional[str] = None


class ExtractionResponse(BaseModel):
    """Response model for string extraction"""
    success: bool
    filename: str
    file_size: int
    strings: List[ExtractedString] = []
    pe_info: Optional[PEInfo] = None
    suggested_yara: Optional[str] = None
    error: Optional[str] = None


class MatchDetail(BaseModel):
    """Model for a YARA match detail"""
    rule_name: str
    tags: List[str] = []
    meta: Dict[str, Any] = {}
    strings: List[Dict[str, Any]] = []


class TestResult(BaseModel):
    """Model for a test result on a single file"""
    file_path: str
    file_size: int
    matches: List[MatchDetail] = []
    error: Optional[str] = None


class TestResponse(BaseModel):
    """Response model for rule testing"""
    success: bool
    total_files: int
    matched_files: int
    results: List[TestResult] = []
    error: Optional[str] = None
