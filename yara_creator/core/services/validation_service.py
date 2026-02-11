"""Validation service for YARA rules"""

import re
from typing import List, Dict, Any, Optional
from ...api.models.responses import ValidationResponse, ValidationError

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import plyara
    from plyara import utils as plyara_utils
    PLYARA_AVAILABLE = True
except ImportError:
    PLYARA_AVAILABLE = False


class ValidationService:
    """Service for validating YARA rules"""

    def validate(self, rule_content: str) -> ValidationResponse:
        """Full validation with compile check and quality warnings"""
        errors: List[ValidationError] = []
        warnings: List[ValidationError] = []
        parsed_rules: Optional[List[Dict[str, Any]]] = None

        # Step 1: Compile check with yara-python
        compile_result = self._compile_check(rule_content)
        if compile_result:
            errors.append(compile_result)

        # Step 2: Parse and quality check with plyara
        if PLYARA_AVAILABLE and not errors:
            parse_result = self._parse_and_check(rule_content)
            parsed_rules = parse_result.get("parsed")
            warnings.extend(parse_result.get("warnings", []))

        return ValidationResponse(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            parsed_rules=parsed_rules
        )

    def compile_check(self, rule_content: str) -> Dict[str, Any]:
        """Quick compile check only"""
        error = self._compile_check(rule_content)
        if error:
            return {
                "valid": False,
                "error": error.message,
                "line": error.line
            }
        return {"valid": True}

    def _compile_check(self, rule_content: str) -> Optional[ValidationError]:
        """Check if rule compiles with yara-python"""
        if not YARA_AVAILABLE:
            return ValidationError(
                message="yara-python not installed",
                severity="error"
            )

        try:
            yara.compile(source=rule_content)
            return None
        except yara.SyntaxError as e:
            # Parse error message for line number
            error_str = str(e)
            line_num = self._extract_line_number(error_str)

            return ValidationError(
                line=line_num,
                message=error_str,
                severity="error"
            )
        except yara.Error as e:
            return ValidationError(
                message=str(e),
                severity="error"
            )

    def _extract_line_number(self, error_msg: str) -> Optional[int]:
        """Extract line number from YARA error message"""
        # YARA errors typically contain "line X"
        match = re.search(r'line\s+(\d+)', error_msg, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def _parse_and_check(self, rule_content: str) -> Dict[str, Any]:
        """Parse with plyara and check quality"""
        warnings: List[ValidationError] = []
        parsed = None

        try:
            parser = plyara.Plyara()
            parsed = parser.parse_string(rule_content)

            for rule in parsed:
                rule_warnings = self._check_rule_quality(rule)
                warnings.extend(rule_warnings)

        except Exception as e:
            warnings.append(ValidationError(
                message=f"Parse warning: {str(e)}",
                severity="warning"
            ))

        return {
            "parsed": parsed,
            "warnings": warnings
        }

    def _check_rule_quality(self, rule: Dict[str, Any]) -> List[ValidationError]:
        """Check quality of a parsed rule"""
        warnings: List[ValidationError] = []
        rule_name = rule.get("rule_name", "unknown")

        # Check for missing metadata
        meta = rule.get("metadata", [])
        meta_keys = [list(m.keys())[0] for m in meta] if meta else []

        if "author" not in meta_keys:
            warnings.append(ValidationError(
                message=f"Rule '{rule_name}': Missing 'author' in metadata",
                severity="warning"
            ))

        if "description" not in meta_keys:
            warnings.append(ValidationError(
                message=f"Rule '{rule_name}': Missing 'description' in metadata",
                severity="warning"
            ))

        # Check strings
        strings = rule.get("strings", [])
        for string in strings:
            string_name = string.get("name", "")
            string_value = string.get("value", "")
            string_type = string.get("type", "")

            # Check for very short strings (potential false positives)
            if string_type == "text" and len(string_value) < 4:
                warnings.append(ValidationError(
                    message=f"Rule '{rule_name}': String {string_name} is very short ({len(string_value)} chars), may cause false positives",
                    severity="warning"
                ))

            # Check for overly generic strings
            generic_patterns = ["http://", "https://", ".exe", ".dll", "MZ"]
            if string_type == "text" and string_value in generic_patterns:
                warnings.append(ValidationError(
                    message=f"Rule '{rule_name}': String {string_name} is very generic, consider adding more specific strings",
                    severity="info"
                ))

        # Check condition complexity
        condition = rule.get("condition_terms", [])
        if len(condition) == 1 and condition[0] == "true":
            warnings.append(ValidationError(
                message=f"Rule '{rule_name}': Condition is just 'true', will match all files",
                severity="warning"
            ))

        return warnings
