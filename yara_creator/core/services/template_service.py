"""Template generation service for YARA rules"""

from datetime import datetime
from typing import Optional, List
from ...api.models.responses import TemplateResponse


class TemplateService:
    """Service for generating YARA rule templates"""

    def generate(
        self,
        template_type: str,
        rule_name: str,
        author: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> TemplateResponse:
        """Generate a YARA rule template based on type"""

        # Sanitize rule name (YARA identifiers)
        safe_name = self._sanitize_name(rule_name)

        # Build meta section
        meta = self._build_meta(author, description)

        # Build tags string
        tags_str = ""
        if tags:
            tags_str = " : " + " ".join(tags)

        # Generate template based on type
        generators = {
            "basic": self._generate_basic,
            "strings": self._generate_strings,
            "pe_imports": self._generate_pe_imports,
            "behavioral": self._generate_behavioral
        }

        generator = generators.get(template_type)
        if not generator:
            return TemplateResponse(
                success=False,
                rule_content="",
                message=f"Unknown template type: {template_type}"
            )

        rule_content = generator(safe_name, tags_str, meta)

        return TemplateResponse(
            success=True,
            rule_content=rule_content,
            message=f"Generated {template_type} template successfully"
        )

    def _sanitize_name(self, name: str) -> str:
        """Sanitize rule name to valid YARA identifier"""
        # Replace spaces and special chars with underscores
        sanitized = ""
        for c in name:
            if c.isalnum() or c == "_":
                sanitized += c
            else:
                sanitized += "_"

        # Ensure it starts with letter or underscore
        if sanitized and sanitized[0].isdigit():
            sanitized = "_" + sanitized

        return sanitized or "unnamed_rule"

    def _build_meta(self, author: Optional[str], description: Optional[str]) -> str:
        """Build the meta section of the rule"""
        date = datetime.now().strftime("%Y-%m-%d")
        lines = [
            f'        author = "{author or "Unknown"}"',
            f'        description = "{description or "No description"}"',
            f'        date = "{date}"',
            '        version = "1.0"'
        ]
        return "\n".join(lines)

    def _generate_basic(self, name: str, tags: str, meta: str) -> str:
        """Generate a basic YARA rule template"""
        return f'''rule {name}{tags}
{{
    meta:
{meta}

    condition:
        true
}}
'''

    def _generate_strings(self, name: str, tags: str, meta: str) -> str:
        """Generate a string-based YARA rule template"""
        return f'''rule {name}{tags}
{{
    meta:
{meta}

    strings:
        // ASCII strings
        $str1 = "example_string" ascii nocase
        $str2 = "another_string" ascii

        // Wide (Unicode) strings
        $wide1 = "unicode_example" wide

        // Hex strings
        $hex1 = {{ 4D 5A 90 00 }}

        // Regular expression
        $re1 = /[a-zA-Z]{{4,}}\\.(exe|dll|sys)/i

    condition:
        2 of them
}}
'''

    def _generate_pe_imports(self, name: str, tags: str, meta: str) -> str:
        """Generate a PE import-based YARA rule template"""
        return f'''import "pe"

rule {name}{tags}
{{
    meta:
{meta}

    strings:
        $mz = "MZ"

    condition:
        $mz at 0 and
        pe.is_pe and
        (
            // Check for suspicious imports
            pe.imports("kernel32.dll", "VirtualAlloc") and
            pe.imports("kernel32.dll", "WriteProcessMemory")
        ) or
        (
            // Alternative: check import count
            pe.number_of_imports > 0 and
            pe.imports("ntdll.dll", "NtCreateThreadEx")
        )
}}
'''

    def _generate_behavioral(self, name: str, tags: str, meta: str) -> str:
        """Generate a behavioral pattern YARA rule template"""
        return f'''import "pe"

rule {name}{tags}
{{
    meta:
{meta}
        threat_type = "malware"

    strings:
        // Anti-debugging
        $antidbg1 = "IsDebuggerPresent" ascii
        $antidbg2 = "CheckRemoteDebuggerPresent" ascii
        $antidbg3 = "NtQueryInformationProcess" ascii

        // Process injection
        $inject1 = "VirtualAllocEx" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "CreateRemoteThread" ascii
        $inject4 = "NtCreateThreadEx" ascii

        // Persistence
        $persist1 = "CurrentVersion\\\\Run" ascii nocase
        $persist2 = "schtasks" ascii nocase
        $persist3 = "RegSetValueEx" ascii

        // Network
        $net1 = "InternetOpen" ascii
        $net2 = "HttpSendRequest" ascii
        $net3 = "WSAStartup" ascii

        // Crypto
        $crypto1 = "CryptEncrypt" ascii
        $crypto2 = "CryptDecrypt" ascii
        $crypto3 = "BCryptEncrypt" ascii

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        (
            (2 of ($antidbg*)) or
            (3 of ($inject*)) or
            (2 of ($persist*) and 1 of ($net*)) or
            (1 of ($crypto*) and 2 of ($net*))
        )
}}
'''
