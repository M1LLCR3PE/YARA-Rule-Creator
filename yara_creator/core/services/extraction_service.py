"""String extraction service for files"""

import re
from typing import List, Optional, Dict, Any
from ...api.models.responses import (
    ExtractionResponse, ExtractedString, PEInfo
)

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class ExtractionService:
    """Service for extracting strings and PE info from files"""

    # Patterns for classifying interesting strings
    PATTERNS = {
        "url": re.compile(r'^https?://[^\s<>"{}|\\^`\[\]]+$', re.IGNORECASE),
        "ip_address": re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
        "email": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        "registry": re.compile(r'^(HKEY_|HKLM|HKCU|HKU|HKCR)', re.IGNORECASE),
        "file_path": re.compile(r'^[A-Za-z]:\\|^\\\\|^/[a-zA-Z]', re.IGNORECASE),
        "api_call": re.compile(r'^(Nt|Zw|Rtl|Ldr|Crypt|Virtual|Heap|Create|Open|Read|Write|Delete|Query|Set)[A-Z][a-zA-Z]+$'),
        "dll_name": re.compile(r'^[a-zA-Z0-9_-]+\.(dll|sys|exe)$', re.IGNORECASE),
        "mutex": re.compile(r'^(Global\\|Local\\|Session\\)', re.IGNORECASE),
        "command": re.compile(r'^(cmd|powershell|wscript|cscript|mshta|regsvr32|rundll32)', re.IGNORECASE),
    }

    def extract(
        self,
        data: bytes,
        filename: str,
        min_length: int = 4,
        include_unicode: bool = True,
        include_pe_info: bool = True,
        classify_strings: bool = True
    ) -> ExtractionResponse:
        """Extract strings and optionally PE info from binary data"""

        strings: List[ExtractedString] = []
        pe_info: Optional[PEInfo] = None

        # Extract ASCII strings
        ascii_strings = self._extract_ascii_strings(data, min_length)
        strings.extend(ascii_strings)

        # Extract Unicode strings
        if include_unicode:
            unicode_strings = self._extract_unicode_strings(data, min_length)
            strings.extend(unicode_strings)

        # Classify strings
        if classify_strings:
            for s in strings:
                s.category = self._classify_string(s.value)

        # Sort by interest (categorized first, then by length)
        strings.sort(key=lambda x: (x.category is None, -len(x.value)))

        # Limit to prevent huge responses
        strings = strings[:500]

        # Extract PE info
        if include_pe_info and self._is_pe(data):
            pe_info = self._extract_pe_info(data)

        # Generate suggested YARA strings
        suggested_yara = self._generate_suggested_yara(strings, pe_info)

        return ExtractionResponse(
            success=True,
            filename=filename,
            file_size=len(data),
            strings=strings,
            pe_info=pe_info,
            suggested_yara=suggested_yara
        )

    def _extract_ascii_strings(self, data: bytes, min_length: int) -> List[ExtractedString]:
        """Extract ASCII strings from binary data"""
        strings = []
        pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'

        for match in re.finditer(pattern, data):
            value = match.group().decode('ascii', errors='ignore')
            if len(value) <= 256:  # Max string length
                strings.append(ExtractedString(
                    value=value,
                    encoding="ascii",
                    offset=match.start(),
                    length=len(value)
                ))

        return strings

    def _extract_unicode_strings(self, data: bytes, min_length: int) -> List[ExtractedString]:
        """Extract Unicode (UTF-16LE) strings from binary data"""
        strings = []
        # Pattern for UTF-16LE encoded ASCII characters
        pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'

        for match in re.finditer(pattern, data):
            try:
                value = match.group().decode('utf-16-le', errors='ignore')
                if len(value) <= 256:
                    strings.append(ExtractedString(
                        value=value,
                        encoding="unicode",
                        offset=match.start(),
                        length=len(value)
                    ))
            except Exception:
                pass

        return strings

    def _classify_string(self, value: str) -> Optional[str]:
        """Classify a string based on patterns"""
        for category, pattern in self.PATTERNS.items():
            if pattern.match(value):
                return category
        return None

    def _is_pe(self, data: bytes) -> bool:
        """Check if data is a PE file"""
        return len(data) > 2 and data[:2] == b'MZ'

    def _extract_pe_info(self, data: bytes) -> Optional[PEInfo]:
        """Extract PE file information"""
        if not PEFILE_AVAILABLE:
            return None

        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
                ]
            )

            # Extract imports
            imports: Dict[str, List[str]] = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    functions = []
                    for imp in entry.imports:
                        if imp.name:
                            functions.append(imp.name.decode('utf-8', errors='ignore'))
                    imports[dll_name] = functions

            # Extract exports
            exports: List[str] = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))

            # Extract sections
            sections: List[Dict[str, Any]] = []
            for section in pe.sections:
                sections.append({
                    "name": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(section.get_entropy(), 2)
                })

            # Entry point and timestamp
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            timestamp = None
            if pe.FILE_HEADER.TimeDateStamp:
                from datetime import datetime
                try:
                    timestamp = datetime.utcfromtimestamp(
                        pe.FILE_HEADER.TimeDateStamp
                    ).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass

            pe.close()

            return PEInfo(
                imports=imports,
                exports=exports,
                sections=sections,
                entry_point=entry_point,
                timestamp=timestamp
            )

        except Exception:
            return None

    def _generate_suggested_yara(
        self,
        strings: List[ExtractedString],
        pe_info: Optional[PEInfo]
    ) -> str:
        """Generate suggested YARA string definitions"""
        lines = ["    strings:"]

        # Add interesting strings (categorized ones first)
        string_count = 0
        seen_values = set()

        for s in strings:
            if s.category and s.value not in seen_values and string_count < 20:
                seen_values.add(s.value)
                string_count += 1

                # Escape special characters
                escaped = self._escape_yara_string(s.value)

                modifier = "ascii"
                if s.encoding == "unicode":
                    modifier = "wide"

                lines.append(f'        $str{string_count} = "{escaped}" {modifier}  // {s.category}')

        # Add PE import suggestions
        if pe_info and pe_info.imports:
            lines.append("")
            lines.append("    // Suggested PE import conditions:")
            for dll, funcs in list(pe_info.imports.items())[:3]:
                for func in funcs[:2]:
                    lines.append(f'        // pe.imports("{dll}", "{func}")')

        return "\n".join(lines)

    def _escape_yara_string(self, value: str) -> str:
        """Escape special characters for YARA strings"""
        escaped = value.replace("\\", "\\\\")
        escaped = escaped.replace('"', '\\"')
        escaped = escaped.replace("\n", "\\n")
        escaped = escaped.replace("\r", "\\r")
        escaped = escaped.replace("\t", "\\t")
        return escaped
