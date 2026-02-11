"""Testing service for YARA rules"""

import os
import asyncio
from pathlib import Path
from typing import List, Dict, Any
from ...api.models.responses import TestResponse, TestResult, MatchDetail

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class TestingService:
    """Service for testing YARA rules against files"""

    MAX_FILES = 1000  # Maximum files to scan in a directory
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max per file

    def test_data(
        self,
        rule_content: str,
        data: bytes,
        filename: str
    ) -> TestResponse:
        """Test a YARA rule against binary data"""
        if not YARA_AVAILABLE:
            return TestResponse(
                success=False,
                total_files=0,
                matched_files=0,
                error="yara-python not installed"
            )

        try:
            # Compile the rule
            rules = yara.compile(source=rule_content)
        except yara.SyntaxError as e:
            return TestResponse(
                success=False,
                total_files=0,
                matched_files=0,
                error=f"Rule compilation error: {str(e)}"
            )
        except yara.Error as e:
            return TestResponse(
                success=False,
                total_files=0,
                matched_files=0,
                error=f"YARA error: {str(e)}"
            )

        # Run the scan
        result = self._scan_data(rules, data, filename)

        matched = 1 if result.matches else 0
        return TestResponse(
            success=True,
            total_files=1,
            matched_files=matched,
            results=[result]
        )

    async def test_path(
        self,
        rule_content: str,
        target_path: str
    ) -> TestResponse:
        """Test a YARA rule against a file or directory"""
        if not YARA_AVAILABLE:
            return TestResponse(
                success=False,
                total_files=0,
                matched_files=0,
                error="yara-python not installed"
            )

        try:
            rules = yara.compile(source=rule_content)
        except yara.SyntaxError as e:
            return TestResponse(
                success=False,
                total_files=0,
                matched_files=0,
                error=f"Rule compilation error: {str(e)}"
            )
        except yara.Error as e:
            return TestResponse(
                success=False,
                total_files=0,
                matched_files=0,
                error=f"YARA error: {str(e)}"
            )

        path = Path(target_path)

        if not path.exists():
            return TestResponse(
                success=False,
                total_files=0,
                matched_files=0,
                error=f"Path not found: {target_path}"
            )

        # Collect files to scan
        files_to_scan: List[Path] = []

        if path.is_file():
            files_to_scan.append(path)
        else:
            # Scan directory (non-recursive by default for safety)
            for item in path.iterdir():
                if item.is_file():
                    files_to_scan.append(item)
                    if len(files_to_scan) >= self.MAX_FILES:
                        break

        # Scan all files
        results: List[TestResult] = []
        matched_count = 0

        for file_path in files_to_scan:
            result = await self._scan_file_async(rules, file_path)
            results.append(result)
            if result.matches:
                matched_count += 1

        return TestResponse(
            success=True,
            total_files=len(files_to_scan),
            matched_files=matched_count,
            results=results
        )

    def _scan_data(
        self,
        rules: "yara.Rules",
        data: bytes,
        filename: str
    ) -> TestResult:
        """Scan binary data with compiled rules"""
        try:
            matches = rules.match(data=data)
            match_details = self._format_matches(matches)

            return TestResult(
                file_path=filename,
                file_size=len(data),
                matches=match_details
            )
        except Exception as e:
            return TestResult(
                file_path=filename,
                file_size=len(data),
                error=str(e)
            )

    async def _scan_file_async(
        self,
        rules: "yara.Rules",
        file_path: Path
    ) -> TestResult:
        """Scan a file asynchronously"""
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._scan_file,
            rules,
            file_path
        )

    def _scan_file(
        self,
        rules: "yara.Rules",
        file_path: Path
    ) -> TestResult:
        """Scan a file with compiled rules"""
        try:
            file_size = file_path.stat().st_size

            if file_size > self.MAX_FILE_SIZE:
                return TestResult(
                    file_path=str(file_path),
                    file_size=file_size,
                    error=f"File too large (max {self.MAX_FILE_SIZE // (1024*1024)}MB)"
                )

            matches = rules.match(str(file_path))
            match_details = self._format_matches(matches)

            return TestResult(
                file_path=str(file_path),
                file_size=file_size,
                matches=match_details
            )
        except PermissionError:
            return TestResult(
                file_path=str(file_path),
                file_size=0,
                error="Permission denied"
            )
        except Exception as e:
            return TestResult(
                file_path=str(file_path),
                file_size=0,
                error=str(e)
            )

    def _format_matches(self, matches: list) -> List[MatchDetail]:
        """Format YARA matches for response"""
        details = []

        for match in matches:
            # Extract matched strings
            strings_list = []
            for string_match in match.strings:
                for instance in string_match.instances:
                    strings_list.append({
                        "identifier": string_match.identifier,
                        "offset": instance.offset,
                        "data": instance.matched_data[:100].hex() if len(instance.matched_data) > 100
                                else instance.matched_data.hex()
                    })

            details.append(MatchDetail(
                rule_name=match.rule,
                tags=list(match.tags) if match.tags else [],
                meta=dict(match.meta) if match.meta else {},
                strings=strings_list
            ))

        return details
