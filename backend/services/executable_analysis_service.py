"""
Executable sample analysis service for ransomware Layer 2.

The service stores uploaded samples in backend/data/quarantine, extracts static
indicators, runs optional YARA rules, and delegates PE ML scoring to the
existing PEHeaderDetectionService.
"""

import hashlib
import math
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from ml.pe_service import get_pe_detection_service
except ImportError:
    from backend.ml.pe_service import get_pe_detection_service


SUSPICIOUS_IMPORTS = {
    "CryptAcquireContextA",
    "CryptAcquireContextW",
    "CryptEncrypt",
    "CryptGenKey",
    "BCryptEncrypt",
    "BCryptGenRandom",
    "CreateFileA",
    "CreateFileW",
    "WriteFile",
    "MoveFileA",
    "MoveFileW",
    "DeleteFileA",
    "DeleteFileW",
    "FindFirstFileA",
    "FindFirstFileW",
    "FindNextFileA",
    "FindNextFileW",
    "CreateProcessA",
    "CreateProcessW",
    "ShellExecuteA",
    "ShellExecuteW",
    "WinExec",
    "RegSetValueA",
    "RegSetValueW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
}


YARA_RULES = """
rule Ransomware_Static_Indicators {
    strings:
        $note1 = "Your files have been encrypted" nocase
        $note2 = "decrypt" nocase
        $note3 = "bitcoin" nocase
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "wmic shadowcopy delete" nocase
        $cmd3 = "bcdedit /set" nocase
    condition:
        any of them
}
"""


class ExecutableAnalysisService:
    """Analyze quarantined Windows executables without replacing ML scoring."""

    def __init__(self, quarantine_dir: Optional[Path] = None):
        backend_root = Path(__file__).resolve().parents[1]
        self.quarantine_dir = (
            quarantine_dir or backend_root / "data" / "quarantine"
        ).resolve()
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.pe_service = get_pe_detection_service()

    def store_upload(self, upload_file: Any) -> Path:
        """Persist an UploadFile stream into quarantine using a safe name."""
        original_name = Path(upload_file.filename or "sample.exe").name
        suffix = Path(original_name).suffix.lower()
        if suffix not in {".exe", ".dll", ".scr", ".bin"}:
            raise ValueError("Only executable samples are supported")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", original_name)
        destination = (self.quarantine_dir / f"{timestamp}_{safe_name}").resolve()
        destination.relative_to(self.quarantine_dir)

        with destination.open("wb") as sample:
            shutil.copyfileobj(upload_file.file, sample)

        if destination.stat().st_size == 0:
            destination.unlink(missing_ok=True)
            raise ValueError("Uploaded executable is empty")

        return destination

    def analyze_file(self, sample_path: Path) -> Dict[str, Any]:
        """Run static analysis and existing PE ML scoring on a quarantined file."""
        resolved = sample_path.resolve()
        resolved.relative_to(self.quarantine_dir)
        if not resolved.exists() or not resolved.is_file():
            raise FileNotFoundError("Quarantined sample does not exist")

        data = resolved.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        entropy = self._calculate_entropy(data)
        imports = self._extract_imports(resolved)
        suspicious_imports = sorted(set(imports) & SUSPICIOUS_IMPORTS)
        yara_result = self._scan_yara(resolved)
        pe_result = self.pe_service.predict(str(resolved))

        static_score = self._calculate_static_score(
            entropy=entropy,
            suspicious_imports=suspicious_imports,
            yara_matches=yara_result.get("matches", []),
        )
        ml_confidence = float(pe_result.get("confidence") or 0.0)
        model_loaded = bool(pe_result.get("model_loaded"))
        confidence = max(ml_confidence, static_score)
        is_ransomware = bool(pe_result.get("is_ransomware")) or confidence >= 0.7
        severity = self._severity_from_score(confidence)

        return {
            "sample": {
                "filename": resolved.name,
                "path": str(resolved),
                "size_bytes": len(data),
                "sha256": sha256,
            },
            "pe_header": {
                "features_extracted": pe_result.get("features_extracted", 0),
                "model_loaded": model_loaded,
                "model_error": pe_result.get("error"),
                "model_warning": pe_result.get("warning"),
            },
            "ml": {
                "is_ransomware": bool(pe_result.get("is_ransomware")),
                "confidence": ml_confidence,
                "prediction_class": pe_result.get("prediction_class"),
            },
            "static_analysis": {
                "entropy": round(entropy, 4),
                "suspicious_imports": suspicious_imports,
                "suspicious_import_count": len(suspicious_imports),
                "imports_scanned": len(imports),
                "yara": yara_result,
                "static_score": round(static_score, 4),
            },
            "verdict": {
                "is_ransomware": is_ransomware,
                "confidence": round(confidence, 4),
                "severity": severity,
                "indicators": self._build_indicators(
                    pe_result, entropy, suspicious_imports, yara_result
                ),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def analyze_upload(self, upload_file: Any) -> Dict[str, Any]:
        sample_path = self.store_upload(upload_file)
        return self.analyze_file(sample_path)

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in counts:
            if count:
                probability = count / length
                entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def _extract_imports(sample_path: Path) -> List[str]:
        try:
            import pefile
        except ImportError:
            return []

        imports: List[str] = []
        try:
            pe = pefile.PE(str(sample_path), fast_load=False)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imported in entry.imports:
                        if imported.name:
                            imports.append(imported.name.decode(errors="ignore"))
        except Exception:
            return []
        return imports

    @staticmethod
    def _scan_yara(sample_path: Path) -> Dict[str, Any]:
        try:
            import yara
        except ImportError:
            return {
                "available": False,
                "matches": [],
                "error": "yara-python is not installed",
            }

        try:
            rules = yara.compile(source=YARA_RULES)
            matches = rules.match(str(sample_path))
            return {
                "available": True,
                "matches": [match.rule for match in matches],
                "error": None,
            }
        except Exception as exc:
            return {"available": True, "matches": [], "error": str(exc)}

    @staticmethod
    def _calculate_static_score(
        entropy: float,
        suspicious_imports: List[str],
        yara_matches: List[str],
    ) -> float:
        score = 0.0
        if entropy >= 7.2:
            score += 0.35
        elif entropy >= 6.8:
            score += 0.2
        score += min(0.3, len(suspicious_imports) * 0.05)
        if yara_matches:
            score += 0.35
        return min(1.0, score)

    @staticmethod
    def _severity_from_score(score: float) -> str:
        if score >= 0.9:
            return "CRITICAL"
        if score >= 0.7:
            return "HIGH"
        if score >= 0.4:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _build_indicators(
        pe_result: Dict[str, Any],
        entropy: float,
        suspicious_imports: List[str],
        yara_result: Dict[str, Any],
    ) -> List[str]:
        indicators: List[str] = []
        if pe_result.get("is_ransomware"):
            indicators.append("Existing PE ML model classified sample as ransomware")
        if entropy >= 7.2:
            indicators.append("High file entropy consistent with packing or encryption")
        if suspicious_imports:
            indicators.append("Suspicious file, crypto, process, or network imports found")
        if yara_result.get("matches"):
            indicators.append("YARA ransomware indicators matched")
        if pe_result.get("error"):
            indicators.append(f"PE ML analysis error: {pe_result['error']}")
        return indicators


_executable_analysis_service = None


def get_executable_analysis_service() -> ExecutableAnalysisService:
    global _executable_analysis_service
    if _executable_analysis_service is None:
        _executable_analysis_service = ExecutableAnalysisService()
    return _executable_analysis_service
