import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from config import (
    COMMON_SDK_INCLUDE_PATHS,
    KNOWN_XOR_KEYS,
    SUSPICIOUS_CODE_PATTERNS
)
from modules.utils import (
    log_info, log_success, log_warning, log_error,
    quarantine_file
)

TARGET_EXTENSIONS = {
    ".h", ".hpp", ".c", ".cpp", ".cc", ".cxx",
    ".vcxproj", ".vcxproj.user", ".vcxproj.filters",
    ".suo", ".props", ".targets", ".sln", ".rc"
}

class SDKProjectScanner:
    def __init__(self, custom_paths: Optional[List[str]] = None):
        self.scan_paths = custom_paths or COMMON_SDK_INCLUDE_PATHS
        self.compiled_patterns = [
            (pattern, re.compile(pattern, re.IGNORECASE))
            for pattern in SUSPICIOUS_CODE_PATTERNS
        ]

    def scan_path(self, target_dir: str, max_depth: int = 10) -> List[Dict[str, Any]]:
        findings = []
        p = Path(target_dir)
        if not p.exists():
            return findings

        log_info(f"Taraniyor: {p.resolve()}")

        try:
            for root, dirs, files in os.walk(str(p)):
                depth = len(Path(root).relative_to(p).parts)
                if depth > max_depth:
                    continue

                for file in files:
                    file_path = Path(root) / file
                    ext = file_path.suffix.lower()

                    if ext in TARGET_EXTENSIONS or file.endswith(".suo"):
                        result = self.inspect_file(str(file_path))
                        if result:
                            findings.append(result)
        except Exception as e:
            log_error(f"Dizin tarama hatasi ({target_dir}): {e}")

        return findings

    def inspect_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read(10 * 1024 * 1024)

            matched_xor_keys = []
            for key in KNOWN_XOR_KEYS:
                if key in raw_bytes:
                    matched_xor_keys.append(key.decode(errors="ignore"))

            text_matches = []
            try:
                text = raw_bytes.decode("utf-8", errors="ignore")
                for raw_pat, regex in self.compiled_patterns:
                    matches = regex.findall(text)
                    if matches:
                        lines = text.splitlines()
                        for i, line in enumerate(lines, 1):
                            if regex.search(line):
                                text_matches.append({
                                    "pattern": raw_pat,
                                    "line": i,
                                    "snippet": line.strip()[:120]
                                })
            except Exception:
                pass

            if matched_xor_keys or text_matches:
                severity = "HIGH" if matched_xor_keys or any("NtExploreProcess" in m["pattern"] or "LuckyWare" in m["pattern"] for m in text_matches) else "MEDIUM"
                return {
                    "file_path": file_path,
                    "severity": severity,
                    "xor_keys": matched_xor_keys,
                    "text_matches": text_matches,
                    "size_bytes": len(raw_bytes)
                }

        except Exception:
            pass

        return None

    def clean_infected_file(self, file_path: str) -> bool:
        p = Path(file_path)
        if not p.exists():
            return False

        ext = p.suffix.lower()

        if ext in [".suo", ".user"] or ".suo" in p.name:
            log_warning(f"Zararli dosya karantinaya aliniyor: {p.name}")
            return quarantine_file(file_path, reason="Luckyware .suo infection") is not None

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            backup_file = p.with_suffix(p.suffix + ".luckyware_bak")
            with open(backup_file, "w", encoding="utf-8") as f:
                f.write(content)

            cleaned_lines = []
            removed_count = 0

            for line in content.splitlines(keepends=True):
                is_suspicious = False
                for raw_pat, regex in self.compiled_patterns:
                    if regex.search(line):
                        is_suspicious = True
                        break

                if is_suspicious:
                    cleaned_lines.append(f"// CLEANED: /* {line.strip()} */\n")
                    removed_count += 1
                else:
                    cleaned_lines.append(line)

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(cleaned_lines)

            log_success(f"{p.name} dosyasindan {removed_count} satir temizlendi.")
            return True
        except Exception as e:
            log_error(f"Dosya temizleme hatasi ({file_path}): {e}")
            return False

    def run_full_sdk_scan(self) -> List[Dict[str, Any]]:
        all_findings = []
        for path_str in self.scan_paths:
            if os.path.exists(path_str):
                findings = self.scan_path(path_str)
                all_findings.extend(findings)
        return all_findings

