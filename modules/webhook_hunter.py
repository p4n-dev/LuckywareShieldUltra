import os
import re
from pathlib import Path
from typing import List, Dict, Any

from modules.utils import log_info, log_success, log_warning, log_error


WEBHOOK_PATTERN = re.compile(
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[\w-]{60,80}",
    re.IGNORECASE
)

SCAN_EXTENSIONS = {
    ".exe", ".py", ".pyw", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".txt", ".cfg", ".ini", ".json", ".yaml", ".yml", ".lua",
    ".ahk", ".au3", ".hta", ".wsf"
}

MAX_FILE_SIZE = 5 * 1024 * 1024


class WebhookHunter:
    def __init__(self):
        self.scan_dirs = self._get_scan_dirs()
        self.findings: List[Dict[str, Any]] = []

    @staticmethod
    def _get_scan_dirs() -> List[str]:
        dirs = []
        for env_var in ["TEMP", "TMP", "APPDATA", "LOCALAPPDATA"]:
            val = os.environ.get(env_var, "")
            if val and os.path.isdir(val):
                dirs.append(val)

        user_profile = os.environ.get("USERPROFILE", "")
        if user_profile:
            for sub in ["Downloads", "Desktop", "Documents"]:
                p = os.path.join(user_profile, sub)
                if os.path.isdir(p):
                    dirs.append(p)

        return dirs

    def scan_file(self, file_path: str) -> List[str]:
        try:
            p = Path(file_path)
            if not p.exists() or not p.is_file():
                return []
            if p.stat().st_size > MAX_FILE_SIZE:
                return []
            if p.suffix.lower() not in SCAN_EXTENSIONS:
                return []

            with open(file_path, "rb") as f:
                raw = f.read()

            text = raw.decode("utf-8", errors="ignore")
            return WEBHOOK_PATTERN.findall(text)
        except Exception:
            return []

    def scan_directory(self, target_dir: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        results = []
        base = Path(target_dir)
        if not base.exists():
            return results

        try:
            for root, dirs, files in os.walk(str(base)):
                depth = len(Path(root).relative_to(base).parts)
                if depth > max_depth:
                    dirs.clear()
                    continue

                skip = {"node_modules", ".git", "__pycache__", "venv", ".venv"}
                dirs[:] = [d for d in dirs if d.lower() not in skip]

                for fname in files:
                    fpath = os.path.join(root, fname)
                    webhooks = self.scan_file(fpath)
                    if webhooks:
                        results.append({
                            "file_path": fpath,
                            "webhooks": webhooks,
                            "count": len(webhooks)
                        })
        except Exception:
            pass

        return results

    def run_full_scan(self) -> List[Dict[str, Any]]:
        self.findings = []
        scanned_dirs = 0

        for scan_dir in self.scan_dirs:
            log_info(f"Taraniyor: {scan_dir}")
            results = self.scan_directory(scan_dir)
            self.findings.extend(results)
            scanned_dirs += 1

        return self.findings

    def delete_webhook(self, webhook_url: str) -> bool:
        try:
            import requests
            resp = requests.delete(webhook_url, timeout=10)
            if resp.status_code in [200, 204]:
                log_success(f"Webhook silindi: ...{webhook_url[-30:]}")
                return True
            else:
                log_warning(f"Webhook silinemedi (HTTP {resp.status_code})")
                return False
        except ImportError:
            log_error("'requests' modulu bulunamadi.")
            return False
        except Exception as e:
            log_error(f"Webhook silme hatasi: {e}")
            return False

    def get_summary(self) -> Dict[str, Any]:
        total_webhooks = sum(f["count"] for f in self.findings)
        return {
            "files_with_webhooks": len(self.findings),
            "total_webhooks": total_webhooks,
            "scan_dirs": len(self.scan_dirs),
            "findings": self.findings
        }

