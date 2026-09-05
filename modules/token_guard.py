import os
from pathlib import Path
from typing import List, Dict, Any

from config import SENSITIVE_TARGETS
from modules.utils import log_info, log_success, log_warning, log_error

class TokenGuard:
    def __init__(self):
        self.targets = SENSITIVE_TARGETS

    def audit_sensitive_stores(self) -> Dict[str, List[Dict[str, Any]]]:
        report = {}

        for category, path_list in self.targets.items():
            report[category] = []
            for path_str in path_list:
                p = Path(path_str)
                exists = p.exists()
                item_info = {
                    "path": str(p),
                    "exists": exists,
                    "file_count": 0,
                    "total_size_bytes": 0
                }

                if exists:
                    try:
                        if p.is_dir():
                            files = list(p.glob("*"))
                            item_info["file_count"] = len(files)
                            item_info["total_size_bytes"] = sum(f.stat().st_size for f in files if f.is_file())
                        else:
                            item_info["file_count"] = 1
                            item_info["total_size_bytes"] = p.stat().st_size
                    except Exception as e:
                        item_info["error"] = str(e)

                report[category].append(item_info)

        return report

    def lock_discord_storage(self) -> Dict[str, Any]:
        results = {"hardened": [], "failed": []}
        discord_paths = self.targets.get("Discord", [])

        for path_str in discord_paths:
            p = Path(path_str)
            if p.exists() and p.is_dir():
                try:
                    for f in p.glob("*.ldb"):
                        os.chmod(f, 0o444)
                        results["hardened"].append(str(f))
                    for f in p.glob("*.log"):
                        os.chmod(f, 0o444)
                        results["hardened"].append(str(f))
                except Exception as e:
                    results["failed"].append({"path": path_str, "error": str(e)})

        if results["hardened"]:
            log_success(f"{len(results['hardened'])} adet Discord oturum dosyasi salt-okunur yapildi.")
        return results

    def unlock_discord_storage(self) -> Dict[str, Any]:
        restored = []
        discord_paths = self.targets.get("Discord", [])
        for path_str in discord_paths:
            p = Path(path_str)
            if p.exists() and p.is_dir():
                try:
                    for f in p.glob("*.*"):
                        os.chmod(f, 0o666)
                        restored.append(str(f))
                except Exception:
                    pass
        log_info(f"Discord dizinleri normale donduruldu ({len(restored)} dosya).")
        return {"restored_count": len(restored)}
