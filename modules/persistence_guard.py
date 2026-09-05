import os
import re
import winreg
from pathlib import Path
from typing import List, Dict, Any

from config import REGISTRY_PERSISTENCE_KEYS, KNOWN_C2_DOMAINS, KNOWN_XOR_KEYS
from modules.utils import (
    log_info, log_success, log_warning, log_error,
    quarantine_file, is_admin
)

def inspect_binary_for_malware(file_path: str) -> bool:
    try:
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return False
        if p.stat().st_size > 30 * 1024 * 1024:
            return False

        with open(file_path, "rb") as f:
            content = f.read()

        for key in KNOWN_XOR_KEYS:
            if key in content:
                return True
    except Exception:
        pass
    return False

class PersistenceGuard:
    def __init__(self, c2_domains: List[str] = None):
        if c2_domains:
            self.c2_domains = c2_domains
        else:
            try:
                from modules.threat_intel import ThreatIntelFeed
                self.c2_domains = ThreatIntelFeed().get_domains()
            except Exception:
                self.c2_domains = KNOWN_C2_DOMAINS

        self.reg_hives = {
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKLM": winreg.HKEY_LOCAL_MACHINE
        }

    def scan_registry_startup(self) -> List[Dict[str, Any]]:
        findings = []

        for display_name, hive_key, subkey in REGISTRY_PERSISTENCE_KEYS:
            hive = self.reg_hives.get(hive_key)
            if not hive:
                continue

            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        val_name, val_data, val_type = winreg.EnumValue(key, i)
                        data_str = str(val_data).lower()

                        is_suspicious = False
                        reasons = []

                        for c2 in self.c2_domains:
                            if c2 in data_str:
                                is_suspicious = True
                                reasons.append(f"C2 Domain: {c2}")
                                break

                        raw_path = str(val_data).split()[0].strip('"')
                        if os.path.exists(raw_path):
                            if inspect_binary_for_malware(raw_path):
                                is_suspicious = True
                                reasons.append("Zararli binary imzasi")

                        findings.append({
                            "hive": hive_key,
                            "subkey": subkey,
                            "value_name": val_name,
                            "value_data": str(val_data),
                            "is_suspicious": is_suspicious,
                            "reasons": reasons
                        })
            except Exception:
                pass

        return findings

    def remove_registry_entry(self, hive_key: str, subkey: str, value_name: str) -> bool:
        if not is_admin():
            log_error("Kayit defteri silme icin Administrator yetkisi gereklidir.")
            return False

        hive = self.reg_hives.get(hive_key)
        if not hive:
            return False

        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, value_name)
            log_success(f"Kayit silindi: [{hive_key}\\{subkey}] -> {value_name}")
            return True
        except Exception as e:
            log_error(f"Kayit defteri silme hatasi ({value_name}): {e}")
            return False

    def scan_startup_folders(self) -> List[Dict[str, Any]]:
        startup_items = []
        user_startup = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
        common_startup = Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"

        for startup_dir in [user_startup, common_startup]:
            if startup_dir.exists():
                for item in startup_dir.iterdir():
                    if item.is_file():
                        is_suspicious = False
                        reasons = []

                        if inspect_binary_for_malware(str(item)):
                            is_suspicious = True
                            reasons.append("Zararli binary imzasi")

                        startup_items.append({
                            "path": str(item.resolve()),
                            "filename": item.name,
                            "is_suspicious": is_suspicious,
                            "reasons": reasons
                        })

        return startup_items

    def scan_temp_droppers(self) -> List[Dict[str, Any]]:
        droppers = []
        temp_dir = Path(os.environ.get("TEMP", ""))
        if not temp_dir.exists():
            return droppers

        try:
            for item in temp_dir.iterdir():
                if item.is_file() and item.suffix.lower() in [".exe", ".dll"]:
                    if inspect_binary_for_malware(str(item)):
                        droppers.append({
                            "path": str(item.resolve()),
                            "name": item.name,
                            "size_bytes": item.stat().st_size,
                            "reason": "Luckyware / RAT Binary Imzasi"
                        })
        except Exception:
            pass

        return droppers

    def clean_all_persistence(self) -> Dict[str, int]:
        stats = {"registry_cleaned": 0, "startup_quarantined": 0, "temp_quarantined": 0}

        reg_findings = self.scan_registry_startup()
        for item in reg_findings:
            if item["is_suspicious"]:
                if self.remove_registry_entry(item["hive"], item["subkey"], item["value_name"]):
                    stats["registry_cleaned"] += 1

        startup_items = self.scan_startup_folders()
        for item in startup_items:
            if item["is_suspicious"]:
                if quarantine_file(item["path"], reason=f"Suspicious: {', '.join(item['reasons'])}"):
                    stats["startup_quarantined"] += 1

        temp_droppers = self.scan_temp_droppers()
        for item in temp_droppers:
            if quarantine_file(item["path"], reason=f"Temp dropper: {item['reason']}"):
                stats["temp_quarantined"] += 1

        return stats
