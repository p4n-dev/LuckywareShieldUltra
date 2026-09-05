import os
from pathlib import Path
from typing import List, Dict, Any

from config import KNOWN_C2_DOMAINS, KNOWN_XOR_KEYS
from modules.utils import log_info, log_success, log_warning, log_error


SYSTEM_TRUSTED_PREFIXES = (
    os.environ.get("SystemRoot", "C:\\Windows").lower(),
    os.environ.get("ProgramFiles", "C:\\Program Files").lower(),
    os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)").lower(),
)

TRUSTED_PARENTS = {
    "services.exe", "wininit.exe", "winlogon.exe",
    "lsass.exe", "csrss.exe", "smss.exe"
}

SUSPICIOUS_CHILD_OF_SVCHOST = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe"
}

WHITELISTED_NAMES = {
    "python.exe", "pythonw.exe", "code.exe", "devenv.exe",
    "explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "discord.exe", "steam.exe", "luckywareshieldultra.exe",
    "luckywareshield.exe"
}


class InjectionDetector:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def scan_processes(self) -> List[Dict[str, Any]]:
        self.findings = []
        try:
            import psutil
        except ImportError:
            log_error("'psutil' modulu bulunamadi.")
            return self.findings

        for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "cmdline"]):
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                exe_path = info["exe"] or ""
                exe_lower = exe_path.lower()
                pid = info["pid"]

                if name in WHITELISTED_NAMES:
                    continue
                if any(exe_lower.startswith(p) for p in SYSTEM_TRUSTED_PREFIXES):
                    continue

                issues = []

                # Svchost child anomaly
                try:
                    parent = psutil.Process(info["ppid"])
                    parent_name = (parent.name() or "").lower()
                    if parent_name == "svchost.exe" and name in SUSPICIOUS_CHILD_OF_SVCHOST:
                        issues.append(f"svchost.exe -> {name} (supheli child process)")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # Command-line C2 domain check
                cmdline = " ".join(info["cmdline"] or []).lower()
                for c2 in KNOWN_C2_DOMAINS:
                    if c2 in cmdline:
                        issues.append(f"Komut satirinda C2 domain: {c2}")
                        break

                # Binary signature check (lightweight — only small files)
                if exe_path and os.path.isfile(exe_path):
                    try:
                        fsize = Path(exe_path).stat().st_size
                        if 1024 < fsize < 10 * 1024 * 1024:
                            with open(exe_path, "rb") as f:
                                chunk = f.read(1024 * 512)
                            for key in KNOWN_XOR_KEYS:
                                if key in chunk:
                                    issues.append(f"Binary imzasi: {key.decode(errors='ignore')}")
                                    break
                    except (PermissionError, OSError):
                        pass

                # Suspicious unsigned exe in user directories
                if exe_path and not any(exe_lower.startswith(p) for p in SYSTEM_TRUSTED_PREFIXES):
                    user_profile = os.environ.get("USERPROFILE", "").lower()
                    temp_dir = os.environ.get("TEMP", "").lower()
                    if exe_lower.startswith(temp_dir):
                        issues.append("TEMP dizininden calistirilmis surec")
                    elif user_profile and "downloads" in exe_lower:
                        issues.append("Downloads dizininden calistirilmis surec")

                if issues:
                    self.findings.append({
                        "pid": pid,
                        "name": name,
                        "exe": exe_path,
                        "issues": issues,
                        "severity": "HIGH" if len(issues) > 1 else "MEDIUM"
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return self.findings

    def get_summary(self) -> Dict[str, Any]:
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        return {
            "total_suspicious": len(self.findings),
            "high_severity": high,
            "medium_severity": medium,
            "findings": self.findings
        }

