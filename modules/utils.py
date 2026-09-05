import os
import sys
import ctypes
import shutil
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from config import QUARANTINE_DIR, LOGS_DIR

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
except Exception:
    pass

class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

try:
    if os.name == 'nt':
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
except Exception:
    pass

def setup_logger() -> logging.Logger:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOGS_DIR / f"shield_{datetime.now().strftime('%Y%m%d')}.log"

    logger = logging.getLogger("LuckywareShield")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger

logger = setup_logger()

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def require_admin_prompt():
    if not is_admin():
        print(f"{Colors.WARNING}[!] Uyari: Yonetici (Administrator) yetkileri olmadan bazi ozellikler calismayabilir.{Colors.ENDC}")

def log_info(msg: str):
    print(f"[*] {msg}")
    logger.info(msg)

def log_success(msg: str):
    print(f"{Colors.GREEN}[+] {msg}{Colors.ENDC}")
    logger.info(msg)

def log_warning(msg: str):
    print(f"{Colors.WARNING}[!] {msg}{Colors.ENDC}")
    logger.warning(msg)

def log_error(msg: str):
    print(f"{Colors.FAIL}[-] {msg}{Colors.ENDC}")
    logger.error(msg)

def log_header(title: str):
    print(f"\n{Colors.BOLD}{title}{Colors.ENDC}")
    logger.info(f"=== {title} ===")

def calculate_hashes(file_path: str) -> Dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
        return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}
    except Exception as e:
        return {"sha256": f"Error: {e}", "md5": f"Error: {e}"}

def quarantine_file(file_path: str, reason: str = "Threat detected") -> Optional[str]:
    try:
        p = Path(file_path)
        if not p.exists():
            return None

        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hashes = calculate_hashes(file_path)
        dest_filename = f"{timestamp}_{p.name}.quarantined"
        dest_path = QUARANTINE_DIR / dest_filename

        shutil.copy2(file_path, dest_path)
        
        try:
            os.chmod(dest_path, 0o444)
        except Exception:
            pass

        try:
            os.remove(file_path)
        except PermissionError:
            log_warning(f"Dosya kilitli: {file_path}")

        manifest_file = QUARANTINE_DIR / "quarantine_manifest.json"
        manifest_data = []
        if manifest_file.exists():
            try:
                with open(manifest_file, "r", encoding="utf-8") as mf:
                    manifest_data = json.load(mf)
            except Exception:
                manifest_data = []

        manifest_data.append({
            "original_path": str(p.resolve()),
            "quarantined_as": str(dest_path.resolve()),
            "timestamp": timestamp,
            "reason": reason,
            "hashes": hashes
        })

        with open(manifest_file, "w", encoding="utf-8") as mf:
            json.dump(manifest_data, mf, indent=2, ensure_ascii=False)

        log_success(f"Karantinaya alindi: {p.name}")
        return str(dest_path)
    except Exception as e:
        log_error(f"Karantina hatasi ({file_path}): {e}")
        return None
