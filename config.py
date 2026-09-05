import sys
import os
from pathlib import Path
from dotenv import load_dotenv

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
    if hasattr(sys, "_MEIPASS"):
        load_dotenv(Path(sys._MEIPASS) / ".env")
    load_dotenv(BASE_DIR / ".env", override=True)
else:
    BASE_DIR = Path(__file__).resolve().parent
    load_dotenv(BASE_DIR / ".env")

APP_NAME = "Luckyware Shield Ultra"
APP_VERSION = "2.2.0"

QUARANTINE_DIR = BASE_DIR / "quarantine"
LOGS_DIR = BASE_DIR / "logs"

HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_BACKUP_PATH = r"C:\Windows\System32\drivers\etc\hosts.luckyware_bak"

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

_raw_feed_urls = os.environ.get("C2_FEED_URLS") or os.environ.get("C2_FEED_URL", "")
C2_FEED_URLS = [
    url.strip() for url in _raw_feed_urls.split(",")
    if url.strip()
]
C2_FEED_CACHE_FILE = BASE_DIR / "c2_cache.json"
C2_FEED_UPDATE_INTERVAL = 5 * 60

KNOWN_C2_DOMAINS = [
    "exo-api.tf",
    "api.exo-api.tf",
    "gate.exo-api.tf",
    "c2.exo-api.tf",
    "devruntime.cy",
    "api.devruntime.cy",
    "cdn.devruntime.cy",
    "auth.devruntime.cy",
    "gate.devruntime.cy",
    "exoapi.xyz",
    "exoapi.cc",
    "exoapi.top",
    "exoapi.online",
    "exo-api.online",
    "exo-api.cc",
    "exo-api.xyz",
    "vcc-library.uk",
    "darkside.cy",
    "zetolacs-cloud.top",
    "frozi.cc",
    "nuzzyservices.com",
    "balista.lol",
    "phobos.top",
    "phobosransom.com",
    "pee-files.nl",
    "luckyware.co",
    "luckyware.cc",
    "91.92.243.218",
    "dhszo.darkside.cy",
    "188.114.96.11",
    "risesmp.net",
    "i-like.boats",
    "luckystrike.pw",
    "krispykreme.pw",
    "vcc-redistrbutable.top",
    "i-slept-with-ur.mom"
]

KNOWN_MALWARE_PROCESSES = [
    "berok.exe",
    "retev.exe",
]

KNOWN_XOR_KEYS = [
    b"NtExploreProcess",
    b"VccLibaries",
    b"VccLibraries",
    b"exo-api",
    b"devruntime",
    b"Berok",
    b"Retev",
]

SUSPICIOUS_CODE_PATTERNS = [
    r"NtExploreProcess",
    r"VccLibaries",
    r"VccLibraries",
    r"exo-api\.tf",
    r"devruntime\.cy",
    r"Berok\.exe",
    r"Retev\.exe",
    r"URLDownloadToFile[AW]?\s*\(.*?(?:exo-api|devruntime|catbox)",
    r"powershell(?:\.exe)?\s+.*?(?:exo-api|devruntime|Berok|Retev)",
    r"discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
]

REGISTRY_PERSISTENCE_KEYS = [
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    (r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKCU", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
]

MONITORED_DIRECTORIES = [
    os.environ.get("TEMP", ""),
    os.environ.get("APPDATA", ""),
    os.environ.get("LOCALAPPDATA", ""),
    os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
]

SENSITIVE_TARGETS = {
    "Discord": [
        os.path.join(os.environ.get("APPDATA", ""), "discord", "Local Storage", "leveldb"),
        os.path.join(os.environ.get("APPDATA", ""), "discordcanary", "Local Storage", "leveldb"),
        os.path.join(os.environ.get("APPDATA", ""), "discordptb", "Local Storage", "leveldb"),
        os.path.join(os.environ.get("APPDATA", ""), "Lightcord", "Local Storage", "leveldb"),
    ],
    "Browser": [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data", "Default", "Login Data"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "BraveSoftware", "Brave-Browser", "User Data", "Default", "Login Data"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data", "Default", "Login Data"),
        os.path.join(os.environ.get("APPDATA", ""), "Opera Software", "Opera Stable", "Login Data"),
    ],
    "Telegram": [
        os.path.join(os.environ.get("APPDATA", ""), "Telegram Desktop", "tdata"),
    ]
}

COMMON_SDK_INCLUDE_PATHS = [
    r"C:\Program Files (x86)\Windows Kits\10\Include",
    r"C:\Program Files (x86)\Windows Kits\8.1\Include",
    r"C:\Program Files\Microsoft Visual Studio",
    r"C:\Program Files (x86)\Microsoft Visual Studio",
]
