import os
import sys
import time
import gc
import threading
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, Callable, Set

from config import KNOWN_C2_DOMAINS, KNOWN_XOR_KEYS, KNOWN_MALWARE_PROCESSES
from modules.network_shield import NetworkShield
from modules.threat_intel import ThreatIntelFeed
from modules.telegram_notifier import TelegramNotifier
from modules.utils import (
    log_info, log_success, log_warning, log_error,
    quarantine_file
)

SYSTEM_TRUSTED_PREFIXES = (
    os.environ.get("SystemRoot", "C:\\Windows").lower(),
    os.environ.get("ProgramFiles", "C:\\Program Files").lower(),
    os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)").lower(),
)

WHITELISTED_EXE_NAMES = {
    "antigravity.exe", "code.exe", "devenv.exe", "pyinstaller.exe",
    "luckywareshieldultra.exe", "luckywareshield.exe", "luckywareshield_daemon.exe", "python.exe",
    "pythonw.exe", "explorer.exe", "taskhostw.exe", "searchhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "discord.exe",
    "steam.exe", "epicgameslauncher.exe"
}


def send_windows_notification(title: str, message: str):
    try:
        ps_script = f"""
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $textNodes = $template.GetElementsByTagName("text")
        $textNodes.Item(0).AppendChild($template.CreateTextNode("{title}")) > $null
        $textNodes.Item(1).AppendChild($template.CreateTextNode("{message}")) > $null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Luckyware Shield Ultra").Show($toast)
        """
        subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000
        )
    except Exception:
        pass


def inspect_binary_for_malware_signatures(file_path: str) -> bool:
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


class LiveShield:
    def __init__(self, auto_terminate: bool = True, on_threat_detected: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.auto_terminate = auto_terminate
        self.on_threat_detected = on_threat_detected
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._known_pids: Set[int] = set()
        self.stats = {"processes_scanned": 0, "threats_blocked": 0, "files_quarantined": 0}
        self._tick_count = 0
        self._net_shield = NetworkShield()
        self.my_pid = os.getpid()
        self._threat_intel = ThreatIntelFeed()
        self._c2_domains: list = []
        self._telegram = TelegramNotifier()

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._initialize_baselines()
        self._c2_domains = self._threat_intel.get_domains()
        self._threat_intel.start_auto_update()
        log_info(f"C2 domain listesi yuklendi: {len(self._c2_domains)} domain")
        if self._telegram.is_configured:
            log_info("Telegram bildirimleri aktif.")
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="LuckywareShieldWatchdog")
        self._thread.start()
        log_success("Canli Kalkan aktif edildi. Bu pencereyi kapatmayin.")

    def stop(self):
        self.is_running = False
        self._threat_intel.stop_auto_update()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        log_info("Canli Kalkan durduruldu.")

    def _initialize_baselines(self):
        try:
            import psutil
            self._known_pids = {p.pid for p in psutil.process_iter(['pid'])}
        except Exception:
            self._known_pids = set()

    def _monitor_loop(self):
        while self.is_running:
            try:
                self._scan_new_processes()
                self._tick_count += 1
                if self._tick_count % 30 == 0:
                    if not self._net_shield.is_hosts_shield_active():
                        self._net_shield.apply_hosts_block()
                    self._c2_domains = self._threat_intel.get_domains()
                    gc.collect()
            except Exception:
                pass
            time.sleep(2.0)

    def _scan_new_processes(self):
        try:
            import psutil
            current_procs = {p.pid: p for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline'])}
            new_pids = set(current_procs.keys()) - self._known_pids

            for pid in new_pids:
                if pid == self.my_pid:
                    continue

                proc = current_procs[pid]
                try:
                    name = (proc.info['name'] or "").lower()
                    exe_path = proc.info['exe'] or ""
                    exe_lower = exe_path.lower()
                    raw_cmd = " ".join(proc.info['cmdline'] or [])
                    cmdline = raw_cmd.lower()
                    self.stats["processes_scanned"] += 1

                    is_threat = False
                    threat_reason = ""

                    if name in KNOWN_MALWARE_PROCESSES:
                        is_threat = True
                        threat_reason = f"Luckyware Process: {name}"

                    if not is_threat:
                        c2_list = self._c2_domains or KNOWN_C2_DOMAINS
                        for c2_domain in c2_list:
                            if c2_domain in cmdline:
                                is_threat = True
                                threat_reason = f"C2 Domain Iletisimi: {c2_domain}"
                                break

                    if not is_threat and name == "ktmutil.exe" and ("-c" in cmdline or "http" in cmdline or len(proc.info['cmdline'] or []) > 1):
                        is_threat = True
                        threat_reason = "Hollowed ktmutil.exe injection"

                    if not is_threat and name not in WHITELISTED_EXE_NAMES and not any(exe_lower.startswith(prefix) for prefix in SYSTEM_TRUSTED_PREFIXES):
                        if exe_path and os.path.exists(exe_path):
                            if inspect_binary_for_malware_signatures(exe_path):
                                is_threat = True
                                threat_reason = "Luckyware Binary Imzasi (NtExploreProcess / VccLibaries)"

                    if is_threat:
                        self.stats["threats_blocked"] += 1
                        log_warning(f"Tehdit engellendi: {name} (PID: {pid}) - {threat_reason}")

                        threat_data = {"pid": pid, "name": name, "exe": exe_path, "reason": threat_reason}

                        if self.on_threat_detected:
                            self.on_threat_detected(threat_data)

                        self._telegram.send_alert_async(threat_data)

                        if self.auto_terminate:
                            try:
                                proc.kill()
                                log_success(f"Zararli surec sonlandirildi (PID: {pid})")
                                if exe_path and os.path.exists(exe_path) and not any(exe_lower.startswith(prefix) for prefix in SYSTEM_TRUSTED_PREFIXES):
                                    quarantine_file(exe_path, reason=f"Live Watchdog: {threat_reason}")
                                    self.stats["files_quarantined"] += 1
                                send_windows_notification("Luckyware Shield Ultra", f"Zararli surec engellendi: {name}")
                            except Exception as e:
                                log_error(f"Surec sonlandirma hatasi: {e}")

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            self._known_pids = set(current_procs.keys())

        except ImportError:
            pass
