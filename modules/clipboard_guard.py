import re
import time
import threading
from typing import Optional, Callable

from modules.utils import log_info, log_success, log_warning
from modules.telegram_notifier import TelegramNotifier


BTC_PATTERN = re.compile(r"^(bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
ETH_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
LTC_PATTERN = re.compile(r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$")
XMR_PATTERN = re.compile(r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")
SOL_PATTERN = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

WALLET_PATTERNS = {
    "BTC": BTC_PATTERN,
    "ETH": ETH_PATTERN,
    "LTC": LTC_PATTERN,
    "XMR": XMR_PATTERN,
}


class ClipboardGuard:
    def __init__(self, on_clipper_detected: Optional[Callable] = None):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_clipboard = ""
        self._last_wallet_type = ""
        self._last_wallet_addr = ""
        self._detections = 0
        self.on_clipper_detected = on_clipper_detected
        self._telegram = TelegramNotifier()
        self._check_interval = 3.0

    @staticmethod
    def _get_clipboard() -> str:
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            if not user32.OpenClipboard(None):
                return ""

            try:
                h_data = user32.GetClipboardData(13)  # CF_UNICODETEXT
                if not h_data:
                    return ""

                kernel32.GlobalLock.restype = ctypes.c_wchar_p
                text = kernel32.GlobalLock(h_data)
                if text:
                    result = str(text)
                    kernel32.GlobalUnlock(h_data)
                    return result.strip()
                return ""
            finally:
                user32.CloseClipboard()
        except Exception:
            return ""

    @staticmethod
    def _detect_wallet(text: str) -> Optional[str]:
        if not text or len(text) < 20 or len(text) > 120:
            return None
        if " " in text or "\n" in text:
            return None

        for wallet_type, pattern in WALLET_PATTERNS.items():
            if pattern.match(text):
                return wallet_type
        return None

    def _monitor_loop(self):
        while self._running:
            try:
                current = self._get_clipboard()

                if current and current != self._last_clipboard:
                    wallet_type = self._detect_wallet(current)

                    if wallet_type:
                        if (self._last_wallet_type == wallet_type and
                                self._last_wallet_addr and
                                self._last_wallet_addr != current):

                            self._detections += 1
                            log_warning(
                                f"CLIPPER TESPIT! {wallet_type} adresi degistirildi: "
                                f"{self._last_wallet_addr[:12]}... -> {current[:12]}..."
                            )

                            if self._telegram.is_configured:
                                self._telegram.send_alert_async({
                                    "pid": "N/A",
                                    "name": "Clipboard Clipper",
                                    "exe": "Pano Izleyici",
                                    "reason": (
                                        f"{wallet_type} cuzdani degistirildi! "
                                        f"Orijinal: {self._last_wallet_addr[:16]}... "
                                        f"Sahte: {current[:16]}..."
                                    )
                                })

                            from modules.live_shield import send_windows_notification
                            send_windows_notification(
                                "Clipper Tespit Edildi!",
                                f"{wallet_type} cuzdan adresi degistirildi!"
                            )

                            if self.on_clipper_detected:
                                self.on_clipper_detected(wallet_type, self._last_wallet_addr, current)

                        self._last_wallet_type = wallet_type
                        self._last_wallet_addr = current

                    self._last_clipboard = current

            except Exception:
                pass

            for _ in range(int(self._check_interval * 10)):
                if not self._running:
                    break
                time.sleep(0.1)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True,
            name="ClipboardGuard"
        )
        self._thread.start()
        log_info("Clipboard Guard (Clipper Tespiti) aktif.")

    def stop(self):
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def detection_count(self) -> int:
        return self._detections

    def get_stats(self) -> dict:
        return {
            "running": self._running,
            "detections": self._detections,
            "last_wallet_type": self._last_wallet_type or "N/A",
            "check_interval": self._check_interval
        }

