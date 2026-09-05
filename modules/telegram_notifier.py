import time
import socket
import threading
import html
from datetime import datetime
from typing import Dict, Any

from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, APP_NAME
from modules.utils import log_success, log_warning, log_error


class TelegramNotifier:

    API_URL = "https://api.telegram.org/bot{token}/sendMessage"
    MIN_INTERVAL = 2.0

    def __init__(self, bot_token: str = "", chat_id: str = ""):
        self.bot_token = bot_token or TELEGRAM_BOT_TOKEN
        self.chat_id = chat_id or TELEGRAM_CHAT_ID
        self._last_sent: float = 0.0
        self._lock = threading.Lock()

    @property
    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def _format_threat_message(self, threat_info: Dict[str, Any]) -> str:
        hostname = html.escape(socket.gethostname())
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pid = html.escape(str(threat_info.get("pid", "N/A")))
        name = html.escape(str(threat_info.get("name", "Bilinmiyor")))
        exe = html.escape(str(threat_info.get("exe", "N/A")))
        reason = html.escape(str(threat_info.get("reason", "Bilinmiyor")))

        return (
            f"🚨 <b>{html.escape(APP_NAME)} — TEHDİT TESPİT EDİLDİ</b>\n\n"
            f"📛 <b>Süreç:</b> <code>{name}</code> (PID: <code>{pid}</code>)\n"
            f"📁 <b>Yol:</b> <code>{exe}</code>\n"
            f"⚠️ <b>Sebep:</b> {reason}\n"
            f"🕐 <b>Zaman:</b> {ts}\n"
            f"💻 <b>Bilgisayar:</b> {hostname}\n\n"
            f"✅ <i>Süreç sonlandırıldı ve dosya karantinaya alındı.</i>"
        )

    def send_alert(self, threat_info: Dict[str, Any]) -> bool:
        if not self.is_configured:
            return False
        return self._send(self._format_threat_message(threat_info), parse_mode="HTML")

    def send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        if not self.is_configured:
            return False
        return self._send(text, parse_mode=parse_mode)

    def _send(self, text: str, parse_mode: str = "HTML") -> bool:
        with self._lock:
            elapsed = time.time() - self._last_sent
            if elapsed < self.MIN_INTERVAL:
                time.sleep(self.MIN_INTERVAL - elapsed)

            try:
                import requests
                url = self.API_URL.format(token=self.bot_token)
                payload = {
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": parse_mode,
                    "disable_web_page_preview": True
                }
                resp = requests.post(url, json=payload, timeout=10)
                self._last_sent = time.time()

                if resp.status_code == 200 and resp.json().get("ok"):
                    log_success("Telegram bildirimi gonderildi.")
                    return True

                err_desc = resp.json().get('description', str(resp.status_code)) if resp.text else str(resp.status_code)
                log_warning(f"Telegram API hatasi: {err_desc}")
                return False

            except ImportError:
                log_error("'requests' modulu bulunamadi. pip install requests")
                return False
            except Exception as e:
                log_error(f"Telegram bildirim hatasi: {e}")
                return False

    def send_alert_async(self, threat_info: Dict[str, Any]):
        if not self.is_configured:
            return
        threading.Thread(
            target=self.send_alert, args=(threat_info,),
            daemon=True, name="TelegramAlert"
        ).start()

    def test_connection(self) -> bool:
        if not self.is_configured:
            log_warning("Telegram yapilandirilmamis. .env dosyasini kontrol edin.")
            return False

        test_msg = (
            f"✅ <b>{html.escape(APP_NAME)} — Bağlantı Testi</b>\n\n"
            f"Telegram bildirimleri aktif!\n"
            f"💻 Bilgisayar: {html.escape(socket.gethostname())}\n"
            f"🕐 Zaman: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        result = self.send_message(test_msg, parse_mode="HTML")
        if result:
            log_success("Telegram baglanti testi basarili!")
        else:
            log_error("Telegram baglanti testi basarisiz.")
        return result
