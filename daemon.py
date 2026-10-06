"""
daemon.py — Luckyware Shield Ultra arka plan watchdog servisi.
Bu dosya --daemon argümaniyla ya da Task Scheduler tarafindan cagrilir.
"""
import sys
import time
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules.network_shield import NetworkShield
from modules.live_shield import LiveShield, send_windows_notification
from modules.clipboard_guard import ClipboardGuard
from modules.utils import is_admin, log_info, log_warning, log_success, setup_logger

logger = setup_logger()


def run_daemon():
    log_info("Daemon baslatiliyor...")

    # Hosts + firewall (yalnizca admin ise)
    if is_admin():
        try:
            net = NetworkShield()
            net.apply_hosts_block()
            net.apply_firewall_rules()
            log_success("Hosts kalkani ve guvenlik duvari kurallari uygulandi.")
        except Exception as e:
            log_warning(f"Hosts/firewall uygulama hatasi: {e}")
    else:
        log_warning("Daemon admin yetkisi olmadan calisiyor — hosts/firewall atlandi.")

    # Live shield (proses izleyici)
    shield = LiveShield(auto_terminate=True)
    shield.start()

    # Clipboard guard (kripto hijack koruması)
    clip_guard = ClipboardGuard()
    clip_guard.start()

    # Baslangic bildirimi
    send_windows_notification(
        "Luckyware Shield Ultra",
        "Arka plan korumasi aktif."
    )

    log_success("Daemon tam olarak aktif: LiveShield + ClipboardGuard calisiyor.")

    try:
        while True:
            time.sleep(5)
    except (KeyboardInterrupt, SystemExit):
        shield.stop()
        clip_guard.stop()
        log_info(
            f"Daemon durduruldu. "
            f"Taranan: {shield.stats['processes_scanned']}, "
            f"Engellenen: {shield.stats['threats_blocked']}, "
            f"Clipper: {clip_guard.detection_count}"
        )


if __name__ == "__main__":
    run_daemon()
