import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules.network_shield import NetworkShield
from modules.live_shield import LiveShield, send_windows_notification

def run_daemon():
    net = NetworkShield()
    net.apply_hosts_block()
    net.apply_firewall_rules()

    shield = LiveShield(auto_terminate=True)
    shield.start()

    send_windows_notification(
        "Luckyware Shield Ultra",
        "Arka plan korumasi aktif."
    )

    try:
        while True:
            time.sleep(5)
    except (KeyboardInterrupt, SystemExit):
        shield.stop()

if __name__ == "__main__":
    run_daemon()
