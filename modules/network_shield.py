import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any

from config import KNOWN_C2_DOMAINS, HOSTS_FILE_PATH, HOSTS_BACKUP_PATH
from modules.utils import (
    log_info, log_success, log_warning, log_error,
    is_admin
)

BLOCK_TAG_START = "# LUCKYWARE SHIELD BLOCK START"
BLOCK_TAG_END = "# LUCKYWARE SHIELD BLOCK END"


class NetworkShield:
    def __init__(self, c2_domains: List[str] = None):
        if c2_domains:
            self.c2_domains = c2_domains
        else:
            try:
                from modules.threat_intel import ThreatIntelFeed
                self.c2_domains = ThreatIntelFeed().get_domains()
            except Exception:
                self.c2_domains = KNOWN_C2_DOMAINS
        self.hosts_path = Path(HOSTS_FILE_PATH)
        self.hosts_bak_path = Path(HOSTS_BACKUP_PATH)

    def backup_hosts(self) -> bool:
        try:
            if not self.hosts_path.exists():
                return False
            if not self.hosts_bak_path.exists():
                shutil.copy2(self.hosts_path, self.hosts_bak_path)
            return True
        except Exception:
            return False

    def is_hosts_shield_active(self) -> bool:
        try:
            if not self.hosts_path.exists():
                return False
            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                return BLOCK_TAG_START in f.read()
        except Exception:
            return False

    def apply_hosts_block(self) -> bool:
        if not is_admin():
            log_error("Hosts dosyasi icin Administrator yetkisi gereklidir.")
            return False

        try:
            self.backup_hosts()

            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            new_lines = []
            inside_block = False
            for line in lines:
                if BLOCK_TAG_START in line:
                    inside_block = True
                    continue
                if BLOCK_TAG_END in line:
                    inside_block = False
                    continue
                if not inside_block:
                    new_lines.append(line)

            content = "".join(new_lines).rstrip() + "\n\n"

            block_entries = [BLOCK_TAG_START + "\n"]
            for domain in sorted(set(self.c2_domains)):
                block_entries.append(f"0.0.0.0 {domain}\n")
                block_entries.append(f"127.0.0.1 {domain}\n")
                block_entries.append(f"0.0.0.0 www.{domain}\n")
                block_entries.append(f"127.0.0.1 www.{domain}\n")
            block_entries.append(BLOCK_TAG_END + "\n")

            full_content = content + "".join(block_entries)
            with open(self.hosts_path, "w", encoding="utf-8") as f:
                f.write(full_content)

            log_success(f"{len(self.c2_domains)} adet C2 adresi engellendi.")
            self.flush_dns()
            return True
        except Exception as e:
            log_error(f"Hosts engelleme hatasi: {e}")
            return False

    def restore_hosts(self) -> bool:
        if not is_admin():
            log_error("Hosts dosyasi icin Administrator yetkisi gereklidir.")
            return False

        try:
            if not self.hosts_path.exists():
                return False

            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            cleaned_lines = []
            inside_block = False
            for line in lines:
                if BLOCK_TAG_START in line:
                    inside_block = True
                    continue
                if BLOCK_TAG_END in line:
                    inside_block = False
                    continue
                if not inside_block:
                    cleaned_lines.append(line)

            with open(self.hosts_path, "w", encoding="utf-8") as f:
                f.writelines(cleaned_lines)

            log_success("Hosts dosyasi sifirlandi.")
            self.flush_dns()
            return True
        except Exception as e:
            log_error(f"Hosts geri yukleme hatasi: {e}")
            return False

    def flush_dns(self):
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, shell=True)
        except Exception:
            pass

    def apply_firewall_rules(self) -> bool:
        if not is_admin():
            return False

        rule_name = "Luckyware_Shield_Block"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True, shell=True
            )

            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                "protocol=TCP",
                "remoteport=1337,4444,5555,8080,8888,9999",
                "description=Luckyware C2 Block"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            return res.returncode == 0
        except Exception:
            return False

    def scan_active_connections(self) -> List[Dict[str, Any]]:
        suspicious = []
        try:
            import psutil
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr:
                    ip, port = conn.raddr.ip, conn.raddr.port
                    if port in [1337, 4444, 5555, 8888, 9999]:
                        try:
                            proc = psutil.Process(conn.pid)
                            pname = proc.name()
                        except Exception:
                            pname = "Bilinmiyor"
                        suspicious.append({
                            "pid": conn.pid,
                            "process": pname,
                            "remote_ip": ip,
                            "remote_port": port
                        })
        except Exception:
            pass
        return suspicious
