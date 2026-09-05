import sys
import os
import argparse
import time
import json
import winreg
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import APP_NAME, APP_VERSION, QUARANTINE_DIR
from modules.utils import (
    Colors, is_admin, require_admin_prompt,
    log_info, log_success, log_warning, log_error, log_header
)
from modules.network_shield import NetworkShield
from modules.sdk_scanner import SDKProjectScanner
from modules.persistence_guard import PersistenceGuard
from modules.token_guard import TokenGuard
from modules.live_shield import LiveShield, send_windows_notification
from modules.telegram_notifier import TelegramNotifier
from modules.threat_intel import ThreatIntelFeed
from modules.webhook_hunter import WebhookHunter
from modules.clipboard_guard import ClipboardGuard
from modules.injection_detector import InjectionDetector
from modules.report_generator import ReportGenerator

def print_banner():
    print(f"\n{Colors.CYAN}{APP_NAME} [v{APP_VERSION}]{Colors.ENDC}\n")
    require_admin_prompt()

def run_full_protection():
    log_header("Tam Sistem Korumasi Baslatiliyor")

    net = NetworkShield()
    log_info("1/7: C2 Alan Adlari ve Ag Kalkani uygulanıyor...")
    net.apply_hosts_block()
    net.apply_firewall_rules()

    persist = PersistenceGuard()
    log_info("2/7: Kayit Defteri ve Baslangic Girdileri temizleniyor...")
    p_stats = persist.clean_all_persistence()
    log_success(f"Kayit Defteri: {p_stats['registry_cleaned']}, Baslangic: {p_stats['startup_quarantined']}, Temp: {p_stats['temp_quarantined']}")

    scanner = SDKProjectScanner()
    log_info("3/7: SDK ve Visual Studio dosyalari taraniyor...")
    sdk_findings = scanner.run_full_sdk_scan()
    if sdk_findings:
        log_warning(f"{len(sdk_findings)} supheli dosya bulundu.")
        for f in sdk_findings:
            log_warning(f"-> {f['file_path']} [{f['severity']}]")
            scanner.clean_infected_file(f["file_path"])
    else:
        log_success("SDK ve Visual Studio dosyalari temiz.")

    token_guard = TokenGuard()
    log_info("4/7: Discord ve Oturum depolari denetleniyor...")
    audit = token_guard.audit_sensitive_stores()
    for cat, items in audit.items():
        found = sum(1 for i in items if i["exists"])
        log_info(f"{cat}: {found} aktif depo mevcut.")

    log_info("5/7: Ag baglantilari kontrol ediliyor...")
    active_conns = net.scan_active_connections()
    if active_conns:
        log_warning(f"{len(active_conns)} supheli baglanti tespit edildi.")
    else:
        log_success("Aktif C2 baglantisi yok.")

    hunter = WebhookHunter()
    log_info("6/7: Discord webhook taramasi yapiliyor...")
    wh_results = hunter.run_full_scan()
    if wh_results:
        log_warning(f"{len(wh_results)} dosyada webhook bulundu!")
    else:
        log_success("Discord webhook bulunamadi.")

    detector = InjectionDetector()
    log_info("7/7: Surec enjeksiyon taramasi yapiliyor...")
    inj_results = detector.scan_processes()
    if inj_results:
        log_warning(f"{len(inj_results)} supheli surec tespit edildi.")
    else:
        log_success("Surec enjeksiyonu bulunamadi.")

    log_success("Tam koruma tamamlandi.\n")

def menu_sdk_scan():
    log_header("SDK ve Proje Dosyasi Taramasi")
    scanner = SDKProjectScanner()
    print("1. Standart SDK Dizinlerini Tara")
    print("2. Ozel Klasor Tara")
    choice = input("\nSeciminiz (1/2): ").strip()

    if choice == "2":
        target_dir = input("Klasor yolu: ").strip().strip('"')
        if not os.path.exists(target_dir):
            log_error("Gecersiz yol.")
            return
        findings = scanner.scan_path(target_dir)
    else:
        findings = scanner.run_full_sdk_scan()

    if findings:
        log_warning(f"{len(findings)} supheli dosya bulundu:")
        for idx, item in enumerate(findings, 1):
            print(f"[{idx}] {item['file_path']} ({item['severity']})")

        clean_all = input("\nTemizlensin mi? (e/h): ").strip().lower()
        if clean_all in ["e", "evet", "y", "yes"]:
            for f in findings:
                scanner.clean_infected_file(f["file_path"])
    else:
        log_success("Tehdit bulunamadi.")

def menu_persistence():
    log_header("Baslangic ve Kayit Defteri Temizligi")
    guard = PersistenceGuard()

    reg_items = guard.scan_registry_startup()
    suspicious_reg = [r for r in reg_items if r["is_suspicious"]]

    if suspicious_reg:
        log_warning(f"{len(suspicious_reg)} supheli baslangic kaydi bulundu.")
        for r in suspicious_reg:
            print(f"  [{r['hive']}] {r['value_name']} -> {r['value_data']}")
    else:
        log_success("Kayit defteri baslangic girdileri temiz.")

    droppers = guard.scan_temp_droppers()
    if droppers:
        log_warning(f"{len(droppers)} olasi dropper bulundu.")
        for d in droppers:
            print(f"  {d['name']} -> {d['reason']}")
    else:
        log_success("Temp dizininde dropper bulunamadi.")

    if suspicious_reg or droppers:
        action = input("\nTemizlensin mi? (e/h): ").strip().lower()
        if action in ["e", "evet", "y", "yes"]:
            res = guard.clean_all_persistence()
            log_success(f"Sonuc: {res}")

def menu_live_watchdog(silent: bool = False):
    if not silent:
        log_header("Canli Kalkan (Real-Time Watchdog)")
        print("Canli kalkan calisiyor. Cikmak icin CTRL+C basin.\n")

    net = NetworkShield()
    net.apply_hosts_block()
    net.apply_firewall_rules()

    shield = LiveShield(auto_terminate=True)
    shield.start()

    clip_guard = ClipboardGuard()
    clip_guard.start()

    send_windows_notification("Luckyware Shield Ultra", "Arka plan korumasi aktif.")

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        shield.stop()
        clip_guard.stop()
        if not silent:
            log_info(f"Durduruldu. Taranan: {shield.stats['processes_scanned']}, Engellenen: {shield.stats['threats_blocked']}")
            if clip_guard.detection_count:
                log_warning(f"Clipper tespiti: {clip_guard.detection_count}")

def toggle_autostart(enable: bool = True):
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "LuckywareShieldUltra"

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            if enable:
                cmd = f'"{sys.executable}" --daemon' if getattr(sys, 'frozen', False) else f'"{sys.executable}" "{Path(__file__).resolve()}" --daemon'
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, cmd)
                log_success("Otomatik baslatma aktif edildi.")
            else:
                try:
                    winreg.DeleteValue(key, value_name)
                    log_success("Otomatik baslatma kaldirildi.")
                except FileNotFoundError:
                    log_info("Zaten kayitli degil.")
    except Exception as e:
        log_error(f"Hata: {e}")

def display_status():
    log_header("Sistem Durumu")
    net = NetworkShield()
    is_hosts_ok = net.is_hosts_shield_active()

    status_hosts = f"{Colors.GREEN}Aktif{Colors.ENDC}" if is_hosts_ok else f"{Colors.WARNING}Devre Disi{Colors.ENDC}"
    admin_status = f"{Colors.GREEN}Var{Colors.ENDC}" if is_admin() else f"{Colors.WARNING}Yok{Colors.ENDC}"

    print(f"  Yonetici Yetkisi : {admin_status}")
    print(f"  Hosts Kalkani    : {status_hosts}")

    feed = ThreatIntelFeed()
    fstats = feed.get_stats()
    feed_status = f"{Colors.GREEN}{fstats['total_count']} Domain ({fstats['feed_sources']} Kaynak){Colors.ENDC}"
    print(f"  Tehdit Feed      : {feed_status}")

    tg_notifier = TelegramNotifier()
    tg_status = f"{Colors.GREEN}Yapilandirildi{Colors.ENDC}" if tg_notifier.is_configured else f"{Colors.WARNING}Devre Disi{Colors.ENDC}"
    print(f"  Telegram Bot     : {tg_status}")
    
    guard = PersistenceGuard()
    droppers = guard.scan_temp_droppers()
    temp_status = f"{Colors.FAIL}Supheli Dosyalar ({len(droppers)}){Colors.ENDC}" if droppers else f"{Colors.GREEN}Temiz{Colors.ENDC}"
    print(f"  Temp Durumu      : {temp_status}")

    tg = TokenGuard()
    audit = tg.audit_sensitive_stores()
    disc_count = sum(1 for item in audit.get("Discord", []) if item["exists"])
    print(f"  Discord Depolari : {disc_count} adet\n")

def menu_telegram_test():
    log_header("Telegram Bildirim Testi")
    notifier = TelegramNotifier()
    if not notifier.is_configured:
        log_warning("Telegram yapilandirilmamis.")
        log_info("Lutfen .env dosyasina TELEGRAM_BOT_TOKEN ve TELEGRAM_CHAT_ID degerlerini girin.")
        log_info("Ornek .env dosyasi: .env.example")
        return
    log_info("Telegram test bildirimi gonderiliyor...")
    notifier.test_connection()

def menu_update_c2_feed():
    log_header("C2 Tehdit Istihbarati Guncelleme")
    feed = ThreatIntelFeed()
    stats_before = feed.get_stats()
    log_info(f"Mevcut: {stats_before['builtin_count']} dahili, {stats_before['remote_count']} uzak domain")
    log_info(f"Aktif Kaynak Sayisi: {stats_before['feed_sources']}")

    log_info("Kaynaklardan guncelleniyor...")
    feed.get_domains(force_refresh=True)
    stats_after = feed.get_stats()
    log_success(f"Guncellendi: Toplam {stats_after['total_count']} C2 domain ({stats_after['remote_count']} uzak kaynak)")

def menu_webhook_hunter():
    log_header("Discord Webhook Avcisi")
    hunter = WebhookHunter()
    log_info("Dosya sistemi taraniyor...")
    results = hunter.run_full_scan()
    summary = hunter.get_summary()

    if not results:
        log_success("Discord webhook bulunamadi. Sistem temiz.")
        return

    log_warning(f"{summary['total_webhooks']} webhook bulundu ({summary['files_with_webhooks']} dosya):")
    all_webhooks = []
    for finding in results:
        print(f"\n  {Colors.FAIL}{finding['file_path']}{Colors.ENDC}")
        for wh in finding["webhooks"]:
            print(f"    -> {wh[:70]}...")
            all_webhooks.append(wh)

    print(f"\n1. Webhook'lari Discord'dan sil (devre disi birak)")
    print("2. Sadece raporla")
    choice = input("\nSeciminiz (1/2): ").strip()

    if choice == "1":
        for wh in set(all_webhooks):
            hunter.delete_webhook(wh)
        log_success("Islem tamamlandi.")

def menu_clipboard_guard():
    log_header("Clipboard Guard (Clipper Tespiti)")
    print("Pano izleme baslatiliyor. Kripto cuzdan adresi kopyalayin ve degistirilip")
    print("degistirilmedigini izleyin. Cikmak icin CTRL+C basin.\n")

    guard = ClipboardGuard()
    guard.start()

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        guard.stop()
        stats = guard.get_stats()
        log_info(f"Durduruldu. Tespit sayisi: {stats['detections']}")

def menu_injection_detector():
    log_header("Surec Enjeksiyon Tespiti")
    detector = InjectionDetector()
    log_info("Calisan surecler analiz ediliyor...")
    results = detector.scan_processes()
    summary = detector.get_summary()

    if not results:
        log_success("Supheli surec enjeksiyonu bulunamadi.")
        return

    log_warning(f"{summary['total_suspicious']} supheli surec tespit edildi:")
    log_warning(f"  Yuksek: {summary['high_severity']}, Orta: {summary['medium_severity']}")

    for finding in results:
        sev_color = Colors.FAIL if finding["severity"] == "HIGH" else Colors.WARNING
        print(f"\n  {sev_color}[{finding['severity']}]{Colors.ENDC} {finding['name']} (PID: {finding['pid']})")
        print(f"    Yol: {finding['exe']}")
        for issue in finding["issues"]:
            print(f"    -> {issue}")

def menu_generate_report():
    log_header("Guvenlik Raporu Olusturuluyor")
    report = ReportGenerator()

    # Hosts durumu
    net = NetworkShield()
    hosts_ok = net.is_hosts_shield_active()
    report.add_section(
        "Ag Kalkani",
        "ok" if hosts_ok else "warning",
        [
            {"label": "Hosts Dosyasi", "value": "Aktif" if hosts_ok else "Devre Disi"},
            {"label": "Admin Yetkisi", "value": "Var" if is_admin() else "Yok"},
        ],
        deduction=0 if hosts_ok else 10
    )

    # C2 feed durumu
    feed = ThreatIntelFeed()
    fstats = feed.get_stats()
    report.add_section(
        "C2 Tehdit Istihbarati",
        "ok" if fstats["total_count"] > 0 else "warning",
        [
            {"label": "Toplam Domain", "value": str(fstats["total_count"])},
            {"label": "Kaynak Sayisi", "value": str(fstats["feed_sources"])},
            {"label": "Cache Guncel", "value": "Evet" if fstats["cache_fresh"] else "Hayir"},
        ]
    )

    # Telegram durumu
    tg = TelegramNotifier()
    report.add_section(
        "Telegram Bildirimleri",
        "ok" if tg.is_configured else "info",
        [{"label": "Durum", "value": "Yapilandirildi" if tg.is_configured else "Yapilandirilmamis"}],
        deduction=0 if tg.is_configured else 5
    )

    # Temp dropper taramasi
    guard = PersistenceGuard()
    droppers = guard.scan_temp_droppers()
    dropper_items = [{"label": d["name"], "value": d["reason"], "severity": "HIGH"} for d in droppers]
    if not dropper_items:
        dropper_items = [{"label": "Temp Dizini", "value": "Temiz"}]
    report.add_section(
        "Temp Dropper Taramasi",
        "danger" if droppers else "ok",
        dropper_items,
        deduction=len(droppers) * 15
    )

    # Webhook taramasi
    log_info("Webhook taramasi yapiliyor...")
    hunter = WebhookHunter()
    wh_results = hunter.run_full_scan()
    wh_items = []
    for r in wh_results:
        for wh in r["webhooks"]:
            wh_items.append({"label": Path(r["file_path"]).name, "value": wh[:60] + "...", "severity": "HIGH"})
    if not wh_items:
        wh_items = [{"label": "Discord Webhook", "value": "Bulunamadi"}]
    report.add_section(
        "Discord Webhook Taramasi",
        "danger" if wh_results else "ok",
        wh_items,
        deduction=len(wh_results) * 20
    )

    # Injection taramasi
    log_info("Surec enjeksiyon taramasi yapiliyor...")
    detector = InjectionDetector()
    inj_results = detector.scan_processes()
    inj_items = []
    for r in inj_results:
        inj_items.append({
            "label": f"{r['name']} (PID: {r['pid']})",
            "value": ", ".join(r["issues"]),
            "severity": r["severity"]
        })
    if not inj_items:
        inj_items = [{"label": "Surec Enjeksiyonu", "value": "Bulunamadi"}]
    report.add_section(
        "Surec Enjeksiyon Taramasi",
        "danger" if inj_results else "ok",
        inj_items,
        deduction=sum(15 if r["severity"] == "HIGH" else 5 for r in inj_results)
    )

    # Discord depolari
    tguard = TokenGuard()
    audit = tguard.audit_sensitive_stores()
    disc_items = []
    for cat, items in audit.items():
        for item in items:
            if item["exists"]:
                disc_items.append({"label": cat, "value": f"{item['path']} ({item['file_count']} dosya)"})
    if not disc_items:
        disc_items = [{"label": "Hassas Depo", "value": "Bulunamadi"}]
    report.add_section(
        "Discord ve Oturum Depolari",
        "info",
        disc_items
    )

    filepath = report.save_report()
    log_success(f"Rapor olusturuldu: {filepath}")
    log_info("Raporu tarayicinizda acabilirsiniz.")

    try:
        os.startfile(filepath)
    except Exception:
        pass

def menu_quarantine_manager():
    log_header("Karantina Yonetimi")
    manifest_file = QUARANTINE_DIR / "quarantine_manifest.json"

    if not manifest_file.exists():
        log_info("Karantina dosyasi bulunamadi.")
        return

    try:
        with open(manifest_file, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except Exception as e:
        log_error(f"Manifest okuma hatasi: {e}")
        return

    if not entries:
        log_info("Karantinada dosya yok.")
        return

    print(f"\n  {Colors.BOLD}Karantinadaki Dosyalar ({len(entries)} adet):{Colors.ENDC}\n")
    for idx, entry in enumerate(entries, 1):
        name = Path(entry["original_path"]).name
        ts = entry.get("timestamp", "?")
        reason = entry.get("reason", "Bilinmiyor")
        print(f"  [{idx}] {name}")
        print(f"      Tarih: {ts} | Sebep: {reason}")
        print(f"      Orijinal: {entry['original_path']}")

    print(f"\n1. Dosya geri yukle (restore)")
    print("2. Tum karantina dosyalarini kalici sil (purge)")
    print("3. Geri don")
    choice = input("\nSeciminiz (1/2/3): ").strip()

    if choice == "1":
        idx_str = input("Geri yuklenecek dosya numarasi: ").strip()
        try:
            idx = int(idx_str) - 1
            if 0 <= idx < len(entries):
                entry = entries[idx]
                q_path = Path(entry["quarantined_as"])
                orig_path = Path(entry["original_path"])

                if q_path.exists():
                    try:
                        os.chmod(q_path, 0o666)
                    except Exception:
                        pass
                    import shutil
                    shutil.copy2(q_path, orig_path)
                    q_path.unlink(missing_ok=True)
                    entries.pop(idx)
                    with open(manifest_file, "w", encoding="utf-8") as f:
                        json.dump(entries, f, indent=2, ensure_ascii=False)
                    log_success(f"Geri yuklendi: {orig_path.name}")
                else:
                    log_error("Karantina dosyasi bulunamadi.")
            else:
                log_error("Gecersiz numara.")
        except ValueError:
            log_error("Gecersiz giris.")

    elif choice == "2":
        confirm = input("Tum karantina dosyalari silinecek. Emin misiniz? (e/h): ").strip().lower()
        if confirm in ["e", "evet", "y", "yes"]:
            deleted = 0
            for entry in entries:
                q_path = Path(entry["quarantined_as"])
                if q_path.exists():
                    try:
                        os.chmod(q_path, 0o666)
                        q_path.unlink()
                        deleted += 1
                    except Exception:
                        pass
            with open(manifest_file, "w", encoding="utf-8") as f:
                json.dump([], f)
            log_success(f"{deleted} dosya kalici olarak silindi.")

def interactive_menu():
    while True:
        print_banner()
        print(f"  {Colors.BOLD}--- Koruma ---{Colors.ENDC}")
        print("  [1] Tam Koruma ve C2 Bloklama")
        print("  [2] Canli Kalkan (Real-Time Watchdog)")
        print(f"\n  {Colors.BOLD}--- Tarama ---{Colors.ENDC}")
        print("  [3] SDK ve Proje Dosyasi Taramasi")
        print("  [4] Baslangic ve Temp Dropper Temizligi")
        print("  [5] Discord ve Oturum Deposu Denetimi")
        print("  [6] Webhook Avcisi (Discord Grabber Tespiti)")
        print("  [7] Injection Detector (Surec Enjeksiyon)")
        print("  [8] Clipboard Guard (Clipper Tespiti)")
        print(f"\n  {Colors.BOLD}--- Araclar ---{Colors.ENDC}")
        print("  [9] Guvenlik Raporu (HTML)")
        print("  [10] Sistem Durumu")
        print("  [11] C2 Listesini Guncelle (GitHub)")
        print("  [12] Telegram Bildirim Testi")
        print("  [13] Karantina Yonetimi")
        print("  [14] Windows Baslangicina Ekle/Kaldir")
        print("  [15] Hosts Dosyasini Sifirla")
        print(f"\n  [0] Cikis")

        choice = input(f"\n  Seciminiz [0-15]: ").strip()

        if choice == "1":
            run_full_protection()
        elif choice == "2":
            menu_live_watchdog()
        elif choice == "3":
            menu_sdk_scan()
        elif choice == "4":
            menu_persistence()
        elif choice == "5":
            log_header("Discord ve Oturum Guvenligi")
            tg = TokenGuard()
            audit = tg.audit_sensitive_stores()
            for cat, items in audit.items():
                print(f"{cat}:")
                for i in items:
                    st = f"Mevcut ({i['file_count']} dosya)" if i["exists"] else "Yok"
                    print(f"  - {i['path']}: {st}")
            
            sub_c = input("\nDiscord dosyalari salt-okunur yapilsin mi? (e/h): ").strip().lower()
            if sub_c in ["e", "evet", "y", "yes"]:
                tg.lock_discord_storage()
        elif choice == "6":
            menu_webhook_hunter()
        elif choice == "7":
            menu_injection_detector()
        elif choice == "8":
            menu_clipboard_guard()
        elif choice == "9":
            menu_generate_report()
        elif choice == "10":
            display_status()
        elif choice == "11":
            menu_update_c2_feed()
        elif choice == "12":
            menu_telegram_test()
        elif choice == "13":
            menu_quarantine_manager()
        elif choice == "14":
            print("1. Baslangica Ekle")
            print("2. Baslangictan Kaldir")
            sub = input("Seciminiz (1/2): ").strip()
            if sub == "1":
                toggle_autostart(enable=True)
            elif sub == "2":
                toggle_autostart(enable=False)
        elif choice == "15":
            log_header("Hosts Sifirlama")
            net = NetworkShield()
            net.restore_hosts()
        elif choice == "0":
            break
        else:
            log_error("Gecersiz secim.")

        input("\nDevam etmek icin Enter'a basin...")

def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("-a", "--all", action="store_true", help="Tum koruma adimlarini uygula.")
    parser.add_argument("-s", "--shield", action="store_true", help="C2 alan adlarini engelle.")
    parser.add_argument("-d", "--scan-sdk", type=str, nargs="?", const="default", help="SDK veya klasoru tara.")
    parser.add_argument("-c", "--clean-persist", action="store_true", help="Baslangic ve temp temizle.")
    parser.add_argument("-w", "--live-watch", action="store_true", help="Canli kalkani baslat.")
    parser.add_argument("--daemon", action="store_true", help="Arka planda sessizce calis.")
    parser.add_argument("--install-autostart", action="store_true", help="Windows baslangicina ekle.")
    parser.add_argument("--uninstall-autostart", action="store_true", help="Windows baslangicindan kaldir.")
    parser.add_argument("--status", action="store_true", help="Durumu goster.")
    parser.add_argument("--restore-hosts", action="store_true", help="Hosts dosyasini sifirla.")
    parser.add_argument("--test-telegram", action="store_true", help="Telegram baglantisini test et.")
    parser.add_argument("--update-feed", action="store_true", help="C2 tehdit istihbarat listesini guncelle.")
    parser.add_argument("--scan-webhooks", action="store_true", help="Discord webhook taramasi yap.")
    parser.add_argument("--scan-injection", action="store_true", help="Surec enjeksiyon taramasi yap.")
    parser.add_argument("--report", action="store_true", help="HTML guvenlik raporu olustur.")

    args = parser.parse_args()

    if args.daemon:
        menu_live_watchdog(silent=True)
    elif args.all:
        print_banner()
        run_full_protection()
    elif args.shield:
        print_banner()
        net = NetworkShield()
        net.apply_hosts_block()
        net.apply_firewall_rules()
    elif args.scan_sdk:
        print_banner()
        scanner = SDKProjectScanner()
        if args.scan_sdk == "default":
            scanner.run_full_sdk_scan()
        else:
            scanner.scan_path(args.scan_sdk)
    elif args.clean_persist:
        print_banner()
        guard = PersistenceGuard()
        guard.clean_all_persistence()
    elif args.live_watch:
        print_banner()
        menu_live_watchdog()
    elif args.install_autostart:
        toggle_autostart(enable=True)
    elif args.uninstall_autostart:
        toggle_autostart(enable=False)
    elif args.status:
        display_status()
    elif args.restore_hosts:
        net = NetworkShield()
        net.restore_hosts()
    elif args.test_telegram:
        menu_telegram_test()
    elif args.update_feed:
        menu_update_c2_feed()
    elif args.scan_webhooks:
        menu_webhook_hunter()
    elif args.scan_injection:
        menu_injection_detector()
    elif args.report:
        menu_generate_report()
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
