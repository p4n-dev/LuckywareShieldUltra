# 🛡️ Luckyware Shield Ultra [v2.0.0]

**Luckyware Shield Ultra**, geliştiricileri ve oyuncuları hedef alan modern zararlı yazılımlara (özellikle *Luckyware*, C2 exfiltration, Visual Studio/SDK zehirlenmeleri, Discord token hırsızlığı ve kalıcılık sağlayan dropper'lar) karşı geliştirilmiş hafif ve etkili bir gerçek zamanlı güvenlik aracıdır.

---

## ✨ Temel Özellikler

- **🌐 Network & C2 Shield (Ağ Kalkanı):**
  - Bilinen zararlı C2 (Command & Control) alan adlarını (örn. `exo-api.tf`, `devruntime.cy`, vb.) yerel `hosts` ve Windows Güvenlik Duvarı (Firewall) üzerinden bloke eder.
  - Aktif ağ bağlantılarını izleyerek şüpheli C2 trafiğini anında tespit eder.

- **🔍 SDK & Proje Tarayıcısı:**
  - Visual Studio, C++ projeleri (`.vcxproj`, `.props`, `.targets`, `.suo`, `.h`, `.cpp`) ve Windows SDK dizinlerinde gizlenen kötü amaçlı kodları ve XOR imzalarını (`NtExploreProcess`, `VccLibraries`, vb.) tespit edip temizler.

- **🛑 Persistence & Dropper Temizliği:**
  - Windows Kayıt Defteri (`Run`, `RunOnce`, `Winlogon`) başlangıç girdilerini denetler ve zararlı persistence kayıtlarını kaldırır.
  - `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%` dizinlerindeki şüpheli dropper ve zararlı ikili dosyaları karantinaya alır.

- **🔒 Token & Oturum Güvenliği:**
  - Discord (Discord, Canary, PTB, Lightcord), Chromium tabanlı tarayıcılar (Chrome, Brave, Edge, Opera) ve Telegram oturum depolarını denetler.
  - Hassas dosyaları salt-okunur (read-only) moduna alarak veri sızdırılmasını engeller.

- **⚡ Real-Time Watchdog (Canlı Kalkan):**
  - Arka planda minimum CPU/RAM kullanımıyla çalışır.
  - Yeni başlatılan süreçleri inceler; bilinen zararlı süreçleri anında sonlandırır ve Windows Bildirim Sistemi (Toast) ile kullanıcıyı uyarır.

---

## 🚀 Kurulum ve Çalıştırma

### 1. Kaynak Koddan Çalıştırma

Gereksinimler: **Python 3.10+**

```bash
# Bağımlılıkları yükleyin
pip install -r requirements.txt

# Yönetici olarak çalıştırın (CLI Menü)
python main.py
```

### 2. Komut Satırı (CLI) Parametreleri

| Parametre | Açıklama |
|---|---|
| `python main.py -a` | Tüm koruma ve temizlik adımlarını tek seferde çalıştırır. |
| `python main.py -s` | C2 alan adlarını Hosts ve Firewall ile engeller. |
| `python main.py -d [klasor]` | Belirtilen klasörü veya standart SDK yollarını tarar. |
| `python main.py -c` | Başlangıç ve Temp dizinindeki kalıcılıkları temizler. |
| `python main.py -w` | Canlı izleme kalkanını konsolda başlatır. |
| `python main.py --daemon` | Arka planda sessiz modda çalışır. |
| `python main.py --install-autostart` | Windows başlangıcına otomatik ekler. |
| `python main.py --status` | Mevcut koruma ve sistem durumunu raporlar. |
| `python main.py --restore-hosts` | Hosts dosyasını orijinal haline döndürür. |

---

## 📁 Proje Mimarisi

```text
LuckywareShieldUltra/
├── config.py                 # C2 listeleri, zararlı imzaları ve global ayarlar
├── daemon.py                 # Arka plan servisi giriş noktası
├── main.py                   # CLI ve interaktif konsol arayüzü
├── requirements.txt          # Python bağımlılıkları
├── modules/
│   ├── live_shield.py        # Gerçek zamanlı süreç izleme ve bildirim
│   ├── network_shield.py     # Hosts ve Firewall C2 engelleme
│   ├── persistence_guard.py  # Kayıt defteri ve başlangıç temizliği
│   ├── sdk_scanner.py        # Proje ve SDK zehirlenmesi tarayıcısı
│   ├── token_guard.py        # Discord ve oturum depolama koruması
│   └── utils.py              # Loglama, renkler, yönetici yetkisi ve karantina
├── quarantine/               # Karantinaya alınan zararlılar
└── logs/                     # Olay ve tespit logları
```

---

## ⚠️ Uyarı ve Lisans

- Hosts dosyasını düzenleme ve Windows Kayıt Defteri temizliği için uygulamanın **Yönetici Olarak (Run as Administrator)** çalıştırılması gerekmektedir.
- Bu yazılım MIT Lisansı altında açık kaynak olarak dağıtılmaktadır.
