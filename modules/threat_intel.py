import json
import time
import threading
from typing import List, Set
from pathlib import Path

from config import (
    KNOWN_C2_DOMAINS, C2_FEED_URLS,
    C2_FEED_CACHE_FILE, C2_FEED_UPDATE_INTERVAL
)
from modules.utils import log_info, log_success, log_warning, log_error


class ThreatIntelFeed:
    _instance = None
    _singleton_lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return

        self._initialized = True
        self._lock = threading.Lock()
        self._cached_domains: Set[str] = set()
        self._last_update: float = 0.0
        self._auto_update_thread = None
        self._running = False

        # Load existing cache from disk
        cached = self.load_cached_domains()
        if cached:
            self._cached_domains = set(cached)

        # If cache is missing, empty or expired, refresh from remote
        if not self._cached_domains:
            remote = self.fetch_remote_domains()
            if remote:
                self._cached_domains = set(remote)
                self.save_cache(remote)
        elif not self._is_cache_fresh():
            threading.Thread(target=self._background_refresh, daemon=True, name="ThreatFeedInitRefresh").start()

    @staticmethod
    def _parse_feed_lines(text: str) -> List[str]:
        domains = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if "," in line:
                parts = line.split(",")
                for part in parts:
                    part = part.strip().strip('"').lower().strip(".")
                    if part and len(part) > 3 and "." in part and not part[0].isdigit():
                        domains.append(part)
                    elif part and all(c.isdigit() or c == "." for c in part) and part.count(".") == 3:
                        domains.append(part)
                continue
            parts = line.split()
            entry = parts[-1] if len(parts) > 1 else parts[0]
            entry = entry.lower().strip(".")
            if entry and len(entry) > 3 and ("." in entry or entry.replace(".", "").isdigit()):
                domains.append(entry)
        return domains

    def fetch_remote_domains(self) -> List[str]:
        if not C2_FEED_URLS:
            return []

        try:
            import requests
        except ImportError:
            log_error("'requests' modulu bulunamadi. pip install requests")
            return []

        all_domains = []
        for url in C2_FEED_URLS:
            try:
                resp = requests.get(url.strip(), timeout=15)
                resp.raise_for_status()
                parsed = self._parse_feed_lines(resp.text)
                all_domains.extend(parsed)
            except Exception as e:
                log_warning(f"Feed alinamadi ({url[:60]}...): {e}")

        unique = list(set(all_domains))
        if unique:
            log_success(f"{len(C2_FEED_URLS)} kaynaktan toplam {len(unique)} C2 domain alindi.")
        return unique

    def _background_refresh(self):
        try:
            remote = self.fetch_remote_domains()
            if remote:
                with self._lock:
                    self._cached_domains = set(remote)
                    self.save_cache(remote)
        except Exception:
            pass

    def load_cached_domains(self) -> List[str]:
        try:
            cache_path = Path(C2_FEED_CACHE_FILE)
            if not cache_path.exists():
                return []
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._last_update = data.get("timestamp", 0.0)
            return data.get("domains", [])
        except Exception as e:
            log_warning(f"Cache okuma hatasi: {e}")
            return []

    def save_cache(self, domains: List[str]):
        try:
            cache_data = {
                "timestamp": time.time(),
                "sources": C2_FEED_URLS,
                "count": len(domains),
                "domains": domains
            }
            with open(C2_FEED_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            self._last_update = cache_data["timestamp"]
        except Exception as e:
            log_warning(f"Cache yazma hatasi: {e}")

    def _is_cache_fresh(self) -> bool:
        if self._last_update == 0.0:
            self.load_cached_domains()
        return (time.time() - self._last_update) < C2_FEED_UPDATE_INTERVAL

    def get_domains(self, force_refresh: bool = False) -> List[str]:
        with self._lock:
            merged: Set[str] = set(KNOWN_C2_DOMAINS)

            if not force_refresh and self._cached_domains:
                if self._is_cache_fresh():
                    merged.update(self._cached_domains)
                    return list(merged)
                else:
                    merged.update(self._cached_domains)
                    threading.Thread(target=self._background_refresh, daemon=True).start()
                    return list(merged)

            if not force_refresh:
                cached = self.load_cached_domains()
                if cached:
                    self._cached_domains = set(cached)
                    merged.update(cached)
                    if self._is_cache_fresh():
                        return list(merged)

            remote = self.fetch_remote_domains()
            if remote:
                self._cached_domains = set(remote)
                self.save_cache(remote)
                merged.update(remote)

            return list(merged)

    def start_auto_update(self):
        if self._running:
            return
        self._running = True
        self._auto_update_thread = threading.Thread(
            target=self._update_loop, daemon=True,
            name="ThreatIntelAutoUpdate"
        )
        self._auto_update_thread.start()
        log_info("C2 tehdit istihbarati otomatik guncelleme baslatildi.")

    def stop_auto_update(self):
        self._running = False

    def _update_loop(self):
        while self._running:
            try:
                self.get_domains(force_refresh=True)
            except Exception:
                pass
            for _ in range(int(C2_FEED_UPDATE_INTERVAL)):
                if not self._running:
                    break
                time.sleep(1)

    def get_stats(self) -> dict:
        with self._lock:
            if not self._cached_domains:
                cached = self.load_cached_domains()
                if cached:
                    self._cached_domains = set(cached)

            return {
                "builtin_count": len(KNOWN_C2_DOMAINS),
                "remote_count": len(self._cached_domains),
                "total_count": len(set(KNOWN_C2_DOMAINS) | self._cached_domains),
                "last_update": self._last_update,
                "feed_sources": len(C2_FEED_URLS),
                "feed_urls": C2_FEED_URLS or ["(yapilandirilmamis)"],
                "cache_fresh": self._is_cache_fresh()
            }
