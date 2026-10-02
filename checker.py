#!/usr/bin/env python3

import base64
import json
import os
import socket
import subprocess
import sys
import time
import concurrent.futures
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, unquote, urlencode, quote

import requests

# ──────────────────────────────────────────────────────────────────────────
# КОНФИГУРАЦИЯ
# ──────────────────────────────────────────────────────────────────────────

SUBSCRIPTIONS = [
    s.strip() for s in os.environ.get("SUBSCRIPTIONS", "").split(",") if s.strip()
] or [
    "https://example.com/sub1",
    "https://example.com/sub2",
]

TEST_URLS = [
    u.strip() for u in os.environ.get("TEST_URLS", "").split(",") if u.strip()
] or [
    "https://www.gstatic.com/generate_204",
]

REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", 6))
XRAY_STARTUP_DELAY = float(os.environ.get("XRAY_STARTUP_DELAY", 1.0))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 8))
XRAY_BIN = os.environ.get("XRAY_BIN", "xray")

MAX_PROXIES = int(os.environ.get("MAX_PROXIES", 200))       # сколько прокси оставлять в итоговой подписке
TOP_N_PROXIES = int(os.environ.get("TOP_N_PROXIES", 10))    # сколько лучших класть во вторую подписку
NAME_SUFFIX = os.environ.get("NAME_SUFFIX", "@KnetaEx")     # хвост названия прокси


SUB_PROFILE_TITLE_MAIN = os.environ.get("SUB_PROFILE_TITLE_MAIN", "Kneta WL | Основная подписка")
SUB_PROFILE_TITLE_TOP = os.environ.get("SUB_PROFILE_TITLE_TOP", "Kneta WL | Топ-10")
SUB_UPDATE_INTERVAL = os.environ.get("SUB_UPDATE_INTERVAL", "4")
SUB_SUPPORT_URL = os.environ.get("SUB_SUPPORT_URL", "https://t.me/KnetaEx")
SUB_ANNOUNCE = os.environ.get("SUB_ANNOUNCE", "Если не работает, то нажмите 🔄, а затем 🕒")
GEO_LOOKUP_WORKERS = int(os.environ.get("GEO_LOOKUP_WORKERS", 5))
GEO_TIMEOUT = float(os.environ.get("GEO_TIMEOUT", 5))


STABILITY_WINDOW = int(os.environ.get("STABILITY_WINDOW", 3))
STABILITY_PENALTY_PER_STEP = float(os.environ.get("STABILITY_PENALTY_PER_STEP", 0.5))

OUTPUT_DIR = "proxies"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "working.txt")
TOP_FILE = os.path.join(OUTPUT_DIR, "top10.txt")
HISTORY_FILE = os.path.join(OUTPUT_DIR, "history.json")
TMP_DIR = "tmp_configs"

# ──────────────────────────────────────────────────────────────────────────
# НАЗВАНИЯ СТРАН
# ──────────────────────────────────────────────────────────────────────────

COUNTRY_NAMES_RU = {
    "RU": "Россия", "US": "США", "DE": "Германия", "NL": "Нидерланды",
    "FR": "Франция", "GB": "Великобритания", "FI": "Финляндия", "JP": "Япония",
    "SG": "Сингапур", "KR": "Южная Корея", "CA": "Канада", "TR": "Турция",
    "PL": "Польша", "UA": "Украина", "CH": "Швейцария", "SE": "Швеция",
    "ES": "Испания", "IT": "Италия", "HK": "Гонконг", "IN": "Индия",
    "AE": "ОАЭ", "KZ": "Казахстан", "AM": "Армения", "GE": "Грузия",
    "LT": "Литва", "LV": "Латвия", "EE": "Эстония", "CZ": "Чехия",
    "AT": "Австрия", "BE": "Бельгия", "PT": "Португалия", "GR": "Греция",
    "RO": "Румыния", "BG": "Болгария", "HU": "Венгрия", "IE": "Ирландия",
    "DK": "Дания", "NO": "Норвегия", "IS": "Исландия", "LU": "Люксембург",
    "MD": "Молдова", "AZ": "Азербайджан", "UZ": "Узбекистан", "KG": "Киргизия",
    "BR": "Бразилия", "AU": "Австралия", "NZ": "Новая Зеландия", "ZA": "ЮАР",
    "CN": "Китай", "TW": "Тайвань", "TH": "Таиланд", "VN": "Вьетнам",
    "ID": "Индонезия", "MY": "Малайзия", "PH": "Филиппины", "IL": "Израиль",
    "SA": "Саудовская Аравия", "EG": "Египет", "MX": "Мексика", "AR": "Аргентина",
    "CL": "Чили", "CY": "Кипр", "MT": "Мальта", "SK": "Словакия",
    "SI": "Словения", "HR": "Хорватия", "RS": "Сербия", "AL": "Албания",
    "BA": "Босния и Герцеговина", "MK": "Северная Македония", "ME": "Черногория",
}


def country_flag(iso_code: str) -> str:
    """ISO alpha-2 код страны -> эмодзи-флаг."""
    if not iso_code or len(iso_code) != 2 or not iso_code.isalpha():
        return "🏳️"
    code = iso_code.upper()
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def country_name_ru(iso_code: str, fallback_en: str = "") -> str:
    return COUNTRY_NAMES_RU.get(iso_code.upper(), fallback_en or iso_code or "Неизвестно")


_geo_cache: dict[str, tuple[str, str]] = {}


def lookup_country(host: str) -> tuple[str, str]:
    """Определяет страну по хосту/IP через бесплатный ipwho.is (без ключа)."""
    if host in _geo_cache:
        return _geo_cache[host]
    try:
        r = requests.get(f"https://ipwho.is/{host}", timeout=GEO_TIMEOUT)
        data = r.json()
        if data.get("success", True):
            iso = data.get("country_code", "")
            name_en = data.get("country", "")
            _geo_cache[host] = (iso, name_en)
            return iso, name_en
    except Exception:
        pass
    _geo_cache[host] = ("", "")
    return "", ""


# ──────────────────────────────────────────────────────────────────────────
# ПАРСИНГ / СБОРКА VLESS-ССЫЛОК
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class VlessProxy:
    uuid: str
    host: str
    port: int
    query: dict = field(default_factory=dict)
    name: str = ""

    @property
    def network(self) -> str:
        return self.query.get("type", "tcp")

    @property
    def security(self) -> str:
        return self.query.get("security", "none")

    @property
    def sni(self) -> str:
        return self.query.get("sni", self.query.get("host", ""))

    @property
    def flow(self) -> str:
        return self.query.get("flow", "")

    @property
    def path(self) -> str:
        return self.query.get("path", "/")

    @property
    def host_header(self) -> str:
        return self.query.get("host", "")

    @property
    def fp(self) -> str:
        return self.query.get("fp", "")

    @property
    def pbk(self) -> str:
        return self.query.get("pbk", "")

    @property
    def sid(self) -> str:
        return self.query.get("sid", "")

    def identity(self) -> tuple:
        """Ключ дедупликации — по параметрам подключения, без учёта имени."""
        return (self.uuid, self.host, self.port, self.network, self.security,
                self.sni, self.path, self.host_header)

    def identity_str(self) -> str:
        """Та же identity, но строкой — для использования как ключ в JSON (history)."""
        return "|".join(str(x) for x in self.identity())

    def to_link(self, name: str | None = None) -> str:
        qs = urlencode(self.query, safe=":/")
        frag = quote(name if name is not None else self.name)
        return f"vless://{self.uuid}@{self.host}:{self.port}?{qs}#{frag}"


def parse_vless(link: str) -> "VlessProxy | None":
    try:
        u = urlparse(link)
        if u.scheme != "vless" or not u.username or not u.hostname or not u.port:
            return None
        params = parse_qs(u.query)
        query = {k: v[0] for k, v in params.items()}
        return VlessProxy(
            uuid=u.username,
            host=u.hostname,
            port=u.port,
            query=query,
            name=unquote(u.fragment) if u.fragment else u.hostname,
        )
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────
# СБОРКА ИСТОЧНИКОВ
# ──────────────────────────────────────────────────────────────────────────

def decode_subscription_text(raw: str) -> list[str]:
    raw = raw.strip()
    decoded = raw
    if not raw.startswith("vless://"):
        try:
            padded = raw + "=" * (-len(raw) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception:
            decoded = raw
    return [line.strip() for line in decoded.splitlines() if line.strip().startswith("vless://")]


def fetch_subscription(url: str) -> list[str]:
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        links = decode_subscription_text(r.text)
    except requests.RequestException as e:
        print(f"[!] Не удалось скачать подписку {url}: {e}", file=sys.stderr)
        return []
    print(f"[+] {url}: найдено {len(links)} ссылок")
    return links


def load_own_previous_subscription() -> list[str]:
    if not os.path.exists(OUTPUT_FILE):
        return []
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            raw = f.read()
        links = decode_subscription_text(raw)
        print(f"[+] Собственная предыдущая подписка: найдено {len(links)} ссылок")
        return links
    except Exception as e:
        print(f"[!] Не удалось прочитать {OUTPUT_FILE}: {e}", file=sys.stderr)
        return []


def collect_all_proxies() -> list[VlessProxy]:
    all_links: list[str] = []
    for sub_url in SUBSCRIPTIONS:
        all_links.extend(fetch_subscription(sub_url))
    all_links.extend(load_own_previous_subscription())

    seen = set()
    proxies: list[VlessProxy] = []
    for link in all_links:
        vp = parse_vless(link)
        if not vp:
            continue
        key = vp.identity()
        if key in seen:
            continue
        seen.add(key)
        proxies.append(vp)

    print(f"[+] Всего уникальных валидных vless-прокси для проверки: {len(proxies)}")
    return proxies


# ──────────────────────────────────────────────────────────────────────────
# ГЕНЕРАЦИЯ XRAY-КОНФИГА
# ──────────────────────────────────────────────────────────────────────────

def find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def build_xray_config(vp: VlessProxy, local_port: int) -> dict:
    stream_settings = {"network": vp.network, "security": vp.security}

    if vp.security == "tls":
        stream_settings["tlsSettings"] = {
            "serverName": vp.sni or vp.host,
            "fingerprint": vp.fp or "chrome",
            "allowInsecure": False,
        }
    elif vp.security == "reality":
        stream_settings["realitySettings"] = {
            "serverName": vp.sni or vp.host,
            "fingerprint": vp.fp or "chrome",
            "publicKey": vp.pbk,
            "shortId": vp.sid,
        }

    if vp.network == "ws":
        stream_settings["wsSettings"] = {
            "path": vp.path or "/",
            "headers": {"Host": vp.host_header or vp.sni or vp.host},
        }
    elif vp.network == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": vp.path.lstrip("/") if vp.path else ""}

    user = {"id": vp.uuid, "encryption": "none"}
    if vp.flow:
        user["flow"] = vp.flow

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": local_port,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": vp.host, "port": vp.port, "users": [user]}]},
            "streamSettings": stream_settings,
        }],
    }


# ──────────────────────────────────────────────────────────────────────────
# ПРОВЕРКА ОДНОГО ПРОКСИ
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    proxy: VlessProxy
    ok: bool
    latency: float | None = None
    error: str = ""


def check_single_proxy(vp: VlessProxy) -> CheckResult:
    local_port = find_free_port()
    config = build_xray_config(vp, local_port)

    os.makedirs(TMP_DIR, exist_ok=True)
    cfg_path = os.path.join(TMP_DIR, f"cfg_{local_port}.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(XRAY_STARTUP_DELAY)

        if proc.poll() is not None:
            return CheckResult(vp, False, error="xray не запустился")

        proxies_dict = {
            "http": f"socks5h://127.0.0.1:{local_port}",
            "https": f"socks5h://127.0.0.1:{local_port}",
        }

        total_latency = 0.0
        for test_url in TEST_URLS:
            start = time.monotonic()
            r = requests.get(test_url, proxies=proxies_dict, timeout=REQUEST_TIMEOUT)
            if r.status_code >= 400:
                return CheckResult(vp, False, error=f"{test_url} -> HTTP {r.status_code}")
            total_latency += time.monotonic() - start

        avg_latency = total_latency / len(TEST_URLS)
        return CheckResult(vp, True, latency=round(avg_latency, 3))

    except requests.RequestException as e:
        return CheckResult(vp, False, error=str(e)[:120])
    except Exception as e:
        return CheckResult(vp, False, error=f"unexpected: {e}"[:120])
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.remove(cfg_path)
        except OSError:
            pass


def check_all_proxies(proxies: list[VlessProxy]) -> list[CheckResult]:
    results: list[CheckResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(check_single_proxy, vp): vp for vp in proxies}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            res = future.result()
            status = "OK" if res.ok else "FAIL"
            info = f"{res.latency}s" if res.ok else res.error
            print(f"[{i}/{len(proxies)}] {status:4} {res.proxy.name[:30]:30} {info}")
            results.append(res)
    return results


# ──────────────────────────────────────────────────────────────────────────
# ИСТОРИЯ СТАБИЛЬНОСТИ
# ──────────────────────────────────────────────────────────────────────────

def load_history() -> dict:
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Не удалось прочитать {HISTORY_FILE}: {e}", file=sys.stderr)
        return {}


def update_history(history: dict, results: list["CheckResult"]) -> dict:
    for r in results:
        key = r.proxy.identity()
        key_str = "|".join(str(x) for x in key)
        entry = history.get(key_str, {"streak": 0})
        if r.ok:
            entry["streak"] = entry.get("streak", 0) + 1
        else:
            entry["streak"] = 0
        entry["last_ok"] = r.ok
        entry["last_latency"] = r.latency
        history[key_str] = entry
    return history


def save_history(history: dict) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=0)


def stability_streak(history: dict, vp: "VlessProxy") -> int:
    key_str = "|".join(str(x) for x in vp.identity())
    return history.get(key_str, {}).get("streak", 0)


def effective_score(latency: float, streak: int) -> float:
    missing = max(0, STABILITY_WINDOW - streak)
    penalty_multiplier = 1.0 + missing * STABILITY_PENALTY_PER_STEP
    return latency * penalty_multiplier


# ──────────────────────────────────────────────────────────────────────────
# ГЕОЛОКАЦИЯ + ПЕРЕИМЕНОВАНИЕ ФИНАЛЬНОГО ТОПА
# ──────────────────────────────────────────────────────────────────────────

def rename_with_country(vp: VlessProxy) -> str:
    iso, name_en = lookup_country(vp.host)
    flag = country_flag(iso)
    name_ru = country_name_ru(iso, name_en)
    new_name = f"{flag} {name_ru} | {NAME_SUFFIX}"
    return vp.to_link(name=new_name)


def geolocate_and_rename(top_results: list[CheckResult]) -> list[str]:
    links = [None] * len(top_results)
    with concurrent.futures.ThreadPoolExecutor(max_workers=GEO_LOOKUP_WORKERS) as pool:
        futures = {pool.submit(rename_with_country, r.proxy): i for i, r in enumerate(top_results)}
        for future in concurrent.futures.as_completed(futures):
            i = futures[future]
            try:
                links[i] = future.result()
            except Exception:
                links[i] = top_results[i].proxy.to_link()
    return links


# ──────────────────────────────────────────────────────────────────────────
# СОХРАНЕНИЕ РЕЗУЛЬТАТА
# ──────────────────────────────────────────────────────────────────────────

def build_subscription_header(title: str) -> str:
    lines = [
        f"#profile-title: {title}",
        f"#profile-update-interval: {SUB_UPDATE_INTERVAL}",
    ]
    if SUB_SUPPORT_URL:
        lines.append(f"#support-url: {SUB_SUPPORT_URL}")
    if SUB_ANNOUNCE:
        lines.append(f"#announce: {SUB_ANNOUNCE}")
    lines.append("#subscription-userinfo: upload=0; download=0; total=0; expire=0")
    return "\n".join(lines)


def write_subscription_file(path: str, results: list[CheckResult], links: list[str], title: str) -> None:
    header = build_subscription_header(title)
    body = header + "\n" + "\n".join(links)
    encoded = base64.b64encode(body.encode("utf-8")).decode("utf-8")
    with open(path, "w", encoding="utf-8") as f:
        f.write(encoded)


def save_results(results: list[CheckResult]) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    history = load_history()
    history = update_history(history, results)

    working = [r for r in results if r.ok]

    working.sort(key=lambda r: effective_score(r.latency, stability_streak(history, r.proxy)))

    main_top = working[:MAX_PROXIES]
    
    best_of_best = main_top[:TOP_N_PROXIES]

    main_links = geolocate_and_rename(main_top)
    write_subscription_file(OUTPUT_FILE, main_top, main_links, SUB_PROFILE_TITLE_MAIN)

    
    best_links = geolocate_and_rename(best_of_best)
    write_subscription_file(TOP_FILE, best_of_best, best_links, SUB_PROFILE_TITLE_TOP)

    save_history(history)

    report_path = os.path.join(OUTPUT_DIR, "report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"Проверено всего: {len(results)}\n")
        f.write(f"Рабочих: {len(working)}\n")
        f.write(f"Основная подписка (лимит {MAX_PROXIES}): {len(main_top)}\n")
        f.write(f"Вторая подписка — топ лучших (лимит {TOP_N_PROXIES}): {len(best_of_best)}\n\n")
        f.write("── Основная подписка ──\n")
        for r, link in zip(main_top, main_links):
            frag = unquote(urlparse(link).fragment)
            streak = stability_streak(history, r.proxy)
            f.write(f"{r.latency:>6}s  streak={streak:<3} {frag}  ({r.proxy.host}:{r.proxy.port})\n")

    print(f"\n[+] Рабочих прокси всего: {len(working)} / {len(results)}")
    print(f"[+] Основная подписка: {len(main_top)} (лимит {MAX_PROXIES}) -> {OUTPUT_FILE}")
    print(f"[+] Вторая подписка (топ): {len(best_of_best)} (лимит {TOP_N_PROXIES}) -> {TOP_FILE}")


# ──────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────

def main():
    if not SUBSCRIPTIONS:
        print("[!] Не заданы подписки (SUBSCRIPTIONS)", file=sys.stderr)
        sys.exit(1)

    print(f"Подписки: {len(SUBSCRIPTIONS)}, тестовые URL: {TEST_URLS}, "
          f"воркеров: {MAX_WORKERS}, лимит подписки: {MAX_PROXIES}\n")

    proxies = collect_all_proxies()
    if not proxies:
        print("[!] Нет прокси для проверки", file=sys.stderr)
        sys.exit(1)

    results = check_all_proxies(proxies)
    save_results(results)


if __name__ == "__main__":
    main()
