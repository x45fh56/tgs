import re
import geoip2.database
import os
import sys
import platform
import subprocess
import tempfile
import time
import json
import argparse
import logging
import threading
import queue
import requests
import shutil
import base64
import binascii
import urllib3
import zipfile
import geoip2.errors
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote, urlencode, quote
from base64 import urlsafe_b64decode, urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
from collections import defaultdict

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

PROTOCOLS_DIR = os.path.join("Servers", "Protocols")
REGIONS_DIR = os.path.join("Servers", "Regions")
REPORTS_DIR = os.path.join("logs")
MERGED_DIR = os.path.join("Servers", "Merged")
CHANNELS_DIR = os.path.join("Servers", "Channels")
MERGED_SNI_FILE = os.path.join(MERGED_DIR, "merged_servers_sni.txt")
SNI_CHANNELS = {"SNI_SPOOFINGconfig"}  # فقط این کانال‌ها به merged_servers_sni.txt نوشته می‌شن
EXTRACTED_IPS_FILE = os.path.join(MERGED_DIR, "extracted_cdn_ips.txt")
CHANNELS_FILE = "data/telegram_sources.txt"
LOG_FILE = os.path.join(REPORTS_DIR, "extraction_report.log")
GEOIP_DATABASE_PATH = Path("data/db/GeoLite2-Country.mmdb")
MERGED_SERVERS_FILE = os.path.join(MERGED_DIR, "merged_servers.txt")

ENABLE_EXTRACTION = True
ENABLE_GEO_LOOKUP = True
ENABLE_REPORTING = True
ENABLE_TESTING = False
ENABLE_V2RAY_SETUP = False
ENABLE_TESTED_GEO_SORT = False
ENABLE_CATEGORIZATION = True
ENABLE_PATT_EDITION = True

PATT_ADDRESSES_MAIN = [
    "188.114.97.6",
]
PATT_IP_CHANNEL_URL = "https://t.me/s/cfipsf"
PATT_MAIN_FILE = os.path.join(MERGED_DIR, "patt_main.txt")
PATT_ALL_FILE = os.path.join(MERGED_DIR, "patt_all.txt")
PATT_PER_IP_DIR = os.path.join(MERGED_DIR, "PerIpsMatt")
PATT_FP = "unsafe"
PATT_FINAL_MASK = '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5","94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}'
PATT_CIPHER_SUITES = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"

SLEEP_TIME = 1
BATCH_SIZE = 10
FETCH_CONFIG_LINKS_TIMEOUT = 15
MAX_CHANNEL_SERVERS = 1000
MAX_PROTOCOL_SERVERS = 100000
MAX_REGION_SERVERS = 100000
MAX_MERGED_SERVERS = 1000000

V2RAY_BIN = 'v2ray' if platform.system() == 'Linux' else 'v2ray.exe'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
V2RAY_DIR = os.path.join(BASE_DIR, 'data', 'v2ray')
TESTED_SERVERS_DIR = os.path.join(BASE_DIR, 'Tested_Servers')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
TEST_LINK = "http://httpbin.org/get"
MAX_THREADS = 20
START_PORT = 10000
REQUEST_TIMEOUT = 30
PROCESS_START_WAIT = 15
REALTIME_UPDATE_INTERVAL = 25
ENABLED_PROTOCOLS_TO_TEST = {
    'vless': True,
    'vmess': False,
    'trojan': False,
    'ss': False,
    'hysteria': False,
    'hysteria2': False,
    'tuic': False,
    'wireguard': False,
    'warp': False,
}
channel_test_stats = defaultdict(
    lambda: {'total_prepared': 0, 'active': 0, 'failed': 0, 'skip': 0})

def clean_directory(dir_path):
    if os.path.exists(dir_path):
        is_v2ray_dir = os.path.abspath(dir_path) == os.path.abspath(V2RAY_DIR)
        if is_v2ray_dir:
            for filename in os.listdir(dir_path):
                file_path = os.path.join(dir_path, filename)
                if filename == V2RAY_BIN or filename.lower().endswith(('.dat', '.db', 'geoip.dat', 'geosite.dat')):
                    continue
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception:
                    pass
            os.makedirs(dir_path, exist_ok=True)
            return
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception:
                pass
    else:
        os.makedirs(dir_path, exist_ok=True)

PATTERNS = {
    'vmess': r'(?<![a-zA-Z0-9_])vmess://[^\s<>]+',
    'vless': r'(?<![a-zA-Z0-9_])vless://[^\s<>]+',
    'trojan': r'(?<![a-zA-Z0-9_])trojan://[^\s<>]+',
    'hysteria': r'(?<![a-zA-Z0-9_])hysteria://[^\s<>]+',
    'hysteria2': r'(?<![a-zA-Z0-9_])hysteria2://[^\s<>]+',
    'tuic': r'(?<![a-zA-Z0-9_])tuic://[^\s<>]+',
    'ss': r'(?<![a-zA-Z0-9_])ss://[^\s<>]+',
    'wireguard': r'(?<![a-zA-Z0-9_])wireguard://[^\s<>]+',
    'warp': r'(?<![a-zA-Z0-9_])warp://[^\s<>]+'
}

def normalize_telegram_url(url):
    if not url:
        return ""
    url = url.strip()
    url_lower = url.lower()
    
    if '.txt' in url_lower or 'raw.githubusercontent.com' in url_lower:
        if not url_lower.startswith("http"):
            return f"https://{url}"
        return url
        
    if url.startswith("@"):
        return f"https://t.me/s/{url[1:]}"
        
    if not url_lower.startswith("http") and not url_lower.startswith("t.me/"):
        return f"https://t.me/s/{url}"
        
    if url_lower.startswith("t.me/"):
        return f"https://{url}"
        
    if url_lower.startswith("https://t.me/"):
        parts = url.split('/')
        if len(parts) >= 4 and parts[3] != 's':
            return f"https://t.me/s/{parts[3]}"
            
    return url

def extract_channel_name(url):
    if '.txt' in url.lower() or 'raw.githubusercontent.com' in url.lower():
        name = url.split('/')[-1]
        return name.replace('.txt', '') if name else "Subscription"
    try:
        parsed_url = urlparse(url)
        path_parts = [part for part in parsed_url.path.split('/') if part]
        if path_parts:
            if path_parts[0] == 's' and len(path_parts) > 1:
                return path_parts[1]
            return path_parts[0]
    except Exception:
        pass
    name_candidate = url.split('/')[-1] if '/' in url else url
    name_candidate = name_candidate.split('?')[0].split('#')[0]
    return name_candidate if name_candidate else "unknown_channel"

def count_servers_in_file(file_path):
    if not os.path.exists(file_path):
        return 0
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return len([line for line in f if line.strip() and not line.strip().startswith('#')])
    except Exception:
        return 0

def get_current_counts():
    counts = {}
    for proto in PATTERNS:
        counts[proto] = count_servers_in_file(os.path.join(PROTOCOLS_DIR, f"{proto}.txt"))
    counts['total'] = count_servers_in_file(MERGED_SERVERS_FILE)
    counts['cdn_ips'] = count_servers_in_file(EXTRACTED_IPS_FILE)
    regional_servers = 0
    country_data = {}
    if os.path.exists(REGIONS_DIR):
        for region_file in Path(REGIONS_DIR).glob("*.txt"):
            country = region_file.stem
            count = count_servers_in_file(region_file)
            country_data[country] = count
            regional_servers += count
    counts['successful'] = regional_servers
    counts['failed'] = max(0, counts['total'] - regional_servers)
    return counts, country_data

def get_channel_stats():
    channel_stats = {}
    if os.path.exists(CHANNELS_DIR):
        for channel_file in Path(CHANNELS_DIR).glob("*.txt"):
            channel_stats[channel_file.stem] = count_servers_in_file(channel_file)
    return channel_stats

def save_extraction_data(channel_stats_data, country_data_map):
    current_counts, country_stats_map_local = get_current_counts()
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(LOG_FILE, 'w', encoding='utf-8') as log:
            log.write("=== Country Statistics ===\n")
            log.write(f"Total Servers (Merged): {current_counts['total']}\n")
            log.write(f"Successful Geo-IP Resolutions: {current_counts['successful']}\n")
            log.write(f"Failed Geo-IP Resolutions: {current_counts['failed']}\n")
            for country, count in sorted(country_stats_map_local.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{country:<20} : {count}\n")
            log.write("\n=== Server Type Summary ===\n")
            valid_protocols = {p: current_counts.get(p, 0) for p in PATTERNS}
            valid_protocols['cdn'] = current_counts.get('cdn_ips', 0)
            for proto, count in sorted(valid_protocols.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{proto.upper():<20} : {count}\n")
            log.write("\n=== Channel Statistics (Extraction) ===\n")
            if not channel_stats_data:
                log.write("No channel data available.\n")
            else:
                for channel, total in sorted(channel_stats_data.items(), key=lambda x: x[1], reverse=True):
                    log.write(f"{channel:<30}: {total}\n")
    except Exception:
        pass

def try_decode_base64(text):
    try:
        padded = text.strip() + "=" * ((4 - len(text.strip()) % 4) % 4)
        return base64.b64decode(padded).decode('utf-8', errors='ignore')
    except Exception:
        return text

def extract_configs_from_text(text, configs_dict):
    for proto, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            valid_matches = {m for m in matches if urlparse(m).scheme == proto}
            if valid_matches:
                configs_dict[proto].update(valid_matches)
                configs_dict["all"].update(valid_matches)
    
    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    if ip_matches:
        for ip_str in ip_matches:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local and not ip_obj.is_multicast and not ip_obj.is_unspecified:
                    configs_dict["ips"].add(ip_str)
            except ValueError:
                pass

def fetch_config_links(url):
    logging.info(f"Fetching configs from: {url}")
    configs = {proto: set() for proto in PATTERNS}
    configs["all"] = set()
    configs["ips"] = set()
    ALLOWED_SUB_KEYWORDS = {'.txt', 'raw.githubusercontent.com', '/sub/', '/subscription'}
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, timeout=FETCH_CONFIG_LINKS_TIMEOUT, headers=headers)
        response.raise_for_status()

        if '.txt' in url.lower() or 'raw.githubusercontent.com' in url.lower() or 't.me' not in url.lower():
            text = response.text
            decoded_text = try_decode_base64(text)
            extract_configs_from_text(text, configs)
            extract_configs_from_text(decoded_text, configs)
            return {k: list(v) for k, v in configs.items() if v}

        soup = BeautifulSoup(response.content, 'html.parser')
        page_text = soup.get_text(separator='\n')
        extract_configs_from_text(page_text, configs)

        url_pattern = r'https?://[^\s<>"\']+'
        found_urls = re.findall(url_pattern, page_text)
        for a_tag in soup.find_all('a', href=True):
            found_urls.append(a_tag['href'])

        for sub_url in set(found_urls):
            if any(kw in sub_url.lower() for kw in ALLOWED_SUB_KEYWORDS):
                try:
                    sub_res = requests.get(sub_url, timeout=10, headers=headers)
                    if sub_res.status_code == 200:
                        sub_text = sub_res.text
                        sub_decoded = try_decode_base64(sub_text)
                        extract_configs_from_text(sub_text, configs)
                        extract_configs_from_text(sub_decoded, configs)
                except Exception:
                    continue

        final_configs = {k: list(v) for k, v in configs.items() if v}
        logging.info(f"Found {len(final_configs.get('all', []))} potential configs in {url}")
        return final_configs
    except Exception as e:
        logging.error(f"Scraping error for {url}: {e}")
        return None

def load_existing_configs():
    existing = {proto: set() for proto in PATTERNS}
    existing["merged"] = set()
    for proto in PATTERNS:
        p_file = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        if os.path.exists(p_file):
            try:
                with open(p_file, 'r', encoding='utf-8') as f:
                    existing[proto] = {l.strip() for l in f if l.strip()}
            except Exception:
                pass
    m_file = MERGED_SERVERS_FILE
    if os.path.exists(m_file):
        try:
            with open(m_file, 'r', encoding='utf-8') as f:
                existing['merged'] = {l.strip() for l in f if l.strip()}
        except Exception:
            pass
    return existing

def trim_file(file_path, max_lines):
    if not os.path.exists(file_path) or max_lines <= 0:
        return
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        valid_lines = [line for line in lines if line.strip()]
        if len(valid_lines) > max_lines:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(l if l.endswith('\n') else l + '\n' for l in valid_lines[:max_lines])
    except Exception:
        pass

def download_geoip_database():
    GEOIP_URL = "https://git.io/GeoLite2-Country.mmdb"
    GEOIP_DIR = GEOIP_DATABASE_PATH.parent
    try:
        GEOIP_DIR.mkdir(parents=True, exist_ok=True)
        with requests.get(GEOIP_URL, timeout=60, stream=True) as response:
            response.raise_for_status()
            with open(GEOIP_DATABASE_PATH, 'wb') as f:
                shutil.copyfileobj(response.raw, f)
        if GEOIP_DATABASE_PATH.stat().st_size > 1024 * 1024:
            return True
        else:
            GEOIP_DATABASE_PATH.unlink(missing_ok=True)
            return False
    except Exception:
        GEOIP_DATABASE_PATH.unlink(missing_ok=True)
        return False

def process_geo_data():
    if not GEOIP_DATABASE_PATH.exists() or GEOIP_DATABASE_PATH.stat().st_size < 1024 * 1024:
        if not download_geoip_database():
            return {}
    geo_reader = None 
    try:
        geo_reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
    except Exception:
        return {}

    country_configs = defaultdict(list)
    failed_lookups = 0
    processed = 0

    if os.path.exists(REGIONS_DIR):
        for rf in Path(REGIONS_DIR).glob("*.txt"):
            try:
                rf.unlink()
            except OSError:
                pass
    else:
        os.makedirs(REGIONS_DIR, exist_ok=True)

    configs_for_geoip = []
    if os.path.exists(MERGED_SERVERS_FILE):
        try:
            with open(MERGED_SERVERS_FILE, 'r', encoding='utf-8') as f:
                configs_for_geoip = [l.strip() for l in f if l.strip()]
        except Exception:
            pass

    if not configs_for_geoip:
        if geo_reader: geo_reader.close()
        return {}

    for config_link in configs_for_geoip:
        processed += 1
        ip_address = None
        country_code = "Unknown"
        try:
            parsed_link = urlparse(config_link)
            hostname = parsed_link.hostname
            if not hostname: 
                failed_lookups += 1
                continue

            if parsed_link.scheme in ['vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'ss']:
                ip_address = hostname
            elif parsed_link.scheme == 'vmess':
                try:
                    b64_payload = parsed_link.netloc + parsed_link.path
                    decoded_payload = urlsafe_b64decode(b64_payload + '=' * ((4 - len(b64_payload) % 4) % 4)).decode('utf-8')
                    vmess_data = json.loads(decoded_payload)
                    ip_address = vmess_data.get('add')
                except Exception:
                    failed_lookups +=1 
                    continue 

            if ip_address:
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
                    country_code = "Domain" 
                else:
                    try:
                        response = geo_reader.country(ip_address)
                        country_code = response.country.iso_code or response.country.name or "Unknown"
                    except Exception:
                        country_code = "Unknown" 
                        failed_lookups +=1
            else: 
                failed_lookups += 1
                country_code = "Unknown"

        except Exception: 
            failed_lookups += 1
            country_code = "Unknown"

        country_configs[country_code].append(config_link)

    if geo_reader:
        geo_reader.close()

    final_country_counts = {}
    for country_code, config_list in country_configs.items():
        final_country_counts[country_code] = len(config_list)
        try:
            safe_country_name = "".join(c if c.isalnum() else "_" for c in country_code)
            with open(os.path.join(REGIONS_DIR, f"{safe_country_name}.txt"), 'w', encoding='utf-8') as f:
                f.write('\n'.join(config_list[:MAX_REGION_SERVERS]) + '\n')
        except Exception:
            pass
    return dict(final_country_counts)

class CleanFormatter(logging.Formatter):
    def format(self, record):
        if hasattr(record, 'clean_output'):
            if record.levelno == logging.INFO:
                return f"{record.msg}"
            elif record.levelno >= logging.WARNING:
                return f"{record.levelname}: {record.msg}"
        return super().format(record)

os.makedirs(LOGS_DIR, exist_ok=True)

if not logging.getLogger().hasHandlers():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    cf = CleanFormatter()
    ch.addFilter(lambda r: setattr(r, 'clean_output', True) or True)
    ch.setFormatter(cf)
    logger.addHandler(ch)
    log_path = os.path.join(LOGS_DIR, 'testing_debug.log')
    fh = logging.FileHandler(log_path, mode='w', encoding='utf-8')
    ff = logging.Formatter('%(asctime)s-%(levelname)s-%(threadName)s- %(message)s')
    fh.setFormatter(ff)
    logger.addHandler(fh)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

port_pool = queue.Queue()
for p in range(START_PORT, START_PORT + (MAX_THREADS * 2)):
    port_pool.put(p)

def get_next_port():
    return port_pool.get()

def release_port(port):
    port_pool.put(port)

def read_links_from_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
    except Exception:
        return []

def build_patt_link_uri(link, scheme, address):
    # برای پروتکل‌هایی که لینکشون به شکل URI با query string هست (vless, trojan)
    parsed = urlparse(link)
    if parsed.scheme != scheme or not parsed.username:
        return None
    query = parse_qs(parsed.query)
    new_query = {k: v[0] for k, v in query.items() if v}
    new_query['security'] = new_query.get('security') or 'tls'
    if scheme == 'vless':
        new_query['encryption'] = new_query.get('encryption') or 'none'
    new_query['cs'] = PATT_CIPHER_SUITES
    new_query['fm'] = PATT_FINAL_MASK
    new_query['fp'] = PATT_FP
    port = parsed.port or (443 if new_query['security'] in ('tls', 'reality') else 80)
    # quote_via=quote مهمه: پیش‌فرض urlencode یعنی quote_plus، space رو '+' می‌کنه
    # که JSON داخل fm رو موقع دیکد استاندارد (unquote، نه unquote_plus) خراب می‌کنه.
    query_string = urlencode(new_query, quote_via=quote)
    new_link = f"{scheme}://{parsed.username}@{address}:{port}?{query_string}"
    tag = f"{parsed.fragment}-{address}" if parsed.fragment else address
    new_link += f"#{tag}"
    return new_link

def build_patt_link_vmess(link, address):
    if not link.startswith('vmess://'):
        return None
    b64_part = link[len('vmess://'):]
    try:
        decoded = urlsafe_b64decode(b64_part + '=' * ((4 - len(b64_part) % 4) % 4)).decode('utf-8')
        data = json.loads(decoded)
    except Exception:
        return None
    data['add'] = address
    data['fp'] = PATT_FP
    # این دو کلید استاندارد فرمت vmess نیستن؛ کلاینت‌هایی که پشتیبانی نکنن نادیده‌شون می‌گیرن
    data['cs'] = PATT_CIPHER_SUITES
    data['fm'] = PATT_FINAL_MASK
    original_ps = data.get('ps', 'vmess')
    data['ps'] = f"{original_ps}-{address}"
    new_b64 = urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip('=')
    return f"vmess://{new_b64}"

def build_patt_link_ss(link, address):
    # ss فقط شکسپه/رمزنگاری AEAD داره، امنیت TLS نداره، پس cs/fm/fp روش معنی نداره؛
    # فقط آدرس رو عوض می‌کنیم و بقیه رو دست‌نخورده نگه می‌داریم
    parsed = urlparse(link)
    if parsed.scheme != 'ss' or '@' not in parsed.netloc:
        return None
    userinfo, host_port = parsed.netloc.rsplit('@', 1)
    port = host_port.split(':', 1)[1] if ':' in host_port else '8388'
    new_link = f"ss://{userinfo}@{address}:{port}"
    if parsed.query:
        new_link += f"?{parsed.query}"
    tag = f"{parsed.fragment}-{address}" if parsed.fragment else address
    new_link += f"#{tag}"
    return new_link

def build_patt_link_generic(link, scheme, address):
    # پروتکل‌های ناشناخته/بدون پارسر اختصاصی (hysteria, hysteria2, tuic, wireguard, warp و...)
    # با فرض ساختار URI معمول user@host:port?query#name فقط آدرس رو عوض می‌کنیم
    parsed = urlparse(link)
    if '@' not in parsed.netloc or ':' not in parsed.netloc.rsplit('@', 1)[-1]:
        return None
    userinfo, host_port = parsed.netloc.rsplit('@', 1)
    port = host_port.rsplit(':', 1)[1]
    new_link = f"{scheme}://{userinfo}@{address}:{port}"
    if parsed.query:
        new_link += f"?{parsed.query}"
    tag = f"{parsed.fragment}-{address}" if parsed.fragment else address
    new_link += f"#{tag}"
    return new_link

def fetch_latest_ips_from_channel(channel_url=PATT_IP_CHANNEL_URL, timeout=20):
    # آخرین پست کانال تلگرام رو می‌خونه و همه‌ی آی‌پی‌های عمومی توش رو استخراج می‌کنه
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(channel_url, timeout=timeout, headers=headers)
        response.raise_for_status()
    except Exception as e:
        logging.error(f"Telegram IP channel fetch failed ({channel_url}): {e}")
        return []
    soup = BeautifulSoup(response.content, 'html.parser')
    posts = soup.find_all('div', class_='tgme_widget_message')
    if not posts:
        logging.error(f"No posts found on {channel_url}")
        return []
    last_post = posts[-1]
    post_text = last_post.get_text(separator='\n')
    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', post_text)
    seen = set()
    ordered_ips = []
    for ip_str in ip_matches:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                or ip_obj.is_multicast or ip_obj.is_unspecified):
            continue
        if ip_str not in seen:
            seen.add(ip_str)
            ordered_ips.append(ip_str)
    logging.info(f"Extracted {len(ordered_ips)} clean IP(s) from latest post of {channel_url}")
    return ordered_ips

def get_patt_builder(link, scheme):
    if scheme == 'vless':
        return lambda addr: build_patt_link_uri(link, 'vless', addr)
    if scheme == 'trojan':
        return lambda addr: build_patt_link_uri(link, 'trojan', addr)
    if scheme == 'vmess':
        return lambda addr: build_patt_link_vmess(link, addr)
    if scheme == 'ss':
        return lambda addr: build_patt_link_ss(link, addr)
    if scheme:
        return lambda addr: build_patt_link_generic(link, scheme, addr)
    return None

def write_patt_file(path, lines):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + ('\n' if lines else ''))

def generate_patt_edition():
    if not os.path.exists(MERGED_SERVERS_FILE):
        logging.error(f"Merged servers file not found: {MERGED_SERVERS_FILE}")
        return 0
    links = read_links_from_file(MERGED_SERVERS_FILE)

    extracted_ips = fetch_latest_ips_from_channel(PATT_IP_CHANNEL_URL)
    all_addresses = list(PATT_ADDRESSES_MAIN)
    seen_addr = set(all_addresses)
    for ip in extracted_ips:
        if ip not in seen_addr:
            seen_addr.add(ip)
            all_addresses.append(ip)

    per_address_links = {addr: [] for addr in all_addresses}
    main_addr_set = set(PATT_ADDRESSES_MAIN)
    main_links = []
    skipped = 0

    for link in links:
        scheme = urlparse(link).scheme
        builder = get_patt_builder(link, scheme)
        if not builder:
            skipped += 1
            continue
        matched_any = False
        for addr in all_addresses:
            try:
                new_link = builder(addr)
            except Exception:
                new_link = None
            if new_link:
                matched_any = True
                per_address_links[addr].append(new_link)
                if addr in main_addr_set:
                    main_links.append(new_link)
        if not matched_any:
            skipped += 1

    os.makedirs(MERGED_DIR, exist_ok=True)
    os.makedirs(PATT_PER_IP_DIR, exist_ok=True)

    write_patt_file(PATT_MAIN_FILE, main_links)
    logging.info(f"Patt main: {len(main_links)} links ({len(PATT_ADDRESSES_MAIN)} address) -> {PATT_MAIN_FILE}")

    all_links = [l for addr in all_addresses for l in per_address_links[addr]]
    write_patt_file(PATT_ALL_FILE, all_links)
    logging.info(f"Patt all: {len(all_links)} links ({len(all_addresses)} addresses) -> {PATT_ALL_FILE}")

    for idx, addr in enumerate(all_addresses, start=1):
        ip_file = os.path.join(PATT_PER_IP_DIR, f"patt_ip_{idx}.txt")
        write_patt_file(ip_file, per_address_links[addr])
    logging.info(f"Patt per-IP: {len(all_addresses)} file(s) (patt_ip_1..patt_ip_{len(all_addresses)}) -> {PATT_PER_IP_DIR}")

    logging.info(f"Patt edition done: servers={len(links)}, skipped={skipped}, addresses={len(all_addresses)}")
    return len(all_links)

def parse_vless_link(link):
    parsed = urlparse(link)
    uuid = parsed.username
    query = parse_qs(parsed.query)
    hostname = parsed.hostname
    if not (parsed.scheme == 'vless' and hostname and uuid and
            re.match(r'^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$', uuid, re.I)):
        raise ValueError(f"Invalid VLESS link structure: {link}")
    port = parsed.port or (443 if query.get('security', [''])[0] in ['tls', 'reality'] else 80)
    sec = query.get('security', ['none'])[0] or 'none'
    net = query.get('type', ['tcp'])[0] or 'tcp'
    sni = query.get('sni', [hostname])[0] or hostname
    return {'original_link': link, 'protocol': 'vless', 'uuid': uuid.replace('-', ''), 'host': hostname, 'port': int(port),
            'security': sec, 'encryption': query.get('encryption', ['none'])[0] or 'none', 'network': net,
            'ws_path': query.get('path', ['/'])[0] if net == 'ws' else '/',
            'ws_host': query.get('host', [sni])[0] if net == 'ws' else sni,
            'sni': sni, 'pbk': query.get('pbk', [''])[0] if sec == 'reality' else '',
            'sid': query.get('sid', [''])[0] if sec == 'reality' else '',
            'fp': query.get('fp', [''])[0] if sec == 'reality' else '',
            'alpn': [v.strip() for v in query.get('alpn', [''])[0].split(',') if v.strip()],
            'flow': query.get('flow', [''])[0]}

def parse_vmess_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'vmess':
        raise ValueError(f"Invalid VMESS scheme: {link}")
    try:
        base64_part = parsed.netloc + parsed.path
        json_str = urlsafe_b64decode(
            base64_part + '=' * ((4 - len(base64_part) % 4) % 4)).decode('utf-8')
        data = json.loads(json_str)
    except Exception as e:
        raise ValueError(f"VMess JSON decode error for {link}: {e}")
    address = data.get('add', '')
    if not re.match(r"^[a-zA-Z0-9.-]+$", address):
        address = data.get('host', '') 
        if not address:
            raise ValueError(f"VMess 'add' field is invalid and no fallback 'host' found: {data.get('add')}")
    port = int(data.get('port', 0))
    uuid = data.get('id')
    if not (address and port and uuid):
        raise ValueError(f"VMess missing address/port/id in {link}")
    clean_data = {
        "v": "2",
        "ps": f"vmess-{address}-{port}",
        "add": address,
        "port": str(port), 
        "id": uuid,
        "aid": str(data.get("aid", 0)),
        "net": data.get("net", "tcp") or "tcp",
        "type": data.get("type", "none") or "none", 
        "host": data.get("host", ""),
        "path": data.get("path", ""),
        "tls": data.get("tls", "") or "", 
        "sni": data.get("sni", ""),
        "alpn": data.get("alpn", ""),
        "fp": data.get("fp", ""),
        "scy": data.get("scy", "auto") or "auto" 
    }
    keys_to_remove = [k for k, v in clean_data.items() if v == "" and k not in ["ps", "add", "port", "id", "net", "tls"]]
    for k in keys_to_remove:
        del clean_data[k]
    clean_json_str = json.dumps(clean_data, separators=(',', ':'), sort_keys=True)
    rebuilt_b64 = urlsafe_b64encode(clean_json_str.encode('utf-8')).decode('utf-8').rstrip("=")
    rebuilt_link = f"vmess://{rebuilt_b64}"
    return {
        'original_link': rebuilt_link, 
        'protocol': 'vmess', 
        'uuid': uuid, 
        'host': address, 
        'port': port, 
        'network': clean_data["net"],
        'security': clean_data["tls"], 
        'ws_path': clean_data.get('path', '/') if clean_data["net"] == 'ws' else '/',
        'ws_host': clean_data.get('host', address) if clean_data["net"] == 'ws' else address,
        'sni': clean_data.get('sni', clean_data.get('host', address) if clean_data["tls"] == 'tls' else ''),
        'alter_id': int(clean_data["aid"]), 
        'encryption': clean_data.get("scy", "auto")
    }

def parse_trojan_link(link):
    parsed = urlparse(link)
    passwd = parsed.username
    host = parsed.hostname
    port = parsed.port
    query = parse_qs(parsed.query)
    if not (parsed.scheme == 'trojan' and passwd and host and port):
        raise ValueError(f"Invalid Trojan link structure: {link}")
    sec = query.get('security', ['tls'])[0] or 'tls'
    sni = query.get('sni', [host])[0] or host
    net = query.get('type', ['tcp'])[0] or 'tcp'
    alpn_str = query.get('alpn', ['h2,http/1.1'])[0]
    alpn = [v.strip() for v in alpn_str.split(',') if v.strip()]
    return {'original_link': link, 'protocol': 'trojan', 'password': passwd, 'host': host, 'port': int(port),
            'security': sec, 'sni': sni, 'alpn': alpn, 'network': net,
            'ws_path': query.get('path', ['/'])[0] if net == 'ws' else '/',
            'ws_host': query.get('host', [sni])[0] if net == 'ws' else sni}

def parse_ss_link(link):
    parsed = urlparse(link)
    host = parsed.hostname
    port = parsed.port
    if not (parsed.scheme == 'ss' and host and port):
        raise ValueError(f"Invalid SS host/port in link: {link}")
    name = unquote(parsed.fragment) if parsed.fragment else f"ss_{host}" 
    userinfo_raw = parsed.username
    method, password = None, None
    if userinfo_raw:
        try:
            decoded_userinfo = urlsafe_b64decode(userinfo_raw + '=' * ((4 - len(userinfo_raw) % 4) % 4)).decode('utf-8')
            if ':' in decoded_userinfo:
                method, password = decoded_userinfo.split(':', 1)
            else: 
                 raise ValueError("Decoded userinfo did not contain ':'")
        except Exception:
             if ':' in userinfo_raw: 
                  method, password = userinfo_raw.split(':',1)
             else:
                  raise ValueError(f"Could not parse method:password from userinfo '{userinfo_raw}' in {link}")
    if method is None or password is None:
        raise ValueError(f"Could not extract method/password for SS link: {link}. Userinfo: '{userinfo_raw}'")
    return {'original_link': link, 'protocol': 'shadowsocks', 'method': method, 'password': password,
            'host': host, 'port': int(port), 'network': 'tcp', 'name': name}

def generate_config(s_info, l_port):
    cfg = {
        "log": {"access": None, "error": None, "loglevel": "warning"},
        "inbounds": [{
            "port": l_port, "listen": "127.0.0.1", "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": [{
            "protocol": s_info['protocol'], "settings": {},
            "streamSettings": {
                "network": s_info.get('network', 'tcp'),
                "security": s_info.get('security', 'none') 
            },
            "mux": {"enabled": True, "concurrency": 8}
        }]
    }
    out_s = cfg['outbounds'][0]['settings']
    stream_s = cfg['outbounds'][0]['streamSettings']

    if s_info['protocol'] == 'vless':
        out_s["vnext"] = [{"address": s_info['host'], "port": s_info['port'], "users": [
            {"id": s_info['uuid'], "encryption": s_info.get('encryption', 'none'), "flow": s_info.get('flow', '')}]}]
    elif s_info['protocol'] == 'vmess':
        out_s["vnext"] = [{"address": s_info['host'], "port": s_info['port'], "users": [
            {"id": s_info['uuid'], "alterId": s_info.get('alter_id', 0),
             "security": s_info.get('encryption', 'auto')}]}]
    elif s_info['protocol'] == 'trojan':
        out_s["servers"] = [{"address": s_info['host'],
                             "port": s_info['port'], "password": s_info['password']}]
    elif s_info['protocol'] == 'shadowsocks': 
        out_s["servers"] = [{"address": s_info['host'], "port": s_info['port'],
                             "method": s_info['method'], "password": s_info['password'], "ota": False}]
    current_security = stream_s.get('security', 'none') 

    if current_security == 'tls':
        tls_settings = {"serverName": s_info.get('sni', s_info['host']), "allowInsecure": True}
        if s_info.get('alpn'):
            tls_settings["alpn"] = s_info['alpn']
        if s_info.get('fp') and s_info.get('fp') != 'none' and s_info.get('fp') != '':
            tls_settings["fingerprint"] = s_info['fp']
        stream_s['tlsSettings'] = tls_settings
    elif current_security == 'reality':
        if not s_info.get('pbk') or not s_info.get('fp'):
            raise ValueError("REALITY config missing 'pbk' (publicKey) or 'fp' (fingerprint)")
        stream_s['realitySettings'] = {
            "show": False, "fingerprint": s_info['fp'],
            "serverName": s_info.get('sni', s_info['host']), 
            "publicKey": s_info['pbk'],
            "shortId": s_info.get('sid', ''),
            "spiderX": s_info.get('spx', '/')
        }

    current_network = stream_s.get('network', 'tcp')
    if current_network == 'ws':
        stream_s['wsSettings'] = {
            "path": s_info.get('ws_path', '/'),
            "headers": {"Host": s_info.get('ws_host', s_info.get('sni', s_info['host']))}
        }

    if stream_s.get('security') == 'none':
        del stream_s['security'] 
        stream_s.pop('tlsSettings', None)
        stream_s.pop('realitySettings', None)

    cfg['outbounds'][0]['streamSettings'] = {
        k: v for k, v in stream_s.items() if v is not None or k in ('network') 
    }
    if stream_s.get('network', 'tcp') == 'tcp' and not stream_s.get('security') and not any(k.endswith('Settings') for k in stream_s):
         cfg['outbounds'][0].pop('streamSettings', None)

    return cfg

def test_server(s_info, cfg, l_port, log_q):
    proc = None
    cfg_path = None
    success = False
    err_msg = "Test incomplete"
    r_time = -1.0
    try:
        os.makedirs(V2RAY_DIR, exist_ok=True)
        v2_exec = os.path.join(V2RAY_DIR, V2RAY_BIN)
        if not os.path.exists(v2_exec):
            raise FileNotFoundError(f"V2Ray executable not found: {v2_exec}")
        if platform.system() != "Windows" and not os.access(v2_exec, os.X_OK):
            try:
                os.chmod(v2_exec, 0o755)
            except Exception as e:
                raise PermissionError(f"V2Ray chmod failed: {e}")

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8', dir=V2RAY_DIR) as f:
            json.dump(cfg, f, indent=2)
            cfg_path = f.name

        cmd = [v2_exec, 'run', '--config', cfg_path]
        proc = subprocess.Popen(cmd, cwd=V2RAY_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                encoding='utf-8', errors='ignore', 
                                close_fds=(platform.system() != 'Windows'))
        time.sleep(2) 

        if proc.poll() is not None:
            stderr_output = ""
            if proc.stderr:
                stderr_output = proc.stderr.read(500) 
            raise RuntimeError(
                f"V2Ray exited prematurely (code {proc.returncode}). Config: {json.dumps(cfg['outbounds'][0])}. Stderr: {stderr_output[:200]}...")
            
        proxies = {'http': f'socks5h://127.0.0.1:{l_port}',
                   'https': f'socks5h://127.0.0.1:{l_port}'}
        start_t_req = time.monotonic()
        try:
            resp = requests.get(TEST_LINK, proxies=proxies, timeout=REQUEST_TIMEOUT,
                                verify=False, headers={'User-Agent': 'ProxyTester/1.0'})
            r_time = time.monotonic() - start_t_req
            if resp.status_code == 200:
                success = True
                err_msg = f"{resp.status_code} OK"
            else:
                err_msg = f"HTTP Status {resp.status_code}"
        except requests.exceptions.Timeout:
            r_time = time.monotonic() - start_t_req 
            err_msg = f"Request Timeout ({r_time:.1f}s > {REQUEST_TIMEOUT}s)"
        except requests.exceptions.ProxyError as pe:
            err_msg = f"Proxy Error: {str(pe)[:100]}"
        except requests.exceptions.RequestException as e: 
            err_msg = f"Request Exception: {str(e)[:100]}"

        log_level = logging.INFO if success else logging.WARNING
        log_symbol = "✅" if success else "⚠️"
        display_link = s_info.get('original_link', 'N/A')
        if len(display_link) > 70 : display_link = display_link[:67] + "..."

        logging.log(log_level, f"{log_symbol} Test {'Success' if success else 'Failed'} ({r_time:.2f}s) - "
                    f"{s_info.get('protocol')} {s_info.get('host')}:{s_info.get('port')} | {err_msg} | Link: {display_link}")

    except Exception as e: 
        err_msg = f"Test Setup/Runtime Error: {str(e)[:150]}"
    finally:
        release_port(l_port)
        if proc and proc.poll() is None: 
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2) 
            except Exception: 
                pass
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.remove(cfg_path)
            except Exception:
                pass
        log_q.put(('success' if success else 'failure', s_info,
                  f"{r_time:.2f}s" if success else err_msg))

def check_v2ray_installed():
    v2ray_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
    if not os.path.exists(v2ray_path):
        return None
    try:
         if platform.system() != "Windows" and not os.access(v2ray_path, os.X_OK):
              try: os.chmod(v2ray_path, 0o755)
              except Exception: return None
         result = subprocess.run(
             [v2ray_path, 'version'],
             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
             encoding='utf-8', check=True, cwd=V2RAY_DIR
         )
         output = result.stdout.strip()
         match = re.search(r'V2Ray\s+([\d.]+)', output)
         if match: return match.group(1)
         else: return "unknown"
    except Exception: return None

_latest_release_data_cache = None
_cache_lock = threading.Lock()
_cache_time = 0
CACHE_DURATION = 300 

def get_github_latest_release_data(force_refresh=False):
    global _latest_release_data_cache, _cache_time
    with _cache_lock:
        if not force_refresh and _latest_release_data_cache and (time.time() - _cache_time < CACHE_DURATION):
            return _latest_release_data_cache
        try:
            response = requests.get(
                'https://api.github.com/repos/v2fly/v2ray-core/releases/latest',
                timeout=15 
            )
            response.raise_for_status()
            _latest_release_data_cache = response.json()
            _cache_time = time.time()
            return _latest_release_data_cache
        except Exception:
            if _latest_release_data_cache:
                return _latest_release_data_cache
            return None

def get_latest_version():
    data = get_github_latest_release_data()
    if data:
        tag_name = data.get('tag_name')
        if tag_name and tag_name.startswith('v'):
            return tag_name.lstrip('v')
    return None

def asset_name_exists(asset_name):
    data = get_github_latest_release_data()
    if data is None: return False
    return any(a.get('name') == asset_name for a in data.get('assets', []))

def get_asset_download_url(asset_name):
    data = get_github_latest_release_data()
    if data is None: return None
    for asset in data.get('assets', []):
        if asset.get('name') == asset_name:
            return asset.get('browser_download_url')
    return None

def install_v2ray():
    try:
        os_type = platform.system().lower()
        machine = platform.machine().lower()
        asset_name = None
        if os_type == 'linux':
            if 'aarch64' in machine or 'arm64' in machine: asset_name = 'v2ray-linux-arm64-v8a.zip'
            elif 'armv7' in machine: asset_name = 'v2ray-linux-arm32-v7a.zip'
            elif '64' in machine: asset_name = 'v2ray-linux-64.zip'
            else: asset_name = 'v2ray-linux-32.zip'
        elif os_type == 'windows':
            if '64' in machine: asset_name = 'v2ray-windows-64.zip'
            else: asset_name = 'v2ray-windows-32.zip'
        if not asset_name:
            logging.error("Unsupported OS/Architecture.")
            sys.exit(1)
        if not asset_name_exists(asset_name):
            get_github_latest_release_data(force_refresh=True) 
            if not asset_name_exists(asset_name):
                logging.error(f"Asset {asset_name} not found.")
                sys.exit(1)
        download_url = get_asset_download_url(asset_name)
        if not download_url:
            logging.error("Download URL not found.")
            sys.exit(1)
        os.makedirs(V2RAY_DIR, exist_ok=True)
        clean_directory(V2RAY_DIR) 
        os.makedirs(V2RAY_DIR, exist_ok=True) 
        zip_path = os.path.join(V2RAY_DIR, "v2ray_download.zip")
        with requests.get(download_url, stream=True, timeout=300) as r:
            r.raise_for_status()
            with open(zip_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(V2RAY_DIR)
        os.remove(zip_path)
        v2ray_executable_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
        if not os.path.exists(v2ray_executable_path):
            found_exe = False
            for root, _, files in os.walk(V2RAY_DIR):
                if V2RAY_BIN in files:
                    potential_exe_path = os.path.join(root, V2RAY_BIN)
                    if os.path.abspath(root) != os.path.abspath(V2RAY_DIR):
                        shutil.move(potential_exe_path, v2ray_executable_path)
                        for dat_file in ['geoip.dat', 'geosite.dat']:
                            src_dat = os.path.join(root, dat_file)
                            dst_dat = os.path.join(V2RAY_DIR, dat_file)
                            if os.path.exists(src_dat) and not os.path.exists(dst_dat):
                                shutil.move(src_dat, dst_dat)
                    found_exe = True
                    break
            if not found_exe:
                raise FileNotFoundError(f"V2Ray executable '{V2RAY_BIN}' not found.")
        if platform.system() != 'Windows' and os.path.exists(v2ray_executable_path):
            os.chmod(v2ray_executable_path, 0o755)
        installed_version = check_v2ray_installed()
        if not installed_version:
            raise RuntimeError("V2Ray installed but version check failed.")
    except Exception as e:
        clean_directory(V2RAY_DIR)
        logging.error(f"V2Ray installation failed: {e}")
        sys.exit(1)

def print_real_time_channel_stats_table(stats_data):
    if not stats_data: return
    header = f"{'Channel File/URL':<45} | {'Total':<7} | {'Active':<7} | {'Failed':<7} | {'Skip':<5} | {'Tested':<10} | {'Success%':<8}"
    sorted_channels_list = sorted(stats_data.items(), key=lambda item: item[0])
    for channel_filename, stats in sorted_channels_list:
        base_channel_name = os.path.splitext(channel_filename)[0]
        if base_channel_name.replace('_', '').isalnum() and not any(c in base_channel_name for c in ['/', '\\', '.']):
            display_name = f"https://t.me/s/{base_channel_name}"
        else:
            display_name = channel_filename
        total_prepared = stats['total_prepared']
        active = stats['active']
        failed = stats['failed']
        skip = stats['skip']
        processed_for_channel = active + failed + skip
        active_plus_failed = active + failed

def sort_server_file_by_time(file_path):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        parsed_lines_data = []
        for line_content in lines:
            stripped_content = line_content.strip()
            if not stripped_content:
                parsed_lines_data.append((float('inf'), line_content)) 
                continue
            parts = stripped_content.rsplit('|', 1)
            time_val = float('inf')
            if len(parts) == 2:
                potential_time_str = parts[1].strip()
                if potential_time_str.endswith('s') and not potential_time_str.lower().startswith('reason:'):
                    time_figure_str = potential_time_str[:-1]
                    try:
                        time_val = float(time_figure_str)
                    except ValueError:
                        pass
            parsed_lines_data.append((time_val, line_content))
        parsed_lines_data.sort(key=lambda x: x[0])
        with open(file_path, 'w', encoding='utf-8') as f:
            for _, line_to_write in parsed_lines_data:
                f.write(line_to_write)
    except Exception:
        pass

def clean_vmess_links(directory):
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.txt'):
                filepath = os.path.join(root, filename)
                clean_single_file(filepath)
 
def clean_single_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        cleaned_lines = []
        modified = False
        for line in lines:
            original_line = line.strip()
            if 'vmess://' in original_line:
                cleaned_line = original_line.split('|')[0].strip()
                if cleaned_line != original_line:
                    modified = True
                cleaned_lines.append(cleaned_line + '\n')
            else:
                cleaned_lines.append(line)
        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(cleaned_lines)
    except Exception:
        pass

def run_link_categorization(base_path):
    source_dir = os.path.join(base_path, "Protocols")
    output_dir = os.path.join(source_dir, "Categorized_Servers")
    if not os.path.exists(source_dir): return
    os.makedirs(output_dir, exist_ok=True)
    categories = {
        "1_VLESS_REALITY_TCP": [], 
        "2_Trojan_TCP": [],        
        "3_VLESS_TLS_WS": [],      
        "4_WireGuard": [],         
        "5_VMess": [],
        "VLESS_ENCRYPTION_NONE": []   
    }
    for filename in os.listdir(source_dir):
        file_path = os.path.join(source_dir, filename)
        if not os.path.isfile(file_path) or not filename.endswith(".txt"): continue
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                tech_part = line.split('#')[0]
                try:
                    parsed = urlparse(tech_part)
                    scheme = parsed.scheme.lower()
                    query = parse_qs(parsed.query)
                    sec = query.get('security', [''])[0].lower()
                    net = query.get('type', ['tcp'])[0].lower()
                    encryption = query.get('encryption', [''])[0].lower()  
                    if scheme == 'vless' and sec == 'reality' and net == 'tcp':
                        categories["1_VLESS_REALITY_TCP"].append(line)
                    elif scheme == 'vless' and encryption == 'none':      
                        categories["VLESS_ENCRYPTION_NONE"].append(line)
                    elif scheme == 'trojan' and net == 'tcp':
                        categories["2_Trojan_TCP"].append(line)
                    elif scheme == 'vless' and (sec == 'tls' or net == 'ws'):
                        categories["3_VLESS_TLS_WS"].append(line)
                    elif scheme in ['wireguard', 'wg']:
                        categories["4_WireGuard"].append(line)
                    elif scheme == 'vmess':
                        categories["5_VMess"].append(line)
                except: continue
    for cat_name, links in categories.items():
        if links:
            unique_links = list(dict.fromkeys(links)) 
            out_file = os.path.join(output_dir, f"{cat_name}.txt")
            with open(out_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(unique_links) + '\n')

def format_server_link(link, country, latency, channel_name, s_info=None):
    base_link = link.split('#')[0].strip()
    clean_ch = str(channel_name).replace(".txt", "").split('|')[0].strip()
    clean_latency = str(latency).strip()
    if "://" in clean_latency or len(clean_latency) > 15:
        clean_latency = "N/A"
    port_val = "N/A"
    if s_info and s_info.get('port'):
        port_val = s_info.get('port')
    else:
        try:
            p_parsed = urlparse(base_link)
            port_val = p_parsed.port if p_parsed.port else base_link.split(':')[-1].split('?')[0]
        except: port_val = "443"
    return f"{base_link}#{clean_ch} | {country} | {clean_latency} | Port:{port_val}"

def convert_to_sni(link):
    try:
        if link.startswith('vmess://'):
            b64_part = link.replace('vmess://', '')
            decoded = urlsafe_b64decode(b64_part + '=' * (-len(b64_part) % 4)).decode('utf-8')
            data = json.loads(decoded)
            data['add'] = '127.0.0.1'
            data['port'] = '40443'
            new_b64 = urlsafe_b64encode(json.dumps(data).encode('utf-8')).decode('utf-8').rstrip('=')
            return f"vmess://{new_b64}"
        else:
            parsed = urlparse(link)
            if '@' in parsed.netloc:
                user_info = parsed.netloc.split('@')[0]
                new_netloc = f"{user_info}@127.0.0.1:40443"
            else:
                new_netloc = "127.0.0.1:40443"
            new_parsed = parsed._replace(netloc=new_netloc)
            return new_parsed.geturl()
    except Exception:
        return link

def process_channel(url):
    channel_name = extract_channel_name(url)
    if not channel_name or channel_name == "unknown_channel":
        return 0, 0
    channel_file = os.path.join(CHANNELS_DIR, f"{channel_name}.txt")
    existing_configs = load_existing_configs()
    configs = fetch_config_links(url)
    
    if configs is not None:
        extracted_ips = set(configs.get("ips", []))
        if extracted_ips:
            os.makedirs(MERGED_DIR, exist_ok=True)
            existing_ips = set()
            if os.path.exists(EXTRACTED_IPS_FILE):
                with open(EXTRACTED_IPS_FILE, 'r', encoding='utf-8') as f:
                    existing_ips = {l.strip() for l in f if l.strip()}
            new_ips = extracted_ips - existing_ips
            if new_ips:
                with open(EXTRACTED_IPS_FILE, 'a', encoding='utf-8') as f:
                    f.write('\n'.join(new_ips) + '\n')

    if configs is None or not configs.get("all"):
        Path(channel_file).touch(exist_ok=True)
        return 1 if configs is not None else 0, 0
        
    raw_fetched_links = set(configs["all"])
    formatted_links_for_channel = set()
    for link in raw_fetched_links:
        base_link = link.split('#')[0]
        formatted_links_for_channel.add(f"{base_link}#{channel_name}")
    existing_channel_cfgs = set()
    if os.path.exists(channel_file):
        with open(channel_file, 'r', encoding='utf-8') as f:
            existing_channel_cfgs = {l.strip() for l in f if l.strip()}
    new_for_channel = formatted_links_for_channel - existing_channel_cfgs
    if new_for_channel:
        updated_ch_cfgs = list(new_for_channel) + list(existing_channel_cfgs)
        with open(channel_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(updated_ch_cfgs[:MAX_CHANNEL_SERVERS]) + '\n')
    new_global_total = 0
    for proto in PATTERNS:
        proto_links = {f"{l.split('#')[0]}#{channel_name}" for l in configs.get(proto, [])}
        if not proto_links: continue
        new_global_proto = proto_links - existing_configs.get(proto, set())
        if new_global_proto:
            # کانال SNI فقط به merged_servers_sni.txt می‌ره، نه پروتکل‌ها و merged اصلی
            if channel_name not in SNI_CHANNELS:
                proto_path = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
                with open(proto_path, 'a', encoding='utf-8') as f:
                    f.write('\n'.join(new_global_proto) + '\n')
                with open(MERGED_SERVERS_FILE, 'a', encoding='utf-8') as f:
                    f.write('\n'.join(new_global_proto) + '\n')
            # همه کانال‌ها (از جمله SNI) با IP تبدیل‌شده به merged_servers_sni.txt می‌رن
            sni_links = [convert_to_sni(l) for l in new_global_proto]
            with open(MERGED_SNI_FILE, 'a', encoding='utf-8') as f:
                f.write('\n'.join(sni_links) + '\n')
            new_global_total += len(new_global_proto)
    return 1, new_global_total

def logger_thread(log_q):
    global channel_test_stats
    protocols_dir = os.path.join(TESTED_SERVERS_DIR, 'Protocols')
    tested_channels_dir = os.path.join(TESTED_SERVERS_DIR, 'Channels')
    os.makedirs(protocols_dir, exist_ok=True); os.makedirs(tested_channels_dir, exist_ok=True)
    working_file = os.path.join(TESTED_SERVERS_DIR, 'working_servers.txt')
    dead_file = os.path.join(TESTED_SERVERS_DIR, 'dead_servers.txt')
    try:
        with open(working_file, 'w', encoding='utf-8') as wf, open(dead_file, 'w', encoding='utf-8') as df:
            while True:
                record = log_q.get()
                if record is None: break
                status, s_info, msg = record
                if status == 'received': continue
                base_link = s_info.get('original_link', 'N/A').split('#')[0]
                proto = s_info.get('protocol', 'unknown').lower()
                source_file = s_info.get('source_file', 'Unknown.txt')
                channel_name = source_file.replace(".txt", "")
                if status == 'success':
                    formatted = f"{base_link}#{channel_name} | Lookup... | {msg} | Port:{s_info.get('port', 'N/A')}"
                    wf.write(f"{formatted}\n"); wf.flush()
                    with open(os.path.join(protocols_dir, f"{proto}.txt"), 'a', encoding='utf-8') as pf:
                        pf.write(f"{formatted}\n")
                    with open(os.path.join(tested_channels_dir, source_file), 'a', encoding='utf-8') as cf:
                        cf.write(f"{formatted}\n")
                elif status == 'failure':
                    df.write(f"{base_link} | Reason: {msg}\n"); df.flush()
    except Exception:
        pass

def process_tested_servers_geo():
    protocols_dir = os.path.join(TESTED_SERVERS_DIR, 'Protocols')
    if not os.path.exists(protocols_dir): return
    try: reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
    except: return
    for filename in os.listdir(protocols_dir):
        if not filename.endswith(".txt"): continue
        file_path = os.path.join(protocols_dir, filename)
        final_lines = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or '#' not in line: continue
                parts = line.split('#')
                base_link = parts[0]
                remark_parts = parts[1].split('|')
                channel_name = remark_parts[0].strip()
                latency = "N/A"
                port_info = "Port:N/A"
                for p in remark_parts:
                    if 's' in p and any(c.isdigit() for c in p) and 'Port' not in p: latency = p.strip()
                    if 'Port:' in p: port_info = p.strip()
                c_code = "Unknown"
                try:
                    u = urlparse(base_link)
                    host = u.hostname
                    if u.scheme == 'vmess':
                        b64 = u.netloc + u.path
                        data = json.loads(urlsafe_b64decode(b64 + '='*(-len(b64)%4)).decode('utf-8'))
                        host = data.get('add')
                    if host:
                        res = reader.country(host.split(':')[0])
                        c_code = res.country.iso_code or "Unknown"
                except: pass
                clean_line = f"{base_link}#{channel_name} | {c_code} | {latency} | {port_info}"
                final_lines.append(clean_line)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_lines) + '\n')
    reader.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-threads', type=int, default=MAX_THREADS)
    parser.add_argument('--skip-install', action='store_true')
    cli_args = parser.parse_args()
    MAX_THREADS = cli_args.max_threads

    ENABLE_TESTED_GEO_SORT = True  
    for directory in [PROTOCOLS_DIR, REGIONS_DIR, REPORTS_DIR, MERGED_DIR, CHANNELS_DIR,
                      V2RAY_DIR, TESTED_SERVERS_DIR, LOGS_DIR]:
        os.makedirs(directory, exist_ok=True)
    if ENABLE_EXTRACTION:
        for dir_to_clean in [CHANNELS_DIR, PROTOCOLS_DIR, MERGED_DIR]:
            if os.path.exists(dir_to_clean):
                shutil.rmtree(dir_to_clean)
            os.makedirs(dir_to_clean, exist_ok=True)
        if os.path.exists(MERGED_SERVERS_FILE):
             os.remove(MERGED_SERVERS_FILE)
        if os.path.exists(MERGED_SNI_FILE):
             os.remove(MERGED_SNI_FILE)
        channels_file_path = CHANNELS_FILE
        try:
            if not os.path.exists(channels_file_path):
                logging.error(f"Channels file not found: {channels_file_path}")
                sys.exit(1)
            with open(channels_file_path, 'r', encoding='utf-8') as f:
                raw_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            normalized_urls = []
            for url in raw_urls:
                norm_url = normalize_telegram_url(url)
                if norm_url and norm_url not in normalized_urls: normalized_urls.append(norm_url)
            normalized_urls.sort()
        except Exception as e:
            logging.error(f"Error reading channels: {e}")
            sys.exit(1)

        total_channels_count = len(normalized_urls)
        processed_ch_count = 0; total_new_added = 0; failed_fetches = 0
        for idx, ch_url in enumerate(normalized_urls, 1):
            success_flag, new_srvs = process_channel(ch_url)
            if success_flag == 1: processed_ch_count += 1; total_new_added += new_srvs
            else: failed_fetches += 1
            if idx % BATCH_SIZE == 0 and idx < total_channels_count:
                time.sleep(SLEEP_TIME)

    if ENABLE_GEO_LOOKUP:
        country_data_map = process_geo_data()
    else:
        country_data_map = {}

    if ENABLE_REPORTING:
        try:
            extraction_channel_stats = get_channel_stats()
            save_extraction_data(extraction_channel_stats, country_data_map)
        except Exception:
            pass

    if ENABLE_TESTING:
        clean_directory(TESTED_SERVERS_DIR) 
        os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Protocols'), exist_ok=True)
        os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Channels'), exist_ok=True)
        os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Regions'), exist_ok=True)
        all_servers_to_test = []
        servers_read_total = 0; parsing_errors = defaultdict(int); proto_load_counts = defaultdict(int); skipped_disabled_count = 0
        if not os.path.exists(CHANNELS_DIR):
            logging.error(f"Directory missing: {CHANNELS_DIR}")
            sys.exit(1)
        source_channel_files = [f for f in os.listdir(CHANNELS_DIR) if f.endswith('.txt')]
        if not source_channel_files:
            logging.error("No channel files to test.")
            sys.exit(1)
        for ch_filename in source_channel_files:
            _ = channel_test_stats[ch_filename] 
            servers_from_file = read_links_from_file(os.path.join(CHANNELS_DIR, ch_filename))
            servers_read_total += len(servers_from_file)
            for link_str in servers_from_file:
                try:
                    parsed_url_scheme = urlparse(link_str).scheme.lower()
                    if not parsed_url_scheme: parsing_errors["no_scheme"] +=1; continue
                    if parsed_url_scheme not in ENABLED_PROTOCOLS_TO_TEST or not ENABLED_PROTOCOLS_TO_TEST[parsed_url_scheme]:
                        if parsed_url_scheme not in ENABLED_PROTOCOLS_TO_TEST: parsing_errors[f"unsupported_{parsed_url_scheme}"] += 1
                        else: parsing_errors["disabled_protocol"] += 1; skipped_disabled_count += 1
                        continue
                    server_info_dict = None
                    parser_func = {
                        'vless': parse_vless_link, 'vmess': parse_vmess_link,
                        'trojan': parse_trojan_link, 'ss': parse_ss_link
                    }.get(parsed_url_scheme)
                    if parser_func:
                        try: server_info_dict = parser_func(link_str)
                        except ValueError as ve:
                            parsing_errors[f"parse_invalid_{parsed_url_scheme}"] += 1
                        except Exception as pe_inner:
                            parsing_errors[f"parse_general_error_{parsed_url_scheme}"] += 1
                    else:
                        parsing_errors[f"no_parser_for_enabled_{parsed_url_scheme}"] += 1
                    if server_info_dict:
                        server_info_dict['source_file'] = ch_filename
                        all_servers_to_test.append(server_info_dict)
                        proto_load_counts[parsed_url_scheme] += 1
                        channel_test_stats[ch_filename]['total_prepared'] += 1 
                except Exception as outer_ex:
                    parsing_errors["outer_processing_loop"] += 1

        if not all_servers_to_test:
            logging.error("No valid servers found to test.")
            sys.exit(1)

        if ENABLE_V2RAY_SETUP and not cli_args.skip_install:
            installed_ver = check_v2ray_installed()
            latest_ver = get_latest_version()
            if not installed_ver or (latest_ver and installed_ver != latest_ver and installed_ver != "unknown"):
                install_v2ray()
                installed_ver = check_v2ray_installed()
                if not installed_ver:
                    logging.error("V2Ray not found after install attempt.")
                    sys.exit(1)
        else:
            if not check_v2ray_installed():
                logging.error("V2Ray not found. Install it or enable ENABLE_V2RAY_SETUP.")
                sys.exit(1)

        test_log_queue = queue.Queue()
        logger_t = threading.Thread(target=logger_thread, args=(test_log_queue,), name="LoggerThread", daemon=True)
        logger_t.start()
        for s_info_item in all_servers_to_test:
            test_log_queue.put(('received', s_info_item, None))
        with ThreadPoolExecutor(max_workers=MAX_THREADS, thread_name_prefix="Tester") as executor:
            futures_list = []
            for s_info_item in all_servers_to_test:
                try:
                    local_port = get_next_port()
                    config_data = generate_config(s_info_item, local_port)
                    futures_list.append(executor.submit(test_server, s_info_item, config_data, local_port, test_log_queue))
                except Exception as e_prep:
                    s_info_item['source_file'] = s_info_item.get('source_file', 'unknown_channel.txt')
                    test_log_queue.put(('skip', s_info_item, f"Prep error: {str(e_prep)[:100]}"))
            for fut in futures_list:
                try: fut.result()
                except Exception: pass
        tested_servers_dir_clean = 'Tested_Servers'  
        clean_vmess_links(tested_servers_dir_clean)
        test_log_queue.put(None) 
        logger_t.join(timeout=30) 

    if ENABLE_TESTED_GEO_SORT:
        process_tested_servers_geo()

    if ENABLE_CATEGORIZATION:
        run_link_categorization("Servers")
        if ENABLE_TESTING or os.path.exists(TESTED_SERVERS_DIR):
            run_link_categorization(TESTED_SERVERS_DIR)

    if ENABLE_PATT_EDITION:
        generate_patt_edition()
