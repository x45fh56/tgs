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
from urllib.parse import urlparse, parse_qs, unquote
from base64 import urlsafe_b64decode, urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
from collections import defaultdict

# Fix for "sys.stdout.reconfigure" error in older python versions or strict linters
# We add '# type: ignore' to silence Pylance since we verify it with hasattr at runtime
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8') # type: ignore

# Organized directory structure for data storage
PROTOCOLS_DIR = os.path.join("Servers", "Protocols")
REGIONS_DIR = os.path.join("Servers", "Regions")
REPORTS_DIR = os.path.join("logs")
MERGED_DIR = os.path.join("Servers", "Merged")
CHANNELS_DIR = os.path.join("Servers", "Channels")
CHANNELS_FILE = "data/telegram_sources.txt"
LOG_FILE = os.path.join(REPORTS_DIR, "extraction_report.log")
GEOIP_DATABASE_PATH = Path("data/db/GeoLite2-Country.mmdb")
MERGED_SERVERS_FILE = os.path.join(MERGED_DIR, "merged_servers.txt")

# --- Control Flags ---
# Set these to True or False to enable or disable parts of the script
ENABLE_EXTRACTION = True  # Part 1: Scrape servers from Telegram sources
ENABLE_GEO_LOOKUP = False  # Part 2: Classify scraped servers by country 
ENABLE_REPORTING = False   # Part 3: Generate a report after extraction/GeoIP
ENABLE_TESTING = False # Part 4: Test the servers for connectivity
ENABLE_V2RAY_SETUP = False     # Download/update V2Ray executable if testing is enabled
ENABLE_TESTED_GEO_SORT = False  
ENABLE_CATEGORIZATION = True  

SLEEP_TIME = 1
BATCH_SIZE = 10
FETCH_CONFIG_LINKS_TIMEOUT = 15
MAX_CHANNEL_SERVERS = 100
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
ENABLED_PROTOCOLS = {
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
            logging.info(f"Selectively cleaning V2Ray directory: {dir_path}")
            for filename in os.listdir(dir_path):
                file_path = os.path.join(dir_path, filename)
                if filename == V2RAY_BIN or filename.lower().endswith(('.dat', '.db', 'geoip.dat', 'geosite.dat')):
                    logging.debug(
                        f"Skipping deletion of essential V2Ray file: {file_path}")
                    continue
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    logging.error(
                        f"Failed to delete {file_path} during V2Ray dir selective clean: {str(e)}")
            os.makedirs(dir_path, exist_ok=True)
            return
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}: {str(e)}")
        logging.info(f"Cleaned directory: {dir_path}")
    else:
        os.makedirs(dir_path, exist_ok=True)
        logging.info(f"Created directory: {dir_path}")

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
    """Normalize various Telegram URL formats to https://t.me/s/ format.

    Args:
        url: Input URL string to normalize

    Returns:
        Normalized URL in https://t.me/s/ format or empty string for invalid URLs
    """
    if not url:
        return ""

    url = url.strip()

    # Handle bare username cases (e.g., "Free_HTTPCustom")
    if not any(url.startswith(prefix) for prefix in ["http://", "https://", "t.me/", "@"]):
        if "/" not in url:  # Confirm it's just a channel name without paths
            return f"https://t.me/s/{url}"

    # Convert t.me/ links to https://t.me/s/
    if url.startswith("t.me/"):
        url = f"https://{url}"

    # Convert @username format to https://t.me/s/username
    if url.startswith("@"):
        return f"https://t.me/s/{url[1:]}"

    # Process full https://t.me/ URLs
    if url.startswith("https://t.me/"):
        parts = url.split('/')
        if len(parts) >= 4:
            channel_candidate = parts[3]
            if channel_candidate == 's':
                if len(parts) > 4 and parts[4]:  # Valid /s/ link
                    return url
                return ""  # Invalid /s/ link like https://t.me/s/
            else:  # Convert to /s/ format
                # Handle cases like https://t.me/channelname/123 by taking only channelname
                return f"https://t.me/s/{parts[3]}"
        return ""  # Invalid URL structure

    return url  # Return as-is if already in /s/ format or other valid format


def extract_channel_name(url):
    try:
        parsed_url = urlparse(url)
        path_parts = [part for part in parsed_url.path.split('/') if part]
        if path_parts:
            if path_parts[0] == 's' and len(path_parts) > 1:
                return path_parts[1]
            return path_parts[0]
    except Exception:
        pass
    # Fallback for simple names or if parsing fails badly
    name_candidate = url.split('/')[-1] if '/' in url else url
    # Remove query parameters or fragments from the name if they got included
    name_candidate = name_candidate.split('?')[0].split('#')[0]
    return name_candidate if name_candidate else "unknown_channel"


def count_servers_in_file(file_path):
    if not os.path.exists(file_path):
        return 0
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return len([line for line in f if line.strip() and not line.strip().startswith('#')])
    except Exception as e:
        logging.error(f"❌ Error counting servers in {file_path}: {e}")
        return 0


def get_current_counts():
    counts = {}
    for proto in PATTERNS:
        counts[proto] = count_servers_in_file(
            os.path.join(PROTOCOLS_DIR, f"{proto}.txt"))
    counts['total'] = count_servers_in_file(MERGED_SERVERS_FILE)
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
            channel_stats[channel_file.stem] = count_servers_in_file(
                channel_file)
    return channel_stats


def save_extraction_data(channel_stats_data, country_data_map):
    current_counts, country_stats_map_local = get_current_counts()
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(LOG_FILE, 'w', encoding='utf-8') as log:
            log.write("=== Country Statistics ===\n")
            log.write(f"Total Servers (Merged): {current_counts['total']}\n")
            log.write(
                f"Successful Geo-IP Resolutions: {current_counts['successful']}\n")
            log.write(
                f"Failed Geo-IP Resolutions: {current_counts['failed']}\n")
            for country, count in sorted(country_stats_map_local.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{country:<20} : {count}\n")
            log.write("\n=== Server Type Summary ===\n")
            valid_protocols = {p: current_counts.get(p, 0) for p in PATTERNS}
            for proto, count in sorted(valid_protocols.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{proto.upper():<20} : {count}\n")
            log.write("\n=== Channel Statistics (Extraction) ===\n")
            if not channel_stats_data:
                log.write("No channel data available.\n")
            else:
                for channel, total in sorted(channel_stats_data.items(), key=lambda x: x[1], reverse=True):
                    log.write(f"{channel:<30}: {total}\n")
    except Exception as e:
        logging.error(f"❌ Error writing extraction report to {LOG_FILE}: {e}")


def fetch_config_links(url):
    logging.info(f"Fetching configs from: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(
            url, timeout=FETCH_CONFIG_LINKS_TIMEOUT, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        message_containers = soup.select(
            'div.tgme_widget_message_bubble, div.tgme_widget_message_text')
        code_blocks = soup.find_all(['code', 'pre'])
        configs = {proto: set() for proto in PATTERNS}
        configs["all"] = set()
        for code_tag in code_blocks:
            clean_text = re.sub(r'(^`{1,3}|`{1,3}$)', '', code_tag.get_text(
                '\n').strip(), flags=re.MULTILINE).strip()
            for line in clean_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                for proto, pattern in PATTERNS.items():
                    valid_matches = set()
                    matches = re.findall(pattern, line)
                    if matches:
                        valid_matches = {
                            m for m in matches if urlparse(m).scheme == proto}
                    if valid_matches:
                        configs[proto].update(valid_matches)
                        configs["all"].update(valid_matches)
        for container in message_containers:
            for line in container.get_text(separator='\n', strip=True).splitlines():
                line = line.strip()
                if not line:
                    continue
                for proto, pattern in PATTERNS.items():
                    valid_matches = set()
                    matches = re.findall(pattern, line)
                    if matches:
                        valid_matches = {
                            m for m in matches if urlparse(m).scheme == proto}
                    if valid_matches:
                        configs[proto].update(valid_matches)
                        configs["all"].update(valid_matches)
        final_configs = {k: list(v) for k, v in configs.items() if v}
        logging.info(
            f"Found {len(final_configs.get('all', []))} potential configs in {url}")
        return final_configs
    except requests.exceptions.Timeout:
        logging.error(f"Timeout fetching {url}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Connection error for {url}: {e}")
        return None
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
            except Exception as e:
                logging.error(f"Error reading {p_file}: {e}")
    m_file = MERGED_SERVERS_FILE
    if os.path.exists(m_file):
        try:
            with open(m_file, 'r', encoding='utf-8') as f:
                existing['merged'] = {l.strip() for l in f if l.strip()}
        except Exception as e:
            logging.error(f"Error reading {m_file}: {e}")
    return existing


def trim_file(file_path, max_lines):
    if not os.path.exists(file_path) or max_lines <= 0:
        return
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        valid_lines = [line for line in lines if line.strip()]
        if len(valid_lines) > max_lines:
            logging.info(
                f"Trimming {file_path} from {len(valid_lines)} to {max_lines} lines.")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(l if l.endswith('\n') else l +
                             '\n' for l in valid_lines[:max_lines])
    except Exception as e:
        logging.error(f"Error trimming {file_path}: {e}")




def download_geoip_database():
    GEOIP_URL = "https://git.io/GeoLite2-Country.mmdb"
    GEOIP_DIR = GEOIP_DATABASE_PATH.parent

    logging.info(f"Attempting to download GeoIP database from {GEOIP_URL}...")
    try:
        GEOIP_DIR.mkdir(parents=True, exist_ok=True)
        with requests.get(GEOIP_URL, timeout=60, stream=True) as response:
            response.raise_for_status()
            with open(GEOIP_DATABASE_PATH, 'wb') as f:
                shutil.copyfileobj(response.raw, f)

        if GEOIP_DATABASE_PATH.stat().st_size > 1024 * 1024: # Check if > 1MB
            logging.info("✅ GeoLite2 database downloaded successfully.")
            return True
        else:
            logging.error("❌ Downloaded GeoIP database seems too small. Deleting.")
            GEOIP_DATABASE_PATH.unlink(missing_ok=True)
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Failed to download GeoIP database: {e}")
        GEOIP_DATABASE_PATH.unlink(missing_ok=True)
        return False
    except Exception as e:
        logging.error(f"❌ An unexpected error occurred during GeoIP download: {e}")
        GEOIP_DATABASE_PATH.unlink(missing_ok=True)
        return False


def process_geo_data():
    if not GEOIP_DATABASE_PATH.exists() or GEOIP_DATABASE_PATH.stat().st_size < 1024 * 1024:
        if not download_geoip_database():
            logging.error("❌ Cannot perform GeoIP: Database download failed.")
            return {}
    geo_reader = None # Initialize to None
    try:
        geo_reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
    except Exception as e:
        logging.error(f"❌ Error opening GeoIP DB: {e}")
        return {}

    country_configs = defaultdict(list)
    failed_lookups = 0
    processed = 0

    if os.path.exists(REGIONS_DIR):
        for rf in Path(REGIONS_DIR).glob("*.txt"):
            try:
                rf.unlink()
            except OSError as e:
                logging.error(f"Error deleting old region file {rf}: {e}")
    else:
        os.makedirs(REGIONS_DIR, exist_ok=True)

    configs_for_geoip = []
    if os.path.exists(MERGED_SERVERS_FILE):
        try:
            with open(MERGED_SERVERS_FILE, 'r', encoding='utf-8') as f:
                configs_for_geoip = [l.strip() for l in f if l.strip()]
        except Exception as e:
            logging.error(f"Error reading merged servers for GeoIP: {e}")

    if not configs_for_geoip:
        logging.warning("No merged configs found to perform GeoIP analysis.")
        if geo_reader: geo_reader.close()
        return {}

    for config_link in configs_for_geoip:
        processed += 1
        ip_address = None
        country_code = "Unknown"
        try:
            parsed_link = urlparse(config_link)
            hostname = parsed_link.hostname
            if not hostname: # Skip if no hostname
                failed_lookups += 1
                continue

            if parsed_link.scheme in ['vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'ss']:
                ip_address = hostname
            elif parsed_link.scheme == 'vmess':
                try:
                    # Ensure padding for base64 decoding
                    b64_payload = parsed_link.netloc + parsed_link.path
                    decoded_payload = urlsafe_b64decode(b64_payload + '=' * ((4 - len(b64_payload) % 4) % 4)).decode('utf-8')
                    vmess_data = json.loads(decoded_payload)
                    ip_address = vmess_data.get('add')
                except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as e:
                    logging.debug(f"VMess decoding error for GeoIP on {config_link[:30]}...: {e}")
                    failed_lookups +=1 # Count as failed if we can't get IP
                    continue # Skip to next config

            if ip_address:
                # Check if ip_address is actually an IP or still a domain
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
                    # If it's a domain, we can't directly use geoip2.database.Reader
                    # This GeoIP library expects an IP address. Domain resolution is out of its scope.
                    # For simplicity, we'll mark as Unknown or implement DNS resolution separately.
                    # For now, marking as Unknown for non-IP hostnames.
                    # logging.debug(f"Hostname '{ip_address}' is not an IP. Skipping GeoIP, marking as Unknown.")
                    country_code = "Domain" # Or keep "Unknown", "Domain" indicates why
                    # failed_lookups += 1 # Optionally count this
                else:
                    try:
                        response = geo_reader.country(ip_address)
                        country_code = response.country.iso_code or response.country.name or "Unknown"
                    except geoip2.errors.AddressNotFoundError:
                        # logging.debug(f"GeoIP: Address {ip_address} not found in database.")
                        country_code = "Unknown" # IP not in DB
                        failed_lookups +=1
                    except Exception as geo_e:
                        logging.warning(f"GeoIP lookup error for IP {ip_address}: {geo_e}")
                        country_code = "Unknown" # Other GeoIP error
                        failed_lookups +=1
            else: # No IP could be extracted
                failed_lookups += 1
                country_code = "Unknown"

        except Exception as e: # Catch errors from URL parsing or other logic
            logging.warning(f"Error processing config for GeoIP '{config_link[:30]}...': {e}")
            failed_lookups += 1
            country_code = "Unknown"

        country_configs[country_code].append(config_link)

    if geo_reader:
        geo_reader.close()

    final_country_counts = {}
    for country_code, config_list in country_configs.items():
        final_country_counts[country_code] = len(config_list)
        try:
            # Sanitize country_code for filename
            safe_country_name = "".join(c if c.isalnum() else "_" for c in country_code)
            with open(os.path.join(REGIONS_DIR, f"{safe_country_name}.txt"), 'w', encoding='utf-8') as f:
                # Trim if necessary before writing
                f.write('\n'.join(config_list[:MAX_REGION_SERVERS]) + '\n')
        except Exception as e:
            logging.error(f"Error writing region file for {country_code}: {e}")

    logging.info(
        f"GeoIP analysis done. Total Processed: {processed}, Successful Lookups: {processed - failed_lookups}, Failed/Unknown: {failed_lookups}")
    return dict(final_country_counts)


class CleanFormatter(logging.Formatter):
    def format(self, record):
        if hasattr(record, 'clean_output'):
            if record.levelno == logging.INFO:
                return f"{record.msg}"
            elif record.levelno >= logging.WARNING:
                return f"{record.levelname}: {record.msg}"
        return super().format(record)

# --- Logging Setup ---
# ایجاد پوشه لاگ بلافاصله قبل از استفاده (برای جلوگیری از خطا)
os.makedirs(LOGS_DIR, exist_ok=True)

if not logging.getLogger().hasHandlers():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    cf = CleanFormatter()
    ch.addFilter(lambda r: setattr(r, 'clean_output', True) or True)
    ch.setFormatter(cf)
    logger.addHandler(ch)
    
    # حالا که پوشه ساخته شده، FileHandler بدون خطا اجرا می‌شود
    log_path = os.path.join(LOGS_DIR, 'testing_debug.log')
    fh = logging.FileHandler(log_path, encoding='utf-8')
    ff = logging.Formatter('%(asctime)s-%(levelname)s-%(threadName)s- %(message)s')
    fh.setFormatter(ff)
    logger.addHandler(fh)
# --- FIX: Direct usage of urllib3 to disable warnings ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


current_port = START_PORT
port_lock = threading.Lock()


def get_next_port():
    global current_port
    with port_lock:
        port = current_port
        current_port += 1
    return port


def read_links_from_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
    except FileNotFoundError:
        logging.debug(f"File not found during read: {file_path}")
        return []
    except Exception as e:
        logging.error(f"Error reading links from {file_path}: {e}")
        return []


def parse_vless_link(link):
    parsed = urlparse(link)
    uuid = parsed.username
    query = parse_qs(parsed.query)
    hostname = parsed.hostname
    if not (parsed.scheme == 'vless' and hostname and uuid and
            re.match(r'^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$', uuid, re.I)):
        raise ValueError(f"Invalid VLESS link structure: {link}")
    port = parsed.port or (443 if query.get('security', [''])[
                           0] in ['tls', 'reality'] else 80)
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

    # Prioritize 'host' over 'add' if 'add' looks invalid, then fall back.
    # This handles cases where 'add' is obfuscated.
    address = data.get('add', '')
    if not re.match(r"^[a-zA-Z0-9.-]+$", address): # Simple check for valid hostname chars
        address = data.get('host', '') # Fallback to 'host' field
        if not address: # If host is also empty/invalid, this link is unusable
            raise ValueError(f"VMess 'add' field is invalid and no fallback 'host' found: {data.get('add')}")
    
    port = int(data.get('port', 0))
    uuid = data.get('id')
    if not (address and port and uuid):
        raise ValueError(f"VMess missing address/port/id in {link}")

    # --- FINAL FIX: Rebuild and Sanitize the VMess link completely ---
    
    # 1. Create a clean dictionary with only standard, necessary fields.
    clean_data = {
        "v": "2",
        # 2. Sanitize the 'ps' field to avoid client import issues.
        "ps": f"vmess-{address}-{port}",
        "add": address,
        "port": str(port), # Port must be a string in the JSON
        "id": uuid,
        "aid": str(data.get("aid", 0)),
        "net": data.get("net", "tcp") or "tcp",
        "type": data.get("type", "none") or "none", # Often "none" for tcp, "" for ws/grpc
        "host": data.get("host", ""),
        "path": data.get("path", ""),
        "tls": data.get("tls", "") or "", # "tls" or ""
        "sni": data.get("sni", ""),
        "alpn": data.get("alpn", ""),
        "fp": data.get("fp", ""),
        "scy": data.get("scy", "auto") or "auto" # Add security method
    }
    
    # Remove empty keys that are not essential, for a cleaner link
    keys_to_remove = [k for k, v in clean_data.items() if v == "" and k not in ["ps", "add", "port", "id", "net", "tls"]]
    for k in keys_to_remove:
        del clean_data[k]
        
    # 3. Re-encode the clean dictionary into a standard Base64 string.
    clean_json_str = json.dumps(clean_data, separators=(',', ':'), sort_keys=True)
    rebuilt_b64 = urlsafe_b64encode(clean_json_str.encode('utf-8')).decode('utf-8').rstrip("=")
    rebuilt_link = f"vmess://{rebuilt_b64}"
    # --- END OF FIX ---

    # Return the rebuilt_link as the 'original_link' to be used in all output files.
    # The other fields are for the internal tester.
    return {
        'original_link': rebuilt_link, 
        'protocol': 'vmess', 
        'uuid': uuid, 
        'host': address, # Use the validated address for testing
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
    name = unquote(parsed.fragment) if parsed.fragment else f"ss_{host}" # Decode fragment
    userinfo_raw = parsed.username
    method, password = None, None

    # Standard SIP002: base64(method:password)@host:port#name
    # If userinfo exists (part before @), it's likely base64 encoded method:password
    if userinfo_raw:
        try:
            # Try decoding userinfo_raw as base64
            decoded_userinfo = urlsafe_b64decode(userinfo_raw + '=' * ((4 - len(userinfo_raw) % 4) % 4)).decode('utf-8')
            if ':' in decoded_userinfo:
                method, password = decoded_userinfo.split(':', 1)
            else: # If not base64 or no colon, it might be plain method:password (less common for userinfo)
                 raise ValueError("Decoded userinfo did not contain ':'")
        except (binascii.Error, UnicodeDecodeError, ValueError):
             # Fallback: if userinfo_raw is not valid base64 or doesn't decode to "method:password",
             # assume it's plain "method:password" if it contains a colon.
             if ':' in userinfo_raw: # This assumes userinfo_raw was NOT b64 but plain text
                  method, password = userinfo_raw.split(':',1)
             else:
                  raise ValueError(f"Could not parse method:password from userinfo '{userinfo_raw}' in {link}")

    # Alternative format: ss://base64(method:password:host:port)#name (less common with netloc)
    # Or ss://base64(method:password) where host:port is separate
    # For now, we primarily rely on userinfo for method:password if @ is present.

    # If userinfo was not present or parsing failed, there's an issue.
    if method is None or password is None:
        # Check if the entire netloc (excluding port if specified by : after hostname) is base64(method:password)
        # This handles ss://BASE64PART where BASE64PART is method:password, and host:port are separate in the URL.
        # This logic is tricky because host and port are already parsed by urlparse.
        # The original code had a complex fallback, let's simplify based on common patterns.
        # Most common is base64(method:password) in username part.
        raise ValueError(f"Could not extract method/password for SS link: {link}. Userinfo: '{userinfo_raw}'")

    return {'original_link': link, 'protocol': 'shadowsocks', 'method': method, 'password': password,
            'host': host, 'port': int(port), 'network': 'tcp', 'name': name}


def generate_config(s_info, l_port):
    cfg = {
        "log": {"access": None, "error": None, "loglevel": "warning"}, # Added loglevel
        "inbounds": [{
            "port": l_port, "listen": "127.0.0.1", "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": [{
            "protocol": s_info['protocol'], "settings": {},
            "streamSettings": {
                "network": s_info.get('network', 'tcp'),
                "security": s_info.get('security', 'none') # Default to 'none' if not present
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
    elif s_info['protocol'] == 'shadowsocks': # V2Ray uses 'shadowsocks' not 'ss' in config
        out_s["servers"] = [{"address": s_info['host'], "port": s_info['port'],
                             "method": s_info['method'], "password": s_info['password'], "ota": False}]

    # Stream settings
    current_security = stream_s.get('security', 'none') # Get current security setting

    if current_security == 'tls':
        tls_settings = {"serverName": s_info.get('sni', s_info['host']), "allowInsecure": True}
        if s_info.get('alpn'):
            tls_settings["alpn"] = s_info['alpn']
        if s_info.get('fp') and s_info.get('fp') != 'none' and s_info.get('fp') != '': # Check fp
            tls_settings["fingerprint"] = s_info['fp']
        stream_s['tlsSettings'] = tls_settings
    elif current_security == 'reality':
        if not s_info.get('pbk') or not s_info.get('fp'):
            raise ValueError("REALITY config missing 'pbk' (publicKey) or 'fp' (fingerprint)")
        stream_s['realitySettings'] = {
            "show": False, "fingerprint": s_info['fp'],
            "serverName": s_info.get('sni', s_info['host']), # SNI is crucial for REALITY
            "publicKey": s_info['pbk'],
            "shortId": s_info.get('sid', ''),
            "spiderX": s_info.get('spx', '/') # spx is not standard VLESS, but some tools use it
        }

    current_network = stream_s.get('network', 'tcp')
    if current_network == 'ws':
        stream_s['wsSettings'] = {
            "path": s_info.get('ws_path', '/'),
            "headers": {"Host": s_info.get('ws_host', s_info.get('sni', s_info['host']))}
        }
    # Add other network types like grpc if needed
    # elif current_network == 'grpc':
    #     stream_s['grpcSettings'] = {
    #         "serviceName": s_info.get('serviceName', '') # Get from link if available
    #     }

    # Clean up streamSettings: remove security if none, remove specific settings if not applicable
    if stream_s.get('security') == 'none':
        del stream_s['security'] # V2Ray doesn't need "security": "none" explicitly usually
        # Remove tlsSettings or realitySettings if security was none
        stream_s.pop('tlsSettings', None)
        stream_s.pop('realitySettings', None)


    cfg['outbounds'][0]['streamSettings'] = {
        k: v for k, v in stream_s.items() if v is not None or k in ('network') # Keep network even if tcp
    }
    # If network is tcp (default) and no other stream settings, streamSettings can be minimal or omitted by V2Ray
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
        # Use Popen for non-blocking start, then manage its lifecycle
        proc = subprocess.Popen(cmd, cwd=V2RAY_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                encoding='utf-8', errors='ignore', # Ignore decoding errors from v2ray output
                                close_fds=(platform.system() != 'Windows'))

        # Wait a short time for V2Ray to start or fail quickly
        time.sleep(2) # Initial wait for V2Ray to bind port or exit

        if proc.poll() is not None: # Check if process terminated
            stderr_output = ""
            if proc.stderr:
                stderr_output = proc.stderr.read(500) # Read some stderr
            raise RuntimeError(
                f"V2Ray exited prematurely (code {proc.returncode}). Config: {json.dumps(cfg['outbounds'][0])}. Stderr: {stderr_output[:200]}...")

        # If V2Ray seems to be running, proceed with the test
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
            r_time = time.monotonic() - start_t_req # Record time even on timeout
            err_msg = f"Request Timeout ({r_time:.1f}s > {REQUEST_TIMEOUT}s)"
        except requests.exceptions.ProxyError as pe:
            err_msg = f"Proxy Error: {str(pe)[:100]}"
        except requests.exceptions.RequestException as e: # Catch other request errors
            err_msg = f"Request Exception: {str(e)[:100]}"

        log_level = logging.INFO if success else logging.WARNING
        log_symbol = "✅" if success else "⚠️"
        # Shorten link for logging if too long
        display_link = s_info.get('original_link', 'N/A')
        if len(display_link) > 70 : display_link = display_link[:67] + "..."

        logging.log(log_level, f"{log_symbol} Test {'Success' if success else 'Failed'} ({r_time:.2f}s) - "
                    f"{s_info.get('protocol')} {s_info.get('host')}:{s_info.get('port')} | {err_msg} | Link: {display_link}")

    except Exception as e: # Catch errors from V2Ray setup, Popen, etc.
        err_msg = f"Test Setup/Runtime Error: {str(e)[:150]}"
        logging.error(f"❌ Error testing {s_info.get('host', 'N/A')} ({s_info.get('original_link', 'N/A')[:30]}...): {err_msg}",
                      exc_info=logger.isEnabledFor(logging.DEBUG)) # Show full exc_info if DEBUG
    finally:
        if proc and proc.poll() is None: # If process is still running
            try:
                proc.terminate()
                proc.wait(timeout=3) # Wait for terminate
            except subprocess.TimeoutExpired:
                proc.kill() # Force kill if terminate fails
                proc.wait(timeout=2) # Wait for kill
            except Exception: # Catch any other errors during termination
                pass
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.remove(cfg_path)
            except Exception: # Ignore errors removing temp config
                pass
        log_q.put(('success' if success else 'failure', s_info,
                  f"{r_time:.2f}s" if success else err_msg))


def check_v2ray_installed():
    v2ray_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
    if not os.path.exists(v2ray_path):
        logging.debug("V2Ray executable not found.")
        return None
    try:
         if platform.system() != "Windows" and not os.access(v2ray_path, os.X_OK):
              logging.warning(f"V2Ray found but not executable, attempting chmod: {v2ray_path}")
              try: os.chmod(v2ray_path, 0o755)
              except Exception as chmod_err:
                   logging.error(f"Failed to make V2Ray executable: {chmod_err}"); return None

         logging.debug(f"Checking V2Ray version using: {v2ray_path}")
         result = subprocess.run(
             [v2ray_path, 'version'],
             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
             encoding='utf-8', check=True, cwd=V2RAY_DIR
         )
         output = result.stdout.strip()
         match = re.search(r'V2Ray\s+([\d.]+)', output)
         if match: return match.group(1)
         else: logging.warning(f"Could not parse V2Ray version: {output}"); return "unknown"
    except FileNotFoundError: logging.debug("V2Ray command failed: File not found."); return None
    except subprocess.CalledProcessError as e: logging.error(f"V2Ray version error {e.returncode}. Stderr: {e.stderr}"); return None
    except Exception as e: logging.error(f"Unexpected V2Ray version check error: {e}"); return None


_latest_release_data_cache = None
_cache_lock = threading.Lock()
_cache_time = 0
CACHE_DURATION = 300 # 5 minutes

def get_github_latest_release_data(force_refresh=False):
    global _latest_release_data_cache, _cache_time
    with _cache_lock:
        if not force_refresh and _latest_release_data_cache and (time.time() - _cache_time < CACHE_DURATION):
            logging.debug("Using cached GitHub release data.")
            return _latest_release_data_cache
        try:
            logging.debug("Fetching latest V2Ray release data from GitHub API...")
            response = requests.get(
                'https://api.github.com/repos/v2fly/v2ray-core/releases/latest',
                timeout=15 # Increased timeout
            )
            response.raise_for_status()
            _latest_release_data_cache = response.json()
            _cache_time = time.time()
            logging.debug("Successfully fetched and cached GitHub release data.")
            return _latest_release_data_cache
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch latest release data from GitHub: {e}")
            # If cache exists but is stale, return stale data instead of None immediately
            if _latest_release_data_cache:
                logging.warning("Returning stale GitHub cache due to fetch error.")
                return _latest_release_data_cache
            return None
        except Exception as e: # Catch other potential errors like JSONDecodeError
            logging.error(f"Unexpected error fetching/parsing GitHub release data: {e}")
            if _latest_release_data_cache:
                logging.warning("Returning stale GitHub cache due to unexpected error.")
                return _latest_release_data_cache
            return None

def get_latest_version():
    data = get_github_latest_release_data()
    if data:
        tag_name = data.get('tag_name')
        if tag_name and tag_name.startswith('v'):
            return tag_name.lstrip('v')
        logging.warning(f"Could not find valid tag_name in GitHub API response: {tag_name}")
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
    logging.warning(f"Asset '{asset_name}' not found in release assets.")
    return None


def install_v2ray():
    try:
        os_type = platform.system().lower()
        machine = platform.machine().lower()
        logging.info(f"Detected OS: {os_type}, Machine: {machine}")

        asset_name = None
        if os_type == 'linux':
            if 'aarch64' in machine or 'arm64' in machine: asset_name = 'v2ray-linux-arm64-v8a.zip'
            elif 'armv7' in machine: asset_name = 'v2ray-linux-arm32-v7a.zip'
            elif '64' in machine: asset_name = 'v2ray-linux-64.zip'
            else: asset_name = 'v2ray-linux-32.zip'
        elif os_type == 'windows':
            if '64' in machine: asset_name = 'v2ray-windows-64.zip'
            else: asset_name = 'v2ray-windows-32.zip'
        # Add macOS if needed:
        # elif os_type == 'darwin':
        #     if 'arm64' in machine: asset_name = 'v2ray-macos-arm64.zip'
        #     else: asset_name = 'v2ray-macos-64.zip'

        if not asset_name:
            logging.critical(f"Unsupported OS/Architecture: {os_type}/{machine}"); sys.exit(1)

        logging.info(f"Determined V2Ray asset: {asset_name}")

        # Try to refresh cache if asset not found with current cache
        if not asset_name_exists(asset_name):
            logging.info(f"Asset {asset_name} not found, forcing GitHub cache refresh.")
            get_github_latest_release_data(force_refresh=True) # Force refresh
            if not asset_name_exists(asset_name): # Check again
                logging.critical(f"Asset {asset_name} still not found after cache refresh. Check V2Fly releases."); sys.exit(1)


        download_url = get_asset_download_url(asset_name)
        if not download_url:
            logging.critical(f"Could not find download URL for {asset_name}."); sys.exit(1)

        logging.info(f"Downloading V2Ray from: {download_url}")
        os.makedirs(V2RAY_DIR, exist_ok=True)
        clean_directory(V2RAY_DIR) # Cleans V2RAY_DIR while preserving essential files
        os.makedirs(V2RAY_DIR, exist_ok=True) # Recreate if clean_directory removed it (it shouldn't for V2Ray)

        # zipfile import removed from here and moved to top
        zip_path = os.path.join(V2RAY_DIR, "v2ray_download.zip") # Use generic name

        with requests.get(download_url, stream=True, timeout=300) as r:
            r.raise_for_status()
            with open(zip_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
        logging.info(f"Downloaded V2Ray archive to {zip_path}")

        logging.info(f"Extracting {zip_path} to {V2RAY_DIR}...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Extract all, then find and ensure permissions, or selectively extract
            # For simplicity, extract all then manage.
            zip_ref.extractall(V2RAY_DIR)
        logging.info("Extraction complete.")
        os.remove(zip_path); logging.debug(f"Removed V2Ray archive: {zip_path}")

        # Ensure V2RAY_BIN is executable
        v2ray_executable_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
        if not os.path.exists(v2ray_executable_path):
            # Try to find it if it's in a subdirectory (common for some zip structures)
            found_exe = False
            for root, _, files in os.walk(V2RAY_DIR):
                if V2RAY_BIN in files:
                    potential_exe_path = os.path.join(root, V2RAY_BIN)
                    # Move essential files to V2RAY_DIR root if found in subdir
                    if os.path.abspath(root) != os.path.abspath(V2RAY_DIR):
                        logging.info(f"Moving V2Ray components from {root} to {V2RAY_DIR}")
                        shutil.move(potential_exe_path, v2ray_executable_path)
                        # Move .dat files too, if they exist alongside the executable
                        for dat_file in ['geoip.dat', 'geosite.dat']:
                            src_dat = os.path.join(root, dat_file)
                            dst_dat = os.path.join(V2RAY_DIR, dat_file)
                            if os.path.exists(src_dat) and not os.path.exists(dst_dat):
                                shutil.move(src_dat, dst_dat)
                    found_exe = True
                    break
            if not found_exe:
                raise FileNotFoundError(f"V2Ray executable '{V2RAY_BIN}' not found in {V2RAY_DIR} after extraction.")

        if platform.system() != 'Windows' and os.path.exists(v2ray_executable_path):
            logging.info(f"Setting executable permission for {v2ray_executable_path}")
            os.chmod(v2ray_executable_path, 0o755)

        installed_version = check_v2ray_installed()
        if installed_version:
            logging.info(f"✅ V2Ray installation successful. Version: {installed_version}")
        else:
            raise RuntimeError("V2Ray installed but version check failed.")

    except (zipfile.BadZipFile, requests.exceptions.RequestException) as download_err:
        logging.critical(f"Download or extraction failed: {download_err}"); clean_directory(V2RAY_DIR); sys.exit(1)
    except Exception as e:
        logging.critical(f"V2Ray installation failed: {e}", exc_info=True); clean_directory(V2RAY_DIR); sys.exit(1)


def print_real_time_channel_stats_table(stats_data):
    if not stats_data: return
    logging.info("\n--- Real-time Channel Test Statistics ---")
    header = f"{'Channel File/URL':<45} | {'Total':<7} | {'Active':<7} | {'Failed':<7} | {'Skip':<5} | {'Tested':<10} | {'Success%':<8}"
    logging.info(header); logging.info("-" * len(header))
    # Sort by channel filename for consistent display
    sorted_channels_list = sorted(stats_data.items(), key=lambda item: item[0])

    for channel_filename, stats in sorted_channels_list:
        base_channel_name = os.path.splitext(channel_filename)[0]
        # Improved display name logic
        if base_channel_name.replace('_', '').isalnum() and not any(c in base_channel_name for c in ['/', '\\', '.']):
            display_name = f"https://t.me/s/{base_channel_name}"
        else:
            display_name = channel_filename # Fallback if complex name

        total_prepared = stats['total_prepared']
        active = stats['active']
        failed = stats['failed']
        skip = stats['skip']
        processed_for_channel = active + failed + skip
        active_plus_failed = active + failed
        success_percent = (active / active_plus_failed * 100) if active_plus_failed > 0 else 0.0
        logging.info(f"{display_name:<45} | {total_prepared:<7} | {active:<7} | {failed:<7} | {skip:<5} | {processed_for_channel:>3}/{total_prepared:<3}    | {success_percent:>7.1f}%")
    logging.info("--- End Real-time ---")


def sort_server_file_by_time(file_path):
    """Sorts a server file by test time. Assumes lines are 'link | X.YYs' for sortable entries."""
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        logging.debug(f"Skipping sorting for empty or non-existent file: {file_path}")
        return

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        parsed_lines_data = []

        for line_content in lines:
            stripped_content = line_content.strip()
            if not stripped_content:
                parsed_lines_data.append((float('inf'), line_content)) # Preserve empty lines at end
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
                        logging.debug(f"Could not parse time from '{time_figure_str}' in {file_path}: '{stripped_content}'")
                        pass

            parsed_lines_data.append((time_val, line_content))

        parsed_lines_data.sort(key=lambda x: x[0])

        with open(file_path, 'w', encoding='utf-8') as f:
            for _, line_to_write in parsed_lines_data:
                f.write(line_to_write)

        logging.info(f"Successfully sorted file by test time: {file_path}")

    except Exception as e:
        logging.error(f"Error sorting file {file_path}: {e}", exc_info=True)


 
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
            print(f'file {filepath} vmess cleaned')
        else:
            print(f'فایل {filepath} .')
    
    except Exception as e:
        print(f' error in {filepath}: {str(e)}')
 

 
 



def run_link_categorization(base_path):
    """
    دسته‌بندی نهایی در پوشه Categorized_Servers
    """
    source_dir = os.path.join(base_path, "Protocols")
    output_dir = os.path.join(source_dir, "Categorized_Servers")
    if not os.path.exists(source_dir): return
    os.makedirs(output_dir, exist_ok=True)

    # تعریف دسته‌ها بر اساس اولویت
    categories = {
        "1_VLESS_REALITY_TCP": [], # ⭐⭐⭐⭐⭐
        "2_Trojan_TCP": [],        # ⭐⭐⭐⭐☆
        "3_VLESS_TLS_WS": [],      # ⭐⭐⭐☆
        "4_WireGuard": [],         # ⭐⭐⭐
        "5_VMess": []              # ⭐⭐
    }

    for filename in os.listdir(source_dir):
        file_path = os.path.join(source_dir, filename)
        if not os.path.isfile(file_path) or not filename.endswith(".txt"): continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                # تحلیل لینک فنی (قبل از علامت #)
                tech_part = line.split('#')[0]
                try:
                    parsed = urlparse(tech_part)
                    scheme = parsed.scheme.lower()
                    query = parse_qs(parsed.query)
                    sec = query.get('security', [''])[0].lower()
                    net = query.get('type', ['tcp'])[0].lower()

                    if scheme == 'vless' and sec == 'reality' and net == 'tcp':
                        categories["1_VLESS_REALITY_TCP"].append(line)
                    elif scheme == 'trojan' and net == 'tcp':
                        categories["2_Trojan_TCP"].append(line)
                    elif scheme == 'vless' and (sec == 'tls' or net == 'ws'):
                        categories["3_VLESS_TLS_WS"].append(line)
                    elif scheme in ['wireguard', 'wg']:
                        categories["4_WireGuard"].append(line)
                    elif scheme == 'vmess':
                        categories["5_VMess"].append(line)
                except: continue

    # ذخیره فایل‌های دسته‌بندی شده
    for cat_name, links in categories.items():
        if links:
            unique_links = list(dict.fromkeys(links)) # حذف تکراری‌های احتمالی
            out_file = os.path.join(output_dir, f"{cat_name}.txt")
            with open(out_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(unique_links) + '\n')
            logging.info(f"✅ Saved Category {cat_name}: {len(unique_links)} servers")


 



def format_server_link(link, country, latency, channel_name, s_info=None):
    """
    ساخت ری‌مارک استاندارد بدون تکرار لینک فنی
    """
    # ۱. جدا کردن لینک فنی (قبل از #) و اطمینان از تمیز بودن آن
    base_link = link.split('#')[0].strip()
    
    # ۲. تمیز کردن نام کانال
    clean_ch = str(channel_name).replace(".txt", "").split('|')[0].strip()
    
    # ۳. اطمینان از اینکه زمان پینگ (Latency) اشتباهاً کل لینک نباشد
    clean_latency = str(latency).strip()
    if "://" in clean_latency or len(clean_latency) > 15:
        clean_latency = "N/A"

    # ۴. استخراج پورت
    port_val = "N/A"
    if s_info and s_info.get('port'):
        port_val = s_info.get('port')
    else:
        try:
            p_parsed = urlparse(base_link)
            port_val = p_parsed.port if p_parsed.port else base_link.split(':')[-1].split('?')[0]
        except: port_val = "443"

    # ۵. خروجی نهایی: لینک#کانال | کشور | پینگ | پورت
    return f"{base_link}#{clean_ch} | {country} | {clean_latency} | Port:{port_val}"



def process_channel(url):
    channel_name = extract_channel_name(url)
    if not channel_name or channel_name == "unknown_channel":
        logging.warning(f"Could not extract a valid channel name from URL: {url}")
        return 0, 0
    
    channel_file = os.path.join(CHANNELS_DIR, f"{channel_name}.txt")
    logging.info(f"Processing channel: {channel_name} ({url})")
    
    existing_configs = load_existing_configs()
    configs = fetch_config_links(url)
    
    if configs is None or not configs.get("all"):
        Path(channel_file).touch(exist_ok=True)
        return 1 if configs is not None else 0, 0

    # --- اصلاح اصلی: اضافه کردن نام کانال به محض دریافت (Extraction) ---
    raw_fetched_links = set(configs["all"])
    formatted_links_for_channel = set()
    
    for link in raw_fetched_links:
        # حذف هرگونه ری‌مارک قدیمی و اضافه کردن نام کانال فعلی
        base_link = link.split('#')[0]
        formatted_links_for_channel.add(f"{base_link}#{channel_name}")

    # ادامه فرآیند ذخیره‌سازی با لینک‌های نام‌گذاری شده
    existing_channel_cfgs = set()
    if os.path.exists(channel_file):
        with open(channel_file, 'r', encoding='utf-8') as f:
            existing_channel_cfgs = {l.strip() for l in f if l.strip()}

    new_for_channel = formatted_links_for_channel - existing_channel_cfgs
    if new_for_channel:
        updated_ch_cfgs = list(new_for_channel) + list(existing_channel_cfgs)
        with open(channel_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(updated_ch_cfgs[:MAX_CHANNEL_SERVERS]) + '\n')
    
    # آپدیت فایل‌های پروتکل و فایل Merged با لینک‌های نام‌دار
    new_global_total = 0
    for proto in PATTERNS:
        proto_links = {f"{l.split('#')[0]}#{channel_name}" for l in configs.get(proto, [])}
        if not proto_links: continue
        
        new_global_proto = proto_links - existing_configs.get(proto, set())
        if new_global_proto:
            proto_path = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
            with open(proto_path, 'a', encoding='utf-8') as f:
                f.write('\n'.join(new_global_proto) + '\n')
            
            # آپدیت فایل Merged
            with open(MERGED_SERVERS_FILE, 'a', encoding='utf-8') as f:
                f.write('\n'.join(new_global_proto) + '\n')
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

                # لینک خالص بدون ری‌مارک قدیمی
                base_link = s_info.get('original_link', 'N/A').split('#')[0]
                proto = s_info.get('protocol', 'unknown').lower()
                
                # نام کانال بر اساس نام فایل منبع (Source of Truth)
                source_file = s_info.get('source_file', 'Unknown.txt')
                channel_name = source_file.replace(".txt", "")

                if status == 'success':
                    # ساخت ری‌مارک: نام کانال | کشور (موقت) | پینگ | پورت
                    formatted = f"{base_link}#{channel_name} | Lookup... | {msg} | Port:{s_info.get('port', 'N/A')}"
                    
                    wf.write(f"{formatted}\n"); wf.flush()
                    
                    with open(os.path.join(protocols_dir, f"{proto}.txt"), 'a', encoding='utf-8') as pf:
                        pf.write(f"{formatted}\n")
                    
                    with open(os.path.join(tested_channels_dir, source_file), 'a', encoding='utf-8') as cf:
                        cf.write(f"{formatted}\n")
                
                elif status == 'failure':
                    df.write(f"{base_link} | Reason: {msg}\n"); df.flush()
    except Exception as e:
        logging.error(f"Logger error: {e}")



def process_tested_servers_geo():
    logging.info("--- Updating Country Codes in Remarks ---")
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
                
                # ۱. استخراج بخش فنی و ری‌مارک
                parts = line.split('#')
                base_link = parts[0]
                remark_parts = parts[1].split('|')
                
                channel_name = remark_parts[0].strip()
                latency = "N/A"
                port_info = "Port:N/A"
                
                # پیدا کردن پینگ و پورت در ری‌مارک فعلی
                for p in remark_parts:
                    if 's' in p and any(c.isdigit() for c in p) and 'Port' not in p: latency = p.strip()
                    if 'Port:' in p: port_info = p.strip()

                # ۲. تشخیص کشور
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

                # ۳. بازسازی نهایی بدون تکرار
                clean_line = f"{base_link}#{channel_name} | {c_code} | {latency} | {port_info}"
                final_lines.append(clean_line)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_lines) + '\n')
            
    reader.close()




if __name__ == "__main__":
    
    # --- Local Flag to control the Tested Servers sorting ---
    # این گزینه را True بگذارید تا حتی اگر تست انجام نشد، فایل‌های قبلی دسته‌بندی شوند
    ENABLE_TESTED_GEO_SORT = True  

    # --- Initial Setup: Non-destructive directory creation ---
    logging.info("--- Initializing Directory Structure ---")
    for directory in [PROTOCOLS_DIR, REGIONS_DIR, REPORTS_DIR, MERGED_DIR, CHANNELS_DIR,
                      V2RAY_DIR, TESTED_SERVERS_DIR, LOGS_DIR]:
        os.makedirs(directory, exist_ok=True)
    logging.info("Directory structure checked/created.")

    # --- Part 1: Telegram Channel Scraping ---
    if ENABLE_EXTRACTION:
        logging.info("--- Starting Part 1: Telegram Channel Scraping ---")
        
        logging.info("--- Cleaning previous extraction data for a fresh run ---")
        for dir_to_clean in [CHANNELS_DIR, PROTOCOLS_DIR, MERGED_DIR]:
            if os.path.exists(dir_to_clean):
                shutil.rmtree(dir_to_clean)
            os.makedirs(dir_to_clean, exist_ok=True)
        if os.path.exists(MERGED_SERVERS_FILE):
             os.remove(MERGED_SERVERS_FILE)

        channels_file_path = CHANNELS_FILE
        try:
            if not os.path.exists(channels_file_path):
                logging.error(f"Telegram sources file not found: {channels_file_path}"); sys.exit(1)
            with open(channels_file_path, 'r', encoding='utf-8') as f:
                raw_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            normalized_urls = []
            for url in raw_urls:
                norm_url = normalize_telegram_url(url)
                if norm_url and norm_url not in normalized_urls: normalized_urls.append(norm_url)
            normalized_urls.sort()
            logging.info(f"✅ Found {len(normalized_urls)} unique, normalized Telegram channels to process.")
        except Exception as e:
            logging.error(f"❌ Error processing Telegram channel list ({channels_file_path}): {e}"); sys.exit(1)

        total_channels_count = len(normalized_urls)
        processed_ch_count = 0; total_new_added = 0; failed_fetches = 0
        for idx, ch_url in enumerate(normalized_urls, 1):
            logging.info(f"--- Processing Channel {idx}/{total_channels_count}: {ch_url} ---")
            success_flag, new_srvs = process_channel(ch_url)
            if success_flag == 1: processed_ch_count += 1; total_new_added += new_srvs
            else: failed_fetches += 1
            if idx % BATCH_SIZE == 0 and idx < total_channels_count:
                logging.info(f"--- Batch of {BATCH_SIZE} processed, sleeping for {SLEEP_TIME}s ---")
                time.sleep(SLEEP_TIME)
        logging.info(f"--- Telegram Scraping Finished ---")
        logging.info(f"Successfully processed {processed_ch_count}/{total_channels_count} channels.")
        if failed_fetches > 0: logging.warning(f"{failed_fetches} channels failed during fetch/processing.")
        logging.info(f"Added {total_new_added} new unique servers globally from scraping.")
    else:
        logging.warning("Skipping Part 1: Telegram Channel Scraping (ENABLE_EXTRACTION is False).")

    # --- Part 2: GeoIP Analysis (For Untested/Scraped Servers) ---
    if ENABLE_GEO_LOOKUP:
        logging.info("\n--- Starting Part 2: GeoIP Analysis (Untested Servers) ---")
        country_data_map = process_geo_data()
        if country_data_map:
            logging.info("✅ GeoIP analysis complete.")
        else:
            logging.warning("⚠️ GeoIP analysis did not return data or failed.")
    else:
        country_data_map = {}
        logging.warning("Skipping Part 2: GeoIP Analysis (ENABLE_GEO_LOOKUP is False).")

    # --- Part 3: Generating Extraction Report ---
    if ENABLE_REPORTING:
        logging.info("\n--- Starting Part 3: Generating Extraction Report ---")
        try:
            extraction_channel_stats = get_channel_stats()
            save_extraction_data(extraction_channel_stats, country_data_map)
            logging.info("✅ Extraction report generated.")
        except Exception as e:
            logging.error(f"❌ Failed to generate extraction report: {e}")
    else:
        logging.warning("Skipping Part 3: Generating Extraction Report (ENABLE_REPORTING is False).")

    # --- Part 4: Server Testing ---
    if ENABLE_TESTING:
        logging.info("\n--- Starting Part 4: Server Testing ---")
        
        logging.info(f"--- Cleaning previous test results in: {TESTED_SERVERS_DIR} ---")
        clean_directory(TESTED_SERVERS_DIR) 
        # Recreate subdirs
        os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Protocols'), exist_ok=True)
        os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Channels'), exist_ok=True)
        os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Regions'), exist_ok=True)

        all_servers_to_test = []
        servers_read_total = 0; parsing_errors = defaultdict(int); proto_load_counts = defaultdict(int); skipped_disabled_count = 0

        if not os.path.exists(CHANNELS_DIR):
            logging.error(f"Source channels directory {CHANNELS_DIR} not found. Cannot load servers for testing."); sys.exit(1)
        source_channel_files = [f for f in os.listdir(CHANNELS_DIR) if f.endswith('.txt')]
        if not source_channel_files:
            logging.error(f"😐 No channel files in {CHANNELS_DIR} to test from. Ensure Part 1 ran successfully or use existing files."); sys.exit(1)

        for ch_filename in source_channel_files:
            _ = channel_test_stats[ch_filename] 
            servers_from_file = read_links_from_file(os.path.join(CHANNELS_DIR, ch_filename))
            servers_read_total += len(servers_from_file)
            for link_str in servers_from_file:
                try:
                    parsed_url_scheme = urlparse(link_str).scheme.lower()
                    if not parsed_url_scheme: parsing_errors["no_scheme"] +=1; continue

                    if parsed_url_scheme not in ENABLED_PROTOCOLS or not ENABLED_PROTOCOLS[parsed_url_scheme]:
                        if parsed_url_scheme not in ENABLED_PROTOCOLS: parsing_errors[f"unsupported_{parsed_url_scheme}"] += 1
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

        logging.info(f"Read {servers_read_total} links. Prepared {len(all_servers_to_test)} for testing.")
        if skipped_disabled_count > 0: logging.info(f"Skipped {skipped_disabled_count} servers due to disabled protocols.")

        if not all_servers_to_test:
            logging.error("❌ No valid and enabled servers found to test after parsing. Exiting."); sys.exit(1)

        parser = argparse.ArgumentParser(description="Scrape Telegram for proxies and test them.")
        parser.add_argument('--max-threads', type=int, default=MAX_THREADS, help=f"Max testing threads (default: {MAX_THREADS})")
        parser.add_argument('--skip-install', action='store_true', help="Skip V2Ray check and installation.")
        cli_args = parser.parse_args()
        MAX_THREADS = cli_args.max_threads

        logging.info("\n--- V2Ray Check ---")
        if ENABLE_V2RAY_SETUP and not cli_args.skip_install:
            installed_ver = check_v2ray_installed()
            latest_ver = get_latest_version()
            if not installed_ver or (latest_ver and installed_ver != latest_ver and installed_ver != "unknown"):
                logging.info("🚀 Attempting V2Ray installation/update...")
                install_v2ray()
                installed_ver = check_v2ray_installed()
                if not installed_ver: logging.critical("V2Ray install attempted but still not found. Exiting."); sys.exit(1)
            else: logging.info(f"✅ Using existing V2Ray version: {installed_ver}")
        else:
            logging.warning("Skipping V2Ray check and installation as requested.")
            if not check_v2ray_installed():
                logging.error("V2Ray check skipped, but V2Ray not found. Testing cannot proceed."); sys.exit(1)

        logging.info(f"\n--- Starting Server Testing ({len(all_servers_to_test)} servers, {MAX_THREADS} threads) ---")
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

            logging.info(f"Submitted {len(futures_list)} testing tasks. Waiting for completion...")
            for fut in futures_list:
                try: fut.result()
                except Exception: pass

        tested_servers_dir_clean = 'Tested_Servers'  
        clean_vmess_links(tested_servers_dir_clean)
        print('all vmess time cleaned')
        
        logging.info("All testing tasks submitted and completed by executor. Signaling logger thread to finalize.")
        test_log_queue.put(None) 
        logger_t.join(timeout=30) 
        if logger_t.is_alive():
            logging.warning("Logger thread did not exit cleanly after timeout.")

        logging.info("--- Testing Phase Complete ---")
    else:
        logging.warning("Skipping Part 4: Server Testing (ENABLE_TESTING is False).")

    # --- Part 5: GeoIP Sorting for Tested Servers (Runs independently) ---
    if ENABLE_TESTED_GEO_SORT:
        logging.info("\n--- Starting Part 5: Sorting TESTED servers by Region ---")
        process_tested_servers_geo()
    else:
        logging.info("Skipping Part 5: Tested Server Sorting (ENABLE_TESTED_GEO_SORT is False).")
    # --- Part 6: Final Categorization ---
    if ENABLE_CATEGORIZATION:
        logging.info("\n--- Starting Part 6: Final Categorization ---")
        
        # دسته‌بندی برای سرورهای خام (Servers\Protocols)
        logging.info("Categorizing Scraped Servers...")
        run_link_categorization("Servers")
        
        # دسته‌بندی برای سرورهای تست شده (Tested_Servers\Protocols)
        if ENABLE_TESTING or os.path.exists(TESTED_SERVERS_DIR):
            logging.info("Categorizing Tested Servers...")
            run_link_categorization(TESTED_SERVERS_DIR)
            
        logging.info("✅ Final Categorization Complete.")
    logging.info("--- Script Finished ---")