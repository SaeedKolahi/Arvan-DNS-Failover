from datetime import datetime, timedelta
import json
import sqlite3
import stat
import paramiko
import requests
import os
import socket
import tempfile
from OpenSSL import crypto
import logging
from logging.handlers import RotatingFileHandler
import platform
import subprocess
import stat
import shutil
from client_counter import get_client_count
import pytz




# === CONFIG BLOCK ===

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

config_path = os.path.join(SCRIPT_DIR, "config.json")
sample_config_path = os.path.join(SCRIPT_DIR, "config.sample.json")

if os.path.exists(config_path):
    with open(config_path) as f:
        CONFIG = json.load(f)
else:
    with open(sample_config_path) as f:
        CONFIG = json.load(f)

STATE_FILE = os.path.join(SCRIPT_DIR, "state.json")
KEY_NAME = "xrayTemplateConfig"

# =====================

# OS-aware log paths
if platform.system() == "Windows":
    LOG_FILE = "dns_failover.log"
    PRINT_LOG_FILE = "dns_failover_prints.log"
else:
    LOG_FILE = "/root/dns-arvan/dns_failover.log"
    PRINT_LOG_FILE = "/root/dns-arvan/dns_failover_prints.log"
    # Ensure the directory exists on non-Windows systems
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


LOG_MAX_SIZE = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3

# Main logger (file only, no console)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
main_handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP_COUNT, encoding='utf-8')
main_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(main_handler)

# Print logger (file + console)
print_logger = logging.getLogger("print_logger")
print_logger.setLevel(logging.INFO)

# File handler for prints
print_file_handler = RotatingFileHandler(PRINT_LOG_FILE, maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP_COUNT, encoding='utf-8')
print_file_handler.setFormatter(logging.Formatter("%(asctime)s [PRINT] %(message)s"))
print_logger.addHandler(print_file_handler)

# Custom formatter to strip timestamp and level for console output
class SimpleConsoleFormatter(logging.Formatter):
    def format(self, record):
        return record.getMessage()

# Console handler for prints (clean output)
print_console_handler = logging.StreamHandler()
print_console_handler.setFormatter(SimpleConsoleFormatter())
print_logger.addHandler(print_console_handler)

# Override print to log to print_logger only
def print(*args, **kwargs):
    message = " ".join(str(arg) for arg in args)
    print_logger.info(message)




# =====================

def ping_host(ip):

    is_windows = platform.system().lower() == 'windows'
    param = '-n' if is_windows else '-c'
    timeout_flag = '-w' if is_windows else '-W'
    timeout_val = str(int(CONFIG["timeout_val"] * 1000)) if is_windows else str(CONFIG["timeout_val"])
    

    for i in range(10):
        cmd = ['ping', param, '1', timeout_flag, timeout_val, ip]

        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            print("       " + output.strip().replace("\n", "\n       "))
            return True  # 🟢 First success, IP is reachable
        except subprocess.CalledProcessError as e:
            print("       " + e.output.strip().replace("\n", "\n       "))

    return False  # 🔴 All 10 failed

def resolve_domain(domain):
    try:
        return list(set([info[4][0] for info in socket.getaddrinfo(domain, 0)]))
    except socket.gaierror:
        return []

def load_json(path):
    return json.load(open(path)) if os.path.exists(path) else {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def update_record(apikey, domain, record_id, subdomain, ips):
    print(f"[API] Updating {subdomain} to IPs: {ips}")
    url = f"https://napi.arvancloud.ir/cdn/4.0/domains/{domain}/dns-records/{record_id}"
    payload = {
        "type": "a",
        "name": subdomain,
        "cloud": False,
        "value": [{"ip": ip, "weight": str(34 if i == 0 else 33)} for i, ip in enumerate(ips)],
        "ttl": 120,
        "upstream_https": "default",
        "ip_filter_mode": {
            "count": "single",
            "order": "weighted",
            "geo_filter": "none"
        }
    }
    headers = {
        "Authorization": f"Apikey {apikey}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    return requests.put(url, headers=headers, json=payload).status_code == 200

def get_current_ips(apikey, domain, record_id):
    url = f"https://napi.arvancloud.ir/cdn/4.0/domains/{domain}/dns-records/{record_id}"
    headers = {"Authorization": f"Apikey {apikey}", "Accept": "application/json"}
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        return [entry["ip"] for entry in res.json()["data"]["value"]]
    return []

def inline_code(text: str) -> str:
    # Escape special chars for Telegram MarkdownV2 inside inline code
    return '`' + text.replace('\\', '\\\\').replace('`', '\\`') + '`'

def escape_markdown(text: str) -> str:
    special_chars = r'\_*[]()~`>#+-=|{}.!'
    return ''.join('\\' + c if c in special_chars else c for c in text)

# Update send_telegram_message to support reply_to_message_id

def send_telegram_message(bot_token, chat_id, text, reply_markup=None, reply_to_message_id=None):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2"
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if reply_to_message_id:
        payload["reply_to_message_id"] = reply_to_message_id
    try:
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()
        print("[Telegram] Message sent successfully.")
    except Exception as e:
        print(f"[Telegram] Exception sending message: {e}")
        print(f"[Telegram] Failed message content:\n{text}")

def modify_balancer_tag(value_json, forced_tag):
    data = json.loads(value_json)
    changed = False
    for rule in data.get("routing", {}).get("rules", []):
        if "balancerTag" in rule:
            rule["balancerTag"] = forced_tag
            changed = True
    return json.dumps(data, ensure_ascii=False, indent=2), forced_tag if changed else None

def transfer_and_patch_db(from_host, to_host, balancer_tag):
    try:
        print(f"\n🔁 Syncing from {from_host} → {to_host} (set tag = {balancer_tag})")
        ssh_from = paramiko.SSHClient()
        ssh_from.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_from.connect(from_host, username=CONFIG["ssh_user"], password=CONFIG["ssh_pass"])
        sftp_from = ssh_from.open_sftp()

        local_db = tempfile.mktemp()
        sftp_from.get(CONFIG["xui_db_path"], local_db)
        sftp_from.close()
        ssh_from.close()
        print("📥 Pulled DB from source server.")
        
        conn = sqlite3.connect(local_db)
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=?", (KEY_NAME,))
        row = cur.fetchone()
        if row:
            new_value, tag = modify_balancer_tag(row[0], balancer_tag)
            cur.execute("UPDATE settings SET value=? WHERE key=?", (new_value, KEY_NAME))
            conn.commit()
            print(f"🛠️  balancerTag set to: {tag}")
        conn.close()

        ssh_to = paramiko.SSHClient()
        ssh_to.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_to.connect(to_host, username=CONFIG["ssh_user"], password=CONFIG["ssh_pass"])
        sftp_to = ssh_to.open_sftp()
        sftp_to.put(local_db, CONFIG["xui_db_path"])
        sftp_to.close()
        ssh_to.exec_command("systemctl restart x-ui")
        ssh_to.close()
        os.remove(local_db)
        print("📤 Updated DB pushed + x-ui restarted.")
        return True

    except Exception as e:
        print(f"❌ DB sync error: {e}")
        print("🚫🚫🚫 Record update cancelled due to failed DB transfer.\n")
        return False




def sftp_recursive_download(sftp_client, remote_path, local_path):
    os.makedirs(local_path, exist_ok=True)
    for item in sftp_client.listdir_attr(remote_path):
        remote_item = remote_path + '/' + item.filename
        local_item = os.path.join(local_path, item.filename)

        if stat.S_ISDIR(item.st_mode):
            # It's a directory: recurse
            sftp_recursive_download(sftp_client, remote_item, local_item)
        else:
            # It's a file: download
            sftp_client.get(remote_item, local_item)

def sftp_recursive_upload(sftp_client, local_path, remote_path):
    try:
        sftp_client.stat(remote_path)
    except FileNotFoundError:
        sftp_client.mkdir(remote_path)

    for item in os.listdir(local_path):
        local_item = os.path.join(local_path, item)
        remote_item = remote_path + '/' + item

        if os.path.isdir(local_item):
            sftp_recursive_upload(sftp_client, local_item, remote_item)
        else:
            sftp_client.put(local_item, remote_item)

def sync_cert_folder(from_host, to_host):
    print(f"🔐 Syncing /root/cert/ recursively from {from_host} → {to_host}")

    # Create temp local folder
    local_temp_dir = "/tmp/cert_sync"
    if os.path.exists(local_temp_dir):
        
        shutil.rmtree(local_temp_dir)
    os.makedirs(local_temp_dir)

    # Connect to source
    ssh_from = paramiko.SSHClient()
    ssh_from.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_from.connect(from_host, username=CONFIG["ssh_user"], password=CONFIG["ssh_pass"])
    sftp_from = ssh_from.open_sftp()

    # Download /root/cert recursively to local
    try:
        sftp_recursive_download(sftp_from, "/root/cert", local_temp_dir)
    except FileNotFoundError:
        print(f"[-] Source /root/cert does not exist on {from_host}")
        sftp_from.close()
        ssh_from.close()
        return
    sftp_from.close()
    ssh_from.close()

    # Connect to destination
    ssh_to = paramiko.SSHClient()
    ssh_to.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_to.connect(to_host, username=CONFIG["ssh_user"], password=CONFIG["ssh_pass"])
    sftp_to = ssh_to.open_sftp()

    # Upload recursively from local to destination
    sftp_recursive_upload(sftp_to, local_temp_dir, "/root/cert")

    sftp_to.close()
    ssh_to.close()

    print("✅ /root/cert/ synced recursively successfully.")



def should_check_cert(state):
    last_check_str = state.get("_last_cert_check")
    if not last_check_str:
        return True
    try:
        last_check = datetime.strptime(last_check_str, "%Y-%m-%dT%H:%M:%S")
        return datetime.utcnow() - last_check >= timedelta(days=CONFIG["cert_check_interval_days"])

    except:
        return True  # if timestamp was malformed

def check_cert_expiry_main_server(host):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=CONFIG["ssh_user"], password=CONFIG["ssh_pass"])
    sftp = ssh.open_sftp()

    cert_base_path = "/root/cert"
    folders = sftp.listdir(cert_base_path)

    alerts = []

    for folder in folders:
        fullchain_path = f"{cert_base_path}/{folder}/fullchain.pem"
        try:
            with sftp.open(fullchain_path, 'r') as f:
                pem_data = f.read().decode()
        except IOError:
            continue


        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
        expiry_timestamp = cert.get_notAfter().decode('ascii')
        expiry_date = datetime.strptime(expiry_timestamp, "%Y%m%d%H%M%SZ")
        days_left = (expiry_date - datetime.utcnow()).days

        if days_left < CONFIG["cert_expiry_threshold_days"]:
            alerts.append((host, folder, days_left))

    sftp.close()
    ssh.close()
    return alerts






def main():
    state = load_json(STATE_FILE)
    # Initialize mute keys for each alert type if missing
    for mute_key in ["mute_capacity_alert", "mute_failover_alert", "mute_ssl_alert", "mute_backup_failover_alert"]:
        if mute_key not in state:
            state[mute_key] = False
    domain = CONFIG["domain"]
    total_available = 0
    capacity_details = []

    for subdomain, rec in CONFIG["records"].items():
        fqdn = f"{subdomain}.{domain}"
        record_id = rec["id"]
        backup_ip = rec["backup_ip"]

        state.setdefault(subdomain, {
            "in_backup": False,
            "original_ips": []
        })

        print(f"[*] Probing {fqdn} (ping each IP once with {CONFIG['timeout_seconds']}s timeout)...")
        
        # Count clients on the current main server

        client_count = get_client_count(fqdn, CONFIG["panel_port"], CONFIG["base_path"], CONFIG["panel_user"], CONFIG["panel_pass"])
        if client_count is not None:
            available = max(0, CONFIG["max_capacity"] - client_count)
            total_available += available
            capacity_details.append(f"{subdomain}: {client_count} / {CONFIG['max_capacity']} (available: {available})")
            print(f"    -> 📊 Client Count: {client_count} (available: {available})")
        else:
            capacity_details.append(f"{subdomain}: Failed to get count")
            print(f"    -> ⚠️  Could not retrieve client count for {fqdn}.")

        

        try:
            main_ip = socket.gethostbyname(fqdn)
        except:
            print(f"❌ Could not resolve {fqdn}")
            continue

        if state[subdomain]["in_backup"]:
            all_down = True
            if not ping_host(backup_ip):
                print(f"❌ Backup IP {backup_ip} is unreachable. Both main and backup are DOWN!")
                domain_md = inline_code(fqdn)
                msg = (
                    "🚨 *Critical DNS Failover Issue*\n"
                    f"Main IPs unreachable\n"
                    f"Domain: {domain_md}\n"
                    f"Backup IP unreachable: {inline_code(backup_ip)}\n"
                )
                
                    
                    
                send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"],msg, reply_markup=json.dumps(build_dynamic_keyboard(state)))
                continue   

            for ip in state[subdomain]["original_ips"]:
                print(f"    ↳ Probing original IP {ip}...")
                if ping_host(ip):
                    all_down = False
                    print(f"[✓] {ip} is reachable. Restoring main IPs...\nfirst Restoring BACKUP...")
                    main_ip = ip
                    if transfer_and_patch_db(from_host=backup_ip, to_host=main_ip, balancer_tag="lb-direct"):
                        success = update_record(CONFIG["apikey"], domain, record_id, subdomain, state[subdomain]["original_ips"])
                        if success:
                            
                            original_ips = state[subdomain]["original_ips"]
                            state[subdomain]["in_backup"] = False
                            state[subdomain]["original_ips"] = []

                            domain_md = inline_code(fqdn)
                            ips_md = ", ".join([inline_code(ip) for ip in original_ips])
                            msg = (
                                "✅ *DNS Failover Restored*\n"
                                f"Domain: {domain_md}\n"
                                f"IPs: {ips_md}\n"
                                "Status: Restored to main IPs"
                            )
                            if not state.get("mute_failover_alert", False):
                                send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg, reply_markup=json.dumps(build_dynamic_keyboard(state)))
                            else:
                                print("🔕 Failover alerts are muted.")
                        else:
                            print("[API] Failed to restore main IPs.")
                        break
                    else:
                        print(f"❌ Skipping record update — transfer from {backup_ip} to {main_ip} failed.")
            if all_down:
                print("[-] All original IPs still down. Keeping backup.")

        else:
            resolved_ips = resolve_domain(fqdn)
            if not resolved_ips:
                print(f"[-] Could not resolve any IP for {fqdn}. Skipping.")
                continue

            all_failed = True
            for ip in resolved_ips:
                print(f"    ↳ Probing IP {ip}...")
                if ping_host(ip):
                    print(f"    [+] IP {ip} is reachable.")
                    all_failed = False
                else:
                    print(f"    [-] IP {ip} is unreachable.")

            if all_failed:
                print(f"[!] {fqdn} is unreachable (all IPs failed once with {CONFIG['timeout_seconds']}s timeout).")
                current_ips = get_current_ips(CONFIG["apikey"], domain, record_id)
                
                # Check if backup IP is available before switching
                if not ping_host(backup_ip):
                    print(f"❌ Backup IP {backup_ip} is also unreachable! Keeping current configuration.")
                    domain_md = inline_code(fqdn)
                    backup_ip_md = inline_code(backup_ip)
                    msg = (
                    "🚨 *Critical DNS Failover Issue*\n"
                    f"Main IPs unreachable\n"
                    f"Domain: {domain_md}\n"
                    f"Backup IP unreachable: {backup_ip_md}\n"
                    "Keeping Main IPs"
                    )
                    if not state.get("mute_failover_alert", False):
                        send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg, reply_markup=json.dumps(build_dynamic_keyboard(state)))
                    else:
                        print("🔕 Failover alerts are muted.")
                    continue
                
                success = update_record(CONFIG["apikey"], domain, record_id, subdomain, [backup_ip] * 3)
                if success:
                    state[subdomain]["original_ips"] = current_ips
                    state[subdomain]["in_backup"] = True

                    domain_md = inline_code(fqdn)
                    orig_ips_md = ", ".join([inline_code(ip) for ip in current_ips])
                    backup_ip_md = inline_code(backup_ip)
                    msg = (
                        "⚠️ *DNS Failover Activated*\n"
                        f"Domain: {domain_md}\n"
                        f"Original IPs: {orig_ips_md}\n"
                        f"Switched to Backup IP: {backup_ip_md}"
                    )
                    if not state.get("mute_failover_alert", False):
                        send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg, reply_markup=json.dumps(build_dynamic_keyboard(state)))
                    else:
                        print("🔕 Failover alerts are muted.")
                    
                else:
                    print("[API] Failed to switch to backup IPs.")
            else:
                print(f"[+] {fqdn} is reachable.")
                if ping_host(backup_ip):
                    transfer_and_patch_db(from_host=main_ip, to_host=backup_ip, balancer_tag="lb-direct")
                    sync_cert_folder(from_host=main_ip, to_host=backup_ip)
                else:
                    print(f"❌ Backup IP {backup_ip} is unreachable. Skipping sync.")
                    backup_ip_md = inline_code(backup_ip)
                    msg = (
                        "❌ *Backup Sync Failed*\n"
                        f"Could not reach backup server {backup_ip_md}"
                    )
                    if not state.get("mute_backup_failover_alert", False):
                        send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg, reply_markup=json.dumps(build_dynamic_keyboard(state)))
                    else:
                        print("🔕 Backup Failover alerts are muted.")
    
    # === Capacity Check and Telegram Notification ===
    if total_available < CONFIG["capacity_threshold"]:
        print(f"\nTotal capacity available ({total_available}) is below the threshold ({CONFIG['capacity_threshold']}). Sending Telegram alert.")
        details_md = "\n".join([escape_markdown(d) for d in capacity_details])
        msg = (
            f"⚠️ *Capacity Alert*\n"
            f"Total available: {total_available}\n"
            f"Threshold: {CONFIG['capacity_threshold']}\n"
            f"*Details*:\n{details_md}"

        )
        tehran = pytz.timezone('Asia/Tehran')
        now_tehran = datetime.now(tehran)
        if CONFIG["capacity_alert_start_hour"] <= now_tehran.hour < CONFIG["capacity_alert_end_hour"]:
            if not state.get("mute_capacity_alert", False):
                send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg, reply_markup=json.dumps(build_dynamic_keyboard(state)))
            else:
                print("🔕 Capacity alerts are muted.")
        else:
            print(f"⏰ Outside the allowed time ({CONFIG['capacity_alert_start_hour']}:00 to {CONFIG['capacity_alert_end_hour']}:00 Iran time)")
        
    else:
        print(f"\nTotal capacity available ({total_available}) is within the threshold ({CONFIG['capacity_threshold']}). No alert sent.")

    # === Check certs on current main servers ===
    if should_check_cert(state):
        all_alerts = []
        checked_fqdns = set()

        for subdomain, rec in CONFIG["records"].items():
            fqdn = f"{subdomain}.{domain}"
            if fqdn not in checked_fqdns:
                print(f"Checking certificates on main server: {fqdn}")
                alerts = check_cert_expiry_main_server(fqdn)
                all_alerts.extend(alerts)
                checked_fqdns.add(fqdn)

        if all_alerts:
            msg_lines = ["⏰ *SSL Certificate Expiry Warning*"]
            current_host = None
            for host, folder, days_left in all_alerts:
                if host != current_host:
                    msg_lines.append(f"\nMain Server: {inline_code(host)}")
                    current_host = host
                msg_lines.append(f"• Cert Folder: `/root/cert`/{inline_code(folder)} — Days Left: {inline_code(str(days_left))}")

            msg = "\n".join(msg_lines)
            if not state.get("mute_ssl_alert", False):
                send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg, reply_markup=json.dumps(build_dynamic_keyboard(state)))
            else:
                print("🔕 SSL alerts are muted.")
        else:
            print("All certificates are fine, no alerts.")

        # Update state file with the new timestamp
        state["_last_cert_check"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    else:
        print(f"Skipping cert check (checked < {CONFIG['cert_check_interval_days']} days ago).")


    save_json(STATE_FILE, state)


def process_telegram_text_commands():
    url = f"https://api.telegram.org/bot{CONFIG['telegram_bot_token']}/getUpdates"
    state = load_json(STATE_FILE)
    last_update_id = state.get("_last_update_id")
    params = {"timeout": 1}
    if last_update_id:
        params["offset"] = last_update_id + 1
    try:
        resp = requests.get(url, params=params, timeout=5).json()
    except Exception as e:
        print(f"[Polling] Exception: {e}")
        return
    send_keyboard = False
    for update in resp.get("result", []):
        state["_last_update_id"] = update["update_id"]
        if "message" in update and "text" in update["message"]:
            text = update["message"]["text"].strip()
            if text == "🔕 Mute Capacity":
                state["mute_capacity_alert"] = True
                send_keyboard = True
            elif text == "🔔 Unmute Capacity":
                state["mute_capacity_alert"] = False
                send_keyboard = True
            elif text == "🔕 Mute Failover":
                state["mute_failover_alert"] = True
                send_keyboard = True
            elif text == "🔔 Unmute Failover":
                state["mute_failover_alert"] = False
                send_keyboard = True
            elif text == "🔕 Mute Backup Failover":
                state["mute_backup_failover_alert"] = True
                send_keyboard = True
            elif text == "🔔 Unmute Backup Failover":
                state["mute_backup_failover_alert"] = False
                send_keyboard = True
            elif text == "🔕 Mute SSL":
                state["mute_ssl_alert"] = True
                send_keyboard = True
            elif text == "🔔 Unmute SSL":
                state["mute_ssl_alert"] = False
                send_keyboard = True
    save_json(STATE_FILE, state)
    
    if send_keyboard:
        reply_keyboard = build_dynamic_keyboard(state)
        send_telegram_message(
            CONFIG["telegram_bot_token"],
            CONFIG["telegram_chat_id"],
            "✅ وضعیت هشدار به‌روزرسانی شد",
            reply_markup=json.dumps(reply_keyboard)
        )

# Show reply keyboard to user
reply_keyboard = {
    "keyboard": [
        ["🔕 Mute Capacity", "🔕 Mute Failover"],
        ["🔕 Mute Backup Failover", "🔕 Mute SSL"],
        ["🔔 Unmute Capacity", "🔔 Unmute Failover"],
        ["🔔 Unmute Backup Failover", "🔔 Unmute SSL"]
    ],
    "resize_keyboard": True,
    "one_time_keyboard": False
}

def build_dynamic_keyboard(state):
    mute_row = []
    unmute_row = []
    if not state.get("mute_failover_alert", False):
        mute_row.append("🔕 Mute Failover")
    else:
        unmute_row.append("🔔 Unmute Failover")
    if not state.get("mute_backup_failover_alert", False):
        mute_row.append("🔕 Mute Backup Failover")
    else:
        unmute_row.append("🔔 Unmute Backup Failover")
    if not state.get("mute_ssl_alert", False):
        mute_row.append("🔕 Mute SSL")
    else:
        unmute_row.append("🔔 Unmute SSL")
    if not state.get("mute_capacity_alert", False):
        mute_row.append("🔕 Mute Capacity")
    else:
        unmute_row.append("🔔 Unmute Capacity")
    keyboard = []
    if mute_row:
        keyboard.append(mute_row)
    if unmute_row:
        keyboard.append(unmute_row)
    return {
        "keyboard": keyboard,
        "resize_keyboard": True,
        "one_time_keyboard": False
    }
# Use build_dynamic_keyboard(state) for reply_markup in all alert send_telegram_message calls.

if __name__ == "__main__":
    process_telegram_text_commands()
    main()
