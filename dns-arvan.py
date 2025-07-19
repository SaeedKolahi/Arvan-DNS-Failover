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




# === CONFIG BLOCK ===
CONFIG = {
    "apikey": "your-arvan-api-key",
    "domain": "example.com",
    "telegram_bot_token": "your-telegram-bot-token",
    "telegram_chat_id": "your-telegram-chat-id",
    "timeout_seconds": 10,
    "timeout_val" : 1,
    "ssh_user": "root",
    "ssh_pass": "your-ssh-password",
    "xui_db_path": "/etc/x-ui/x-ui.db",
    "cert_check_interval_days": 3,
    "cert_expiry_threshold_days": 4,

    "records": {
        "subdomain": {
            "id": "12345678-1234-5678-1234-567812345678",
            "backup_ip": "192.168.1.100"
        },
    }

}
STATE_FILE = 'state.json'
KEY_NAME = "xrayTemplateConfig"
# =====================

LOG_FILE = "/root/dns-arvan/dns_failover.log"
PRINT_LOG_FILE = "/root/dns-arvan/dns_failover_prints.log"

LOG_MAX_SIZE = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3

# Main logger (file only, no console)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
main_handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP_COUNT)
main_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(main_handler)

# Print logger (file + console)
print_logger = logging.getLogger("print_logger")
print_logger.setLevel(logging.INFO)

# File handler for prints
print_file_handler = RotatingFileHandler(PRINT_LOG_FILE, maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP_COUNT)
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

def send_telegram_message(bot_token, chat_id, text):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2"
    }
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
    domain = CONFIG["domain"]


    for subdomain, rec in CONFIG["records"].items():
        fqdn = f"{subdomain}.{domain}"
        record_id = rec["id"]
        backup_ip = rec["backup_ip"]

        state.setdefault(subdomain, {
            "in_backup": False,
            "original_ips": []
        })

        print(f"[*] Probing {fqdn} (ping each IP once with {CONFIG['timeout_seconds']}s timeout)...")
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
                
                    
                    
                send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"],msg)
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
                            send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg)
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
                    send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg)
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
                    send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg)
                    
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
                    send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg)
    
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
            send_telegram_message(CONFIG["telegram_bot_token"], CONFIG["telegram_chat_id"], msg)
        else:
            print("All certificates are fine, no alerts.")

        # Update state file with the new timestamp
        state["_last_cert_check"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    else:
        print(f"Skipping cert check (checked < {CONFIG['cert_check_interval_days']} days ago).")


    save_json(STATE_FILE, state)


if __name__ == "__main__":
    main()
