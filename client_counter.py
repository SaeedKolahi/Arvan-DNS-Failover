import requests
import json
import urllib3
import os

# Suppress only the single InsecureRequestWarning from urllib3 needed for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load config
if os.path.exists("config.json"):
    with open("config.json") as f:
        CONFIG = json.load(f)
else:
    with open("config.sample.json") as f:
        CONFIG = json.load(f)

def _login(session, base_url, username, password):
    """Logs into the service and returns the session if successful."""
    url = f"{base_url}/login"
    try:
        resp = session.post(url, data={"username": username, "password": password}, verify=False, timeout=5)
        resp.raise_for_status()
        if resp.json().get("success"):
            return True
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"    -> Login error for {base_url}: {e}")
        pass
    return False

def _get_inbounds(session, base_url, resolve_host):
    """Fetches inbound data."""
    url = f"{base_url}/panel/api/inbounds/list"
    headers = {"Host": resolve_host}
    try:
        resp = session.get(url, headers=headers, verify=False, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("success"):
            return data.get("obj", [])
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"    -> Inbounds fetch error for {base_url}: {e}")
        pass
    return []

def get_client_count(host, port, base_path, username, password):
    """
    Connects to a server, logs in, and returns the total number of clients.
    Returns the count (int) or None if an error occurs.
    """
    base_url = f"https://{host}:{port}/{base_path}"

    session = requests.Session()

    if not _login(session, base_url, username, password):
        return None

    inbounds = _get_inbounds(session, base_url, host)
    total_clients = 0
    for inbound in inbounds:
        try:
            settings = json.loads(inbound.get("settings", "{}"))
            clients = settings.get("clients", [])
            total_clients += len(clients)
        except (json.JSONDecodeError, AttributeError):
            continue
            
    return total_clients

def main():

    subdomain = list(CONFIG["records"].keys())[0]
    record_conf = CONFIG["records"][subdomain]
    host = f"{subdomain}.{CONFIG['domain']}"
    port = int(record_conf.get("panel_port", CONFIG["panel_port"]))
    username = record_conf.get("panel_user", CONFIG["panel_user"])
    password = record_conf.get("panel_pass", CONFIG["panel_pass"])
    base_path = record_conf.get("base_path", CONFIG["base_path"])

    print(f"Attempting to count clients for {host}...")
    count = get_client_count(host, port, base_path, username, password)
    
    if count is not None:
        print(f"📊 Total clients found: {count}")
    else:
        print("Could not retrieve client count.")

if __name__ == "__main__":
    main()
