import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import itertools
import sys
import argparse

# ==============================
# Banner
# ==============================
print("""
=================================================================
 ██████████                                            ████      
░░███░░░░███                                          ░░███      
 ░███   ░░███ ████████  █████ ████ ████████   ██████   ░███      
 ░███    ░███░░███░░███░░███ ░███ ░░███░░███ ░░░░░███  ░███      
 ░███    ░███ ░███ ░░░  ░███ ░███  ░███ ░███  ███████  ░███      
 ░███    ███  ░███      ░███ ░███  ░███ ░███ ███░░███  ░███      
 ██████████   █████     ░░████████ ░███████ ░░████████ █████     
░░░░░░░░░░   ░░░░░       ░░░░░░░░  ░███░░░   ░░░░░░░░ ░░░░░      
                                   ░███                          
                                   █████                         
                                  ░░░░░                          
 ██████   ██████                                                 
░░██████ ██████                                                  
 ░███░█████░███   ██████   ████████  ████████   ██████  ████████ 
 ░███░░███ ░███  ░░░░░███ ░░███░░███░░███░░███ ███░░███░░███░░███
 ░███ ░░░  ░███   ███████  ░███ ░███ ░███ ░███░███████  ░███ ░░░ 
 ░███      ░███  ███░░███  ░███ ░███ ░███ ░███░███░░░   ░███     
 █████     █████░░████████ ░███████  ░███████ ░░██████  █████    
░░░░░     ░░░░░  ░░░░░░░░  ░███░░░   ░███░░░   ░░░░░░  ░░░░░     
                           ░███      ░███                        
                           █████     █████                       
                          ░░░░░     ░░░░░                        
                Made By Taylor Christian Newsome
=================================================================
""")


# ==============================
# Config (defaults)
# ==============================
TIMEOUT = 5
THREADS = 30

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AdvancedDrupalScanner/3.0"
})

# ==============================
# CLI / Help
# ==============================
def parse_args():
    parser = argparse.ArgumentParser(
        prog="DrupalMapper",
        description="Advanced Drupal attack surface mapper and endpoint discovery tool.",
        epilog="Example: python3 drupalmapper.py https://target.com"
    )

    parser.add_argument("target", nargs="?", help="Target URL (e.g. https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=THREADS, help="Number of threads (default: 30)")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help="Request timeout (default: 5s)")

    return parser.parse_args()

# ==============================
# Sensitive Paths (FULL LIST)
# ==============================
sensitive_paths = list(set([
    # Core Drupal paths
    "core/install.php", "core/authorize.php", "core/rebuild.php", "core/modules/statistics/statistics.php",
    "core/modules/system/tests/https.php", "core/modules/system/tests/http.php", "autoload.php",
    "composer.json", "composer.lock", ".git", ".svn", ".DS_Store", ".well-known",
    "CHANGELOG.txt", "INSTALL.txt", "LICENSE.txt", "MAINTAINERS.txt", "README.txt", "UPGRADE.txt",
    "phpinfo.php", ".htaccess", "robots.txt", "web.config", ".env", ".htpasswd",
    "includes", "misc", "modules", "profiles", "scripts", "sites", "themes",
    
    # Admin paths
    "/admin", "/admin/config", "/admin/config/system", "/admin/config/people", "/admin/config/media",
    "/admin/appearance", "/admin/modules", "/admin/content", "/admin/reports", "/admin/structure",
    "/admin/structure/block", "/admin/structure/taxonomy", "/admin/structure/views", "/admin/structure/menu",
    "/admin/structure/paragraphs", "/admin/structure/layout", "/admin/structure/search",
    "/admin/structure/entity", "/admin/structure/migrate", "/admin/structure/fields", "/admin/structure/users",
    "/admin/structure/custom-blocks", "/admin/config/services", "/admin/config/media/image-style",
    "/admin/config/system/performance", "/admin/config/system/smtp", "/admin/config/search/search-api",
    "/admin/config/search/search-api/index", "/admin/config/search/search-api/server",
    "/admin/config/development/logging", "/admin/config/development/cache", "/admin/config/development/performance",
    "/admin/config/development/debugging", "/admin/config/development/redis", "/admin/config/development/override",
    "/admin/config/development/agentrace", "/admin/config/people/accounts", "/admin/config/people/password-policy",
    "/admin/config/people/roles", "/admin/config/people/permissions", "/admin/config/people/registration",
    "/admin/config/people/session", "/admin/config/people/login", "/admin/config/people/accounts/form",
    "/admin/config/people/roles/permissions", "/admin/config/people/roles/create", "/admin/config/people/roles/update",
    "/admin/config/people/roles/delete",
    
    # Content and nodes
    "/admin/content/{content_type}", "/admin/content/{content_type}/add",
    "/admin/content/{content_type}/edit/{node_id}", "/admin/content/{content_type}/delete/{node_id}",
    "/node/add", "/node/add/article", "/node/add/page", "/node/add/story",
    "/node/{nid}/edit", "/node/{nid}/delete", "/node/{nid}/view",

    # User endpoints
    "/user/login", "/user/logout", "/user/register", "/user/password",
    "/user/{uid}", "/user/{uid}/edit", "/user/{uid}/delete", "/user/{uid}/roles",
    "/user/{uid}/access", "/user/{uid}/content", "/user/{uid}/settings",
    "/user/{uid}/session", "/user/{uid}/password", "/user/{uid}/profile",
    "/user/{uid}/subscriptions", "/user/{uid}/posts", "/user/{uid}/comments",
    "/user/{uid}/notifications", "/user/{uid}/messages", "/user/{uid}/inbox",
    "/user/{uid}/outbox", "/user/{uid}/activity",

    # Core system paths
    "/core", "/core/misc", "/core/scripts", "/core/vendor", "/core/lib", "/core/themes", "/core/assets",
    "/sites/default/files/", "/sites/default/private/", "/sites/default/settings.php", "/sites/default/cron.php",

    # REST and entity endpoints
    "/rest/session/token", "/rest/views/{view_name}/page", "/rest/views/{view_name}/json",
    "/rest/views/{view_name}/rss", "/rest/views/{view_name}/xml", "/rest/{resource_name}",
    "/rest/{resource_name}/{id}", "/entity/{entity_type}/{id}", "/entity/{entity_type}/{id}/edit",
    "/entity/{entity_type}/{id}/delete", "/entity/{entity_type}/{id}/view", "/entity/{entity_type}/{id}/field",
    "/entity/{entity_type}/{id}/permissions", "/entity/{entity_type}/{id}/assign",
    "/entity/{entity_type}/{id}/parent", "/entity/{entity_type}/{id}/content",
    "/entity/{entity_type}/{id}/custom-fields", "/entity/{entity_type}/create",
    "/entity/{entity_type}/update", "/entity/{entity_type}/delete", "/entity/{entity_type}/views",
    "/entity/{entity_type}/manage", "/entity/{entity_type}/settings", "/entity/{entity_type}/rules",
    "/entity/{entity_type}/translations", "/entity/{entity_type}/variants", "/entity/{entity_type}/taxonomy",
    "/entity/{entity_type}/comments", "/entity/{entity_type}/comment-form", "/entity/{entity_type}/fields",
    "/entity/{entity_type}/view-form", "/entity/{entity_type}/create-form", "/entity/{entity_type}/edit-form",
    "/entity/{entity_type}/delete-form", "/entity/{entity_type}/field-edit", "/entity/{entity_type}/assign-roles",
    "/entity/{entity_type}/add-field", "/entity/{entity_type}/update-field", "/entity/{entity_type}/remove-field",
    "/entity/{entity_type}/update-permissions", "/entity/{entity_type}/parent/{parent_id}", "/entity/{entity_type}/children",
    "/entity/{entity_type}/structure", "/entity/{entity_type}/select", "/entity/{entity_type}/views/{view_name}",
    "/entity/{entity_type}/field/{field_name}", "/entity/{entity_type}/field/{field_name}/add",
    "/entity/{entity_type}/field/{field_name}/edit", "/entity/{entity_type}/field/{field_name}/delete",
    "/entity/{entity_type}/field/{field_name}/view", "/entity/{entity_type}/field/{field_name}/settings",
    "/entity/{entity_type}/field/{field_name}/permissions", "/entity/{entity_type}/field/{field_name}/value",
    "/entity/{entity_type}/field/{field_name}/translations", "/entity/{entity_type}/field/{field_name}/text",
    "/entity/{entity_type}/field/{field_name}/field-type", "/entity/{entity_type}/field/{field_name}/create",
    "/entity/{entity_type}/field/{field_name}/update", "/entity/{entity_type}/field/{field_name}/remove",
    "/entity/{entity_type}/field/{field_name}/delete-form", "/entity/{entity_type}/field/{field_name}/add-field",
    "/entity/{entity_type}/field/{field_name}/field-edit", "/entity/{entity_type}/field/{field_name}/edit-form",
    "/entity/{entity_type}/field/{field_name}/update-form", "/entity/{entity_type}/field/{field_name}/translations-form",
    "/entity/{entity_type}/field/{field_name}/delete-form", "/entity/{entity_type}/field/{field_name}/view-form",
    "/entity/{entity_type}/field/{field_name}/field-definition", "/entity/{entity_type}/field/{field_name}/create-form",
    "/entity/{entity_type}/field/{field_name}/edit-form", "/entity/{entity_type}/field/{field_name}/remove-form",
    "/entity/{entity_type}/field/{field_name}/view", "/entity/{entity_type}/field/{field_name}/permissions",
    "/entity/{entity_type}/field/{field_name}/field-type-form", "/entity/{entity_type}/field/{field_name}/field-definitions",
    "/entity/{entity_type}/field/{field_name}/value-form", "/entity/{entity_type}/field/{field_name}/text-form",
    "/entity/{entity_type}/field/{field_name}/value", "/entity/{entity_type}/field/{field_name}/remove",
    "/entity/{entity_type}/field/{field_name}/field-definition-form", "/entity/{entity_type}/field/{field_name}/permissions-form",
    "/robots.txt", "/crossdomain.xml", "/xmlrpc.php", "/update.php", "/about", "/help", "/donate",
    "/terms-of-service", "/privacy-policy", "/404"
]))

# ==============================
# Placeholder expansion values
# ==============================
placeholder_values = {
    "{uid}": ["1","2","admin"],
    "{nid}": ["1","2"],
    "{node_id}": ["1"],
    "{content_type}": ["article","page"],
    "{view_name}": ["default"],
    "{resource_name}": ["node","user"],
    "{entity_type}": ["node","user"],
    "{id}": ["1"],
    "{field_name}": ["body"],
    "{parent_id}": ["1"]
}

# ==============================
# Helpers
# ==============================
def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url.rstrip("/")

def expand_path(path):
    keys = [k for k in placeholder_values if k in path]
    if not keys:
        return [path]

    combos = list(itertools.product(*(placeholder_values[k] for k in keys)))
    results = []

    for combo in combos:
        temp = path
        for k, v in zip(keys, combo):
            temp = temp.replace(k, v)
        results.append(temp)

    return results

def check_path(base, path):
    url = f"{base}/{path.lstrip('/')}"
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)

        if r.status_code == 200:
            return f"[+] 200 OK        → {url}"
        elif r.status_code in (401,403):
            return f"[!] {r.status_code} PROTECTED → {url}"
        elif r.status_code in (301,302):
            return f"[~] REDIRECT     → {url}"
        return None

    except requests.RequestException:
        return None

# ==============================
# Scanner
# ==============================
def scan(url):
    url = normalize_url(url)

    print(f"\n[SCAN] Target: {url}\n")

    try:
        r = session.get(url, timeout=TIMEOUT)
    except Exception as e:
        print(f"[ERROR] {e}")
        return

    print("[HEADERS]")
    for h in ["X-Frame-Options","Content-Security-Policy","Strict-Transport-Security"]:
        print(f"{'[+]' if h in r.headers else '[-]'} {h}")

    print("\n[DIRECTORY LISTING]")
    if "index of" in r.text.lower():
        print("[!] Enabled")
    else:
        print("[+] Disabled")

    print("\n[EXPANDING PATHS]")
    all_paths = set()
    for p in sensitive_paths:
        all_paths.update(expand_path(p))

    print(f"[INFO] Total paths: {len(all_paths)}")

    print("\n[SCANNING]\n")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_path, url, p) for p in all_paths]

        for f in as_completed(futures):
            res = f.result()
            if res:
                print(res)

    print("\n[COMPLETE]\n")

# ==============================
# Entry
# ==============================
if __name__ == "__main__":
    args = parse_args()

    THREADS = args.threads
    TIMEOUT = args.timeout

    if not args.target:
        print("[-] No target specified.\n")
        print("Usage: python3 drupalmapper.py <target>")
        print("Try: python3 drupalmapper.py -h")
        sys.exit(1)

    scan(args.target)
