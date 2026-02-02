import requests
import os
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import yaml

BASE_DIR = "Rule"
OTHER_DIR = os.path.join(BASE_DIR, "Other")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(OTHER_DIR, exist_ok=True)


def parse_clash_list(text: str):
    domains, ipcidr = set(), set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue

        t, v = parts[0], parts[1]

        if t == "DOMAIN":
            domains.add(v)
        elif t == "DOMAIN-SUFFIX":
            domains.add(f"+.{v}")
        elif t in ("IP-CIDR", "IP-CIDR6"):
            ipcidr.add(v)

    return sorted(domains), sorted(ipcidr)


def write_list(path, items):
    if not items:
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(items) + "\n")


def process_blackmatrix(rule):
    name = rule["name"]
    enc = urllib.parse.quote(name)
    url = f"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/{enc}/{enc}.list"

    r = requests.get(url, timeout=30)
    if r.status_code != 200:
        print(f"[SKIP] {name}")
        return

    domains, ipcidr = parse_clash_list(r.text)

    if not domains and not ipcidr:
        print(f"[EMPTY] {name}")
        return

    out = os.path.join(BASE_DIR, name)
    os.makedirs(out, exist_ok=True)

    write_list(os.path.join(out, "domains.list"), domains)
    write_list(os.path.join(out, "ipcidr.list"), ipcidr)

    print(f"[OK] {name}: {len(domains)} domains / {len(ipcidr)} ip")


def process_custom():
    api = "https://api.github.com/repos/Misaka09982/Clash/contents/Rules"
    r = requests.get(api, timeout=30)
    files = r.json()

    if not isinstance(files, list):
        return

    for f in files:
        if f.get("type") != "file" or not f["name"].endswith(".yaml"):
            continue

        name = f["name"].rsplit(".", 1)[0]
        text = requests.get(f["download_url"], timeout=30).text
        data = yaml.safe_load(text) or {}

        domains, ipcidr = set(), set()

        for rule in data.get("payload", []):
            parts = rule.split(",")
            if len(parts) < 2:
                continue

            t, v = parts[0], parts[1]
            if t == "DOMAIN":
                domains.add(v)
            elif t == "DOMAIN-SUFFIX":
                domains.add(f"+.{v}")
            elif t in ("IP-CIDR", "IP-CIDR6"):
                ipcidr.add(v)

        write_list(os.path.join(OTHER_DIR, f"{name}-domains.list"), sorted(domains))
        write_list(os.path.join(OTHER_DIR, f"{name}-ipcidr.list"), sorted(ipcidr))

        print(f"[OK] Other/{name}")


def main():
    api = "https://api.github.com/repos/blackmatrix7/ios_rule_script/contents/rule/Clash"
    r = requests.get(api, timeout=30)
    rules = [i for i in r.json() if i.get("type") == "dir"]

    with ThreadPoolExecutor(max_workers=10) as pool:
        pool.map(process_blackmatrix, rules)

    process_custom()
    print("All rules done.")


if __name__ == "__main__":
    main()
