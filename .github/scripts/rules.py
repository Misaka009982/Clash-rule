import requests
import os
import json
import urllib.parse
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# 创建输出目录
output_dir = 'Rule'
os.makedirs(output_dir, exist_ok=True)

# 确保 Other 目录存在
other_dir = os.path.join(output_dir, 'Other')
os.makedirs(other_dir, exist_ok=True)

# ---------- 工具函数 ----------

def normalize_ipcidr(value: str):
    value = value.strip()
    if not value:
        return None
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
            return value
        ip = ipaddress.ip_address(value)
        return f"{value}/32" if ip.version == 4 else f"{value}/128"
    except ValueError:
        return None

# ---------- 处理 list 文件 ----------

def process_list_file(response_text, rule_name):
    domains = []
    ipcidr = []

    for line in response_text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        if ',' in line:
            parts = line.split(',')
            if len(parts) >= 2:
                rule_type = parts[0]
                rule_value = parts[1]

                if rule_type == 'DOMAIN':
                    domains.append(rule_value)
                elif rule_type == 'DOMAIN-SUFFIX':
                    domains.append(f'+.{rule_value}')
                elif rule_type == 'DOMAIN-KEYWORD':
                    pass
                elif rule_type in ['IP-CIDR', 'IP-CIDR6']:
                    fixed = normalize_ipcidr(rule_value)
                    if fixed:
                        ipcidr.append(fixed)
        else:
            domains.append(line)

    domains = sorted({d.strip() for d in domains if d.strip()})
    ipcidr = sorted({i.strip() for i in ipcidr if i.strip()})

    return domains, ipcidr

# ---------- 自定义规则 ----------

def process_custom_link():
    try:
        api_url = "https://api.github.com/repos/Misaka09982/Clash/contents/Rules"
        files = requests.get(api_url).json()

        if not isinstance(files, list):
            print(f"自定义规则 API 返回异常: {files}")
            return

        for file in files:
            if file.get('type') == 'file' and file['name'].endswith('.yaml'):
                raw_url = file['download_url']
                response = requests.get(raw_url)
                if response.status_code != 200:
                    continue

                rule_name = os.path.splitext(file['name'])[0]

                try:
                    import yaml
                    rule_data = yaml.safe_load(response.text) or {}
                    domains, ipcidr = [], []

                    for rule in rule_data.get('payload', []):
                        parts = rule.split(',')
                        if len(parts) >= 2:
                            rule_type, rule_value = parts[0], parts[1]

                            if rule_type == 'DOMAIN':
                                domains.append(rule_value)
                            elif rule_type == 'DOMAIN-SUFFIX':
                                domains.append(f'+.{rule_value}')
                            elif rule_type in ['IP-CIDR', 'IP-CIDR6']:
                                fixed = normalize_ipcidr(rule_value)
                                if fixed:
                                    ipcidr.append(fixed)

                    domains = sorted(set(domains))
                    ipcidr = sorted(set(ipcidr))

                    if domains:
                        with open(os.path.join(other_dir, f"{rule_name}-domains.list"), 'w', encoding='utf-8') as f:
                            f.write('\n'.join(domains) + '\n')

                    if ipcidr:
                        with open(os.path.join(other_dir, f"{rule_name}-ipcidr.list"), 'w', encoding='utf-8') as f:
                            f.write('\n'.join(ipcidr) + '\n')

                except Exception as e:
                    print(f"{rule_name} 解析失败: {e}")

    except Exception as e:
        print(f"自定义规则处理失败: {e}")

# ---------- blackmatrix7 ----------

def process_rule_file(rule_dir):
    rule_name = rule_dir['name']
    encoded = urllib.parse.quote(rule_name)
    url = f"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/{encoded}/{encoded}.list"

    response = requests.get(url)
    if response.status_code != 200:
        return

    domains, ipcidr = process_list_file(response.text, rule_name)

    if not domains and not ipcidr:
        return

    rule_output_dir = os.path.join(output_dir, rule_name)
    os.makedirs(rule_output_dir, exist_ok=True)

    if domains:
        with open(os.path.join(rule_output_dir, "domains.list"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(domains) + '\n')

    if ipcidr:
        with open(os.path.join(rule_output_dir, "ipcidr.list"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(ipcidr) + '\n')

# ---------- 主入口 ----------

def main():
    api_url = "https://api.github.com/repos/blackmatrix7/ios_rule_script/contents/rule/Clash"
    directories = requests.get(api_url).json()

    if not isinstance(directories, list):
        raise RuntimeError("GitHub API 返回异常")

    rule_dirs = [i for i in directories if i.get('type') == 'dir']

    with ThreadPoolExecutor(max_workers=10) as pool:
        pool.map(process_rule_file, rule_dirs)

    process_custom_link()
    print("规则生成完成")

if __name__ == "__main__":
    main()
