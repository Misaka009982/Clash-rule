import requests
import os
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

# 创建输出目录
output_dir = 'Rule'
os.makedirs(output_dir, exist_ok=True)

# 确保 Other 目录存在
other_dir = os.path.join(output_dir, 'Other')
os.makedirs(other_dir, exist_ok=True)

# 处理 list 文件
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
                    ipcidr.append(rule_value.split(',')[0])
        else:
            domains.append(line)

    # 🔒 空规则防护 + 去重
    domains = sorted({d.strip() for d in domains if d.strip()})
    ipcidr = sorted({i.strip() for i in ipcidr if i.strip()})

    return domains, ipcidr

# 处理自定义链接
def process_custom_link():
    try:
        api_url = "https://api.github.com/repos/Misaka09982/Clash/contents/Rules"
        response = requests.get(api_url)
        files = response.json()

        if not isinstance(files, list):
            print(f"自定义规则 API 返回异常: {files}")
            return

        for file in files:
            if file.get('type') == 'file' and file.get('name', '').endswith('.yaml'):
                raw_url = file.get('download_url')
                response = requests.get(raw_url)

                if response.status_code != 200:
                    print(f"无法下载 {file['name']}: HTTP {response.status_code}")
                    continue

                rule_name = os.path.splitext(file['name'])[0]

                try:
                    import yaml
                    rule_data = yaml.safe_load(response.text) or {}

                    domains = []
                    ipcidr = []

                    for rule in rule_data.get('payload', []):
                        parts = rule.split(',')
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
                                ipcidr.append(rule_value.split(',')[0])

                    # 🔒 空规则防护
                    domains = sorted({d.strip() for d in domains if d.strip()})
                    ipcidr = sorted({i.strip() for i in ipcidr if i.strip()})

                    if domains:
                        with open(os.path.join(other_dir, f"{rule_name}-domains.list"), 'w', encoding='utf-8') as f:
                            for d in domains:
                                f.write(d + '\n')

                    if ipcidr:
                        with open(os.path.join(other_dir, f"{rule_name}-ipcidr.list"), 'w', encoding='utf-8') as f:
                            for i in ipcidr:
                                f.write(i + '\n')

                    print(f"处理完成 {rule_name}: {len(domains)} 域名 / {len(ipcidr)} IP")

                except Exception as e:
                    print(f"解析 {file['name']} 失败: {e}")

    except Exception as e:
        print(f"处理自定义链接时出错: {e}")

# 处理 blackmatrix7 规则
def process_rule_file(rule_dir):
    rule_name = rule_dir['name']
    encoded_rule_name = urllib.parse.quote(rule_name)
    list_url = f"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/{encoded_rule_name}/{encoded_rule_name}.list"

    try:
        response = requests.get(list_url)
        if response.status_code != 200:
            print(f"无法下载 {rule_name}.list")
            return

        domains, ipcidr = process_list_file(response.text, rule_name)

        rule_output_dir = os.path.join(output_dir, rule_name)
        os.makedirs(rule_output_dir, exist_ok=True)

        if domains:
            with open(os.path.join(rule_output_dir, "domains.list"), 'w', encoding='utf-8') as f:
                for d in domains:
                    f.write(d + '\n')

        if ipcidr:
            with open(os.path.join(rule_output_dir, "ipcidr.list"), 'w', encoding='utf-8') as f:
                for i in ipcidr:
                    f.write(i + '\n')

        print(f"处理完成 {rule_name}: {len(domains)} 域名 / {len(ipcidr)} IP")

    except Exception as e:
        print(f"处理 {rule_name} 时出错: {e}")

# 主程序
def main():
    api_url = "https://api.github.com/repos/blackmatrix7/ios_rule_script/contents/rule/Clash"
    response = requests.get(api_url)
    directories = response.json()

    # 🔒 修复 TypeError 根因
    if not isinstance(directories, list):
        raise RuntimeError(f"GitHub API 返回异常: {directories}")

    rule_dirs = [item for item in directories if item.get('type') == 'dir']

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(process_rule_file, rule_dirs)

    process_custom_link()
    print("所有规则处理完成！")

if __name__ == "__main__":
    main()
