import yaml
import requests
import os
import json
from concurrent.futures import ThreadPoolExecutor

# 创建输出目录
output_dir = 'Rule'
os.makedirs(output_dir, exist_ok=True)

# 确保 Other 目录存在
other_dir = os.path.join(output_dir, 'Other')
os.makedirs(other_dir, exist_ok=True)

# 处理自定义链接
def process_custom_link():
    try:
        # 获取目录内容
        api_url = "https://api.github.com/repos/Misaka09982/Clash/contents/Rules"
        response = requests.get(api_url)
        files = json.loads(response.text)
        
        for file in files:
            if file['type'] == 'file' and file['name'].endswith('.yaml'):
                # 获取原始内容
                raw_url = file['download_url']
                response = requests.get(raw_url)
                
                if response.status_code != 200:
                    print(f"无法下载 {file['name']}: HTTP {response.status_code}")
                    continue
                
                # 解析YAML
                try:
                    rule_data = yaml.safe_load(response.text)
                except yaml.YAMLError:
                    print(f"解析 {file['name']} 失败")
                    continue
                
                # 提取规则名称（去除扩展名）
                rule_name = os.path.splitext(file['name'])[0]
                
                # 初始化域名和IP列表
                domains = []
                ipcidr = []
                
                # 解析规则
                for rule in rule_data.get('payload', []):
                    parts = rule.split(',')
                    if len(parts) >= 2:
                        rule_type = parts[0]
                        rule_value = parts[1]
                        
                        if rule_type == 'DOMAIN':
                            domains.append(rule_value)
                        elif rule_type == 'DOMAIN-SUFFIX':
                            # 将 DOMAIN-SUFFIX 转换为 +. 格式
                            domains.append(f'+.{rule_value}')
                        elif rule_type == 'DOMAIN-KEYWORD':
                            # 跳过关键词规则
                            pass
                        elif rule_type in ['IP-CIDR', 'IP-CIDR6']:
                            # 移除可能存在的 no-resolve 参数
                            cidr_value = rule_value.split(',')[0] if ',' in rule_value else rule_value
                            ipcidr.append(cidr_value)
                
                # 写入域名规则文件
                if domains:
                    with open(os.path.join(other_dir, f"{rule_name}-domains.list"), 'w') as f:
                        for domain in domains:
                            f.write(f'{domain}\n')
                
                # 写入IP规则文件
                if ipcidr:
                    with open(os.path.join(other_dir, f"{rule_name}-ipcidr.list"), 'w') as f:
                        for ip in ipcidr:
                            f.write(f'{ip}\n')
                
                print(f"处理完成 {rule_name}: {len(domains)} 个域名规则和 {len(ipcidr)} 个IP规则")
        
    except Exception as e:
        print(f"处理自定义链接时出错: {str(e)}")

# 处理 blackmatrix7 仓库中的规则
def process_rule_file(rule_dir):
    rule_name = rule_dir['name']
    yaml_url = f"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/{rule_name}/{rule_name}.list"
    
    try:
        response = requests.get(yaml_url)
        if response.status_code != 200:
            print(f"无法下载 {rule_name}.yaml: HTTP {response.status_code}")
            return
        
        # 解析YAML
        try:
            rule_data = yaml.safe_load(response.text)
        except yaml.YAMLError:
            print(f"解析 {rule_name}.yaml 失败")
            return
        
        # 初始化域名和IP列表
        domains = []
        ipcidr = []
        
        # 解析规则
        for rule in rule_data.get('payload', []):
            parts = rule.split(',')
            if len(parts) >= 2:
                rule_type = parts[0]
                rule_value = parts[1]
                
                if rule_type == 'DOMAIN':
                    domains.append(rule_value)
                elif rule_type == 'DOMAIN-SUFFIX':
                    # 将 DOMAIN-SUFFIX 转换为 +. 格式
                    domains.append(f'+.{rule_value}')
                elif rule_type == 'DOMAIN-KEYWORD':
                    # 跳过关键词规则
                    pass
                elif rule_type in ['IP-CIDR', 'IP-CIDR6']:
                    # 移除可能存在的 no-resolve 参数
                    cidr_value = rule_value.split(',')[0] if ',' in rule_value else rule_value
                    ipcidr.append(cidr_value)
        
        # 创建规则集子目录
        rule_output_dir = os.path.join(output_dir, rule_name)
        os.makedirs(rule_output_dir, exist_ok=True)
        
        # 写入域名规则文件
        if domains:
            with open(os.path.join(rule_output_dir, "domains.list"), 'w') as f:
                for domain in domains:
                    f.write(f'{domain}\n')
        
        # 写入IP规则文件
        if ipcidr:
            with open(os.path.join(rule_output_dir, "ipcidr.list"), 'w') as f:
                for ip in ipcidr:
                    f.write(f'{ip}\n')
        
        print(f"处理完成 {rule_name}: {len(domains)} 个域名规则和 {len(ipcidr)} 个IP规则")
    
    except Exception as e:
        print(f"处理 {rule_name} 时出错: {str(e)}")

# 主程序
def main():
    # GitHub API URL 获取目录内容
    api_url = "https://api.github.com/repos/blackmatrix7/ios_rule_script/contents/rule/Clash"
    response = requests.get(api_url)
    directories = json.loads(response.text)
    
    # 过滤出目录（排除文件）
    rule_dirs = [item for item in directories if item['type'] == 'dir']
    
    # 使用线程池并行处理所有规则
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(process_rule_file, rule_dirs)
    
    # 处理自定义链接
    process_custom_link()
    
    print("所有规则处理完成！")

if __name__ == "__main__":
    main()
