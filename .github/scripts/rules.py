#!/usr/bin/env python3
import os
import json
import requests
from ruamel.yaml import YAML

yaml = YAML(typ="safe")

def fetch_sources():
    # 假设这里是你需要下载的原始规则列表
    sources = [
      "https://raw.githubusercontent.com/.../list1.txt",
      "https://raw.githubusercontent.com/.../list2.yml"
    ]
    rules = {"domain": [], "ipcidr": []}
    for url in sources:
        resp = requests.get(url)
        content = resp.text
        if url.endswith(".txt"):
            rules["domain"] += content.splitlines()
        elif url.endswith(".yml") or url.endswith(".yaml"):
            data = yaml.load(content)
            # 你 YAML 里的结构如果不同，调整下面 key
            for item in data.get("rules", []):
                rules["domain"].append(item)
    return rules

def save_raw(rules):
    os.makedirs("out", exist_ok=True)
    # 把 domain/text/ipcidr 都先 dump 成 text
    with open("out/domain_rules.txt", "w") as f:
        for r in rules["domain"]:
            f.write(r + "\n")
    # 这里只是示例，若有 ipcidr 同样处理
    with open("out/ipcidr_rules.txt", "w") as f:
        for r in rules["ipcidr"]:
            f.write(r + "\n")

def main():
    print("Fetching sources...")
    rules = fetch_sources()

    # 确保 rules 是预期类型，不会是 string
    if not isinstance(rules, dict):
        print("ERROR: fetched rules not dict:", type(rules))
        return

    save_raw(rules)
    print("Saved raw rules")

if __name__ == "__main__":
    main()
