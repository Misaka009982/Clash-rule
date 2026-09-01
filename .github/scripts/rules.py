#!/usr/bin/env python3

import ipaddress
import os
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml


# ============================================================
# 配置
# ============================================================

BASE_DIR = "Rule"
OTHER_DIR = os.path.join(BASE_DIR, "Other")

BLACKMATRIX_API = (
    "https://api.github.com/repos/"
    "blackmatrix7/ios_rule_script/contents/rule/Clash"
)

BLACKMATRIX_RAW = (
    "https://raw.githubusercontent.com/"
    "blackmatrix7/ios_rule_script/master/rule/Clash"
)

CUSTOM_API = (
    "https://api.github.com/repos/"
    "Misaka09982/Clash/contents/Rules"
)

MAX_WORKERS = 10
REQUEST_TIMEOUT = 30


# ============================================================
# 初始化目录
# ============================================================

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(OTHER_DIR, exist_ok=True)


# ============================================================
# 工具
# ============================================================

def remove_file(path):
    """
    安全删除文件。
    """
    try:
        if os.path.isfile(path):
            os.remove(path)
            print(f"[DELETE] {path}")
    except OSError as e:
        print(f"[WARN] Failed to delete {path}: {e}")


def remove_generated_files(path):
    """
    根据 .list 删除对应的：

        .list
        .mrs
        .srs
    """

    base, ext = os.path.splitext(path)

    targets = [
        path,
        base + ".mrs",
        base + ".srs",
    ]

    for target in targets:
        remove_file(target)


def cleanup_empty_dir(path):
    """
    删除空目录。
    """
    if not os.path.isdir(path):
        return

    try:
        if not os.listdir(path):
            os.rmdir(path)
            print(f"[DELETE DIR] {path}")
    except OSError:
        pass


# ============================================================
# IPv4 / IPv6 清洗
# ============================================================

def normalize_ipcidr(value):
    """
    标准化 IP-CIDR / IP-CIDR6。

    修复上游可能出现的：

        2001:678\\:b28::118

    →   2001:678:b28::118

    同时将纯 IP：

        1.2.3.4

    转成：

        1.2.3.4/32

    IPv6：

        2001:db8::1

    转成：

        2001:db8::1/128

    已经带 CIDR 的保持不变。
    """

    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    # 修复错误转义
    value = value.replace("\\:", ":")

    # 某些来源可能带空白
    value = value.strip()

    # 解析 CIDR / IP
    try:
        if "/" in value:
            network = ipaddress.ip_network(
                value,
                strict=False
            )

            return str(network)

        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            return f"{ip}/32"

        return f"{ip}/128"

    except ValueError:
        print(
            f"[INVALID IP] {value}"
        )
        return None


# ============================================================
# Clash list 解析
# ============================================================

def parse_clash_list(text):
    """
    解析 Clash 规则。

    支持：

        DOMAIN
        DOMAIN-SUFFIX
        IP-CIDR
        IP-CIDR6
    """

    domains = set()
    ipcidr = set()

    for raw_line in text.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        parts = [
            p.strip()
            for p in line.split(",")
        ]

        if len(parts) < 2:
            continue

        rule_type = parts[0]
        value = parts[1]

        if not value:
            continue

        # ----------------------------------------
        # DOMAIN
        # ----------------------------------------

        if rule_type == "DOMAIN":
            domains.add(value)

        # ----------------------------------------
        # DOMAIN-SUFFIX
        # ----------------------------------------

        elif rule_type == "DOMAIN-SUFFIX":
            domains.add(
                f"+.{value}"
            )

        # ----------------------------------------
        # IP-CIDR
        # ----------------------------------------

        elif rule_type in (
            "IP-CIDR",
            "IP-CIDR6"
        ):

            normalized = normalize_ipcidr(
                value
            )

            if normalized:
                ipcidr.add(normalized)

    return (
        sorted(domains),
        sorted(ipcidr)
    )


# ============================================================
# 写入 list
# ============================================================

def write_list(path, items):
    """
    写入规则文件。

    有规则：
        覆盖写入

    无规则：
        删除旧的 .list/.mrs/.srs
    """

    items = sorted(set(items))

    if items:

        directory = os.path.dirname(path)

        if directory:
            os.makedirs(
                directory,
                exist_ok=True
            )

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as f:
            f.write(
                "\n".join(items)
                + "\n"
            )

        print(
            f"[WRITE] {path}: "
            f"{len(items)}"
        )

    else:

        print(
            f"[EMPTY] {path}"
        )

        remove_generated_files(
            path
        )


# ============================================================
# 清理 BlackMatrix 规则
# ============================================================

def clear_blackmatrix_rule(name):
    """
    删除整个：

        Rule/<name>/
    """

    out = os.path.join(
        BASE_DIR,
        name
    )

    remove_generated_files(
        os.path.join(
            out,
            "domains.list"
        )
    )

    remove_generated_files(
        os.path.join(
            out,
            "ipcidr.list"
        )
    )

    cleanup_empty_dir(out)


# ============================================================
# BlackMatrix 单规则
# ============================================================

def process_blackmatrix(rule):
    """
    处理单个 BlackMatrix 规则。

    处理策略：

    200 + 有规则
        更新

    200 + 空规则
        删除旧规则

    404
        删除旧规则

    其他 HTTP
        保留旧规则

    网络异常
        保留旧规则
    """

    name = rule.get("name")

    if not name:
        return

    encoded_name = urllib.parse.quote(
        name,
        safe=""
    )

    url = (
        f"{BLACKMATRIX_RAW}/"
        f"{encoded_name}/"
        f"{encoded_name}.list"
    )

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as e:

        print(
            f"[ERROR] {name}: "
            f"{e}"
        )

        print(
            f"[KEEP] {name}"
        )

        return

    # --------------------------------------------------------
    # 404
    # --------------------------------------------------------

    if response.status_code == 404:

        print(
            f"[404] {name}"
        )

        clear_blackmatrix_rule(
            name
        )

        return

    # --------------------------------------------------------
    # 其他 HTTP 错误
    # --------------------------------------------------------

    if response.status_code != 200:

        print(
            f"[HTTP {response.status_code}] "
            f"{name}"
        )

        print(
            f"[KEEP] {name}"
        )

        return

    # --------------------------------------------------------
    # 解析
    # --------------------------------------------------------

    domains, ipcidr = parse_clash_list(
        response.text
    )

    # --------------------------------------------------------
    # 上游为空
    # --------------------------------------------------------

    if not domains and not ipcidr:

        print(
            f"[EMPTY] {name}: "
            f"upstream returned no rules"
        )

        clear_blackmatrix_rule(
            name
        )

        return

    # --------------------------------------------------------
    # 正常写入
    # --------------------------------------------------------

    out = os.path.join(
        BASE_DIR,
        name
    )

    os.makedirs(
        out,
        exist_ok=True
    )

    write_list(
        os.path.join(
            out,
            "domains.list"
        ),
        domains
    )

    write_list(
        os.path.join(
            out,
            "ipcidr.list"
        ),
        ipcidr
    )

    print(
        f"[OK] {name}: "
        f"{len(domains)} domains / "
        f"{len(ipcidr)} ip"
    )


# ============================================================
# 获取 BlackMatrix 当前规则
# ============================================================

def get_blackmatrix_rules():
    """
    获取 BlackMatrix 当前规则目录。
    """

    try:
        response = requests.get(
            BLACKMATRIX_API,
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as e:

        print(
            f"[ERROR] BlackMatrix API: "
            f"{e}"
        )

        return None

    if response.status_code != 200:

        print(
            f"[ERROR] BlackMatrix API "
            f"HTTP {response.status_code}"
        )

        return None

    try:
        data = response.json()

    except ValueError as e:

        print(
            f"[ERROR] Invalid BlackMatrix "
            f"JSON: {e}"
        )

        return None

    if not isinstance(data, list):

        print(
            "[ERROR] BlackMatrix API "
            "did not return a list"
        )

        return None

    rules = [
        item
        for item in data
        if (
            item.get("type") == "dir"
            and item.get("name")
        )
    ]

    return rules


# ============================================================
# 清理 BlackMatrix 已删除规则
# ============================================================

def cleanup_stale_blackmatrix_rules(
    rules
):
    """
    如果上游已经删除了整个规则目录，
    本地也删除。

    只有 API 成功时才执行。
    """

    current_names = {
        item["name"]
        for item in rules
        if item.get("name")
    }

    for name in os.listdir(BASE_DIR):

        if name == "Other":
            continue

        path = os.path.join(
            BASE_DIR,
            name
        )

        if not os.path.isdir(path):
            continue

        if name not in current_names:

            print(
                f"[STALE] Removed upstream: "
                f"{name}"
            )

            clear_blackmatrix_rule(
                name
            )


# ============================================================
# Custom
# ============================================================

def clear_custom_rule(name):
    """
    删除：

        Rule/Other/<name>-domains.list
        Rule/Other/<name>-ipcidr.list

    以及对应 MRS / SRS。
    """

    remove_generated_files(
        os.path.join(
            OTHER_DIR,
            f"{name}-domains.list"
        )
    )

    remove_generated_files(
        os.path.join(
            OTHER_DIR,
            f"{name}-ipcidr.list"
        )
    )


# ============================================================
# Custom YAML 解析
# ============================================================

def process_custom():
    """
    读取自定义规则仓库：

        Misaka09982/Clash/Rules

    处理 YAML 中的 payload。
    """

    try:
        response = requests.get(
            CUSTOM_API,
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as e:

        print(
            f"[ERROR] Custom API: "
            f"{e}"
        )

        print(
            "[KEEP] Existing custom rules"
        )

        return False

    if response.status_code != 200:

        print(
            f"[ERROR] Custom API "
            f"HTTP {response.status_code}"
        )

        print(
            "[KEEP] Existing custom rules"
        )

        return False

    try:
        files = response.json()

    except ValueError:

        print(
            "[ERROR] Invalid custom API JSON"
        )

        return False

    if not isinstance(files, list):

        print(
            "[ERROR] Custom API response "
            "is not a list"
        )

        return False

    current_names = set()

    for item in files:

        if item.get("type") != "file":
            continue

        filename = item.get(
            "name",
            ""
        )

        if not filename.endswith(
            ".yaml"
        ):
            continue

        name = filename.rsplit(
            ".",
            1
        )[0]

        current_names.add(name)

        download_url = item.get(
            "download_url"
        )

        if not download_url:
            continue

        # ----------------------------------------------------
        # 下载 YAML
        # ----------------------------------------------------

        try:
            response_yaml = requests.get(
                download_url,
                timeout=REQUEST_TIMEOUT
            )

        except requests.RequestException as e:

            print(
                f"[ERROR] Other/{name}: "
                f"{e}"
            )

            print(
                f"[KEEP] Other/{name}"
            )

            continue

        # ----------------------------------------------------
        # 404
        # ----------------------------------------------------

        if response_yaml.status_code == 404:

            print(
                f"[404] Other/{name}"
            )

            clear_custom_rule(
                name
            )

            continue

        # ----------------------------------------------------
        # HTTP error
        # ----------------------------------------------------

        if response_yaml.status_code != 200:

            print(
                f"[HTTP "
                f"{response_yaml.status_code}] "
                f"Other/{name}"
            )

            print(
                f"[KEEP] Other/{name}"
            )

            continue

        # ----------------------------------------------------
        # YAML
        # ----------------------------------------------------

        try:
            data = (
                yaml.safe_load(
                    response_yaml.text
                )
                or {}
            )

        except yaml.YAMLError as e:

            print(
                f"[ERROR] Other/{name}: "
                f"invalid YAML: {e}"
            )

            print(
                f"[KEEP] Other/{name}"
            )

            continue

        domains = set()
        ipcidr = set()

        payload = data.get(
            "payload",
            []
        )

        if not isinstance(
            payload,
            list
        ):
            payload = []

        # ----------------------------------------------------
        # 解析 payload
        # ----------------------------------------------------

        for rule in payload:

            if not isinstance(
                rule,
                str
            ):
                continue

            parts = [
                p.strip()
                for p in rule.split(",")
            ]

            if len(parts) < 2:
                continue

            rule_type = parts[0]
            value = parts[1]

            if not value:
                continue

            # DOMAIN
            if rule_type == "DOMAIN":

                domains.add(
                    value
                )

            # DOMAIN-SUFFIX
            elif rule_type == "DOMAIN-SUFFIX":

                domains.add(
                    f"+.{value}"
                )

            # IP
            elif rule_type in (
                "IP-CIDR",
                "IP-CIDR6"
            ):

                normalized = (
                    normalize_ipcidr(
                        value
                    )
                )

                if normalized:
                    ipcidr.add(
                        normalized
                    )

        # ----------------------------------------------------
        # 空规则
        # ----------------------------------------------------

        if not domains and not ipcidr:

            print(
                f"[EMPTY] Other/{name}"
            )

            clear_custom_rule(
                name
            )

            continue

        # ----------------------------------------------------
        # 写入
        # ----------------------------------------------------

        write_list(
            os.path.join(
                OTHER_DIR,
                f"{name}-domains.list"
            ),
            sorted(domains)
        )

        write_list(
            os.path.join(
                OTHER_DIR,
                f"{name}-ipcidr.list"
            ),
            sorted(ipcidr)
        )

        print(
            f"[OK] Other/{name}: "
            f"{len(domains)} domains / "
            f"{len(ipcidr)} ip"
        )

    # --------------------------------------------------------
    # 清理上游删除的 YAML
    # --------------------------------------------------------

    cleanup_stale_custom_rules(
        current_names
    )

    return True


# ============================================================
# 清理已经不存在的 Custom 规则
# ============================================================

def cleanup_stale_custom_rules(
    current_names
):
    """
    如果 Custom 仓库中的 YAML 已经删除，
    本地也删除。
    """

    if not os.path.isdir(
        OTHER_DIR
    ):
        return

    existing_names = set()

    for filename in os.listdir(
        OTHER_DIR
    ):

        if filename.endswith(
            "-domains.list"
        ):

            existing_names.add(
                filename[
                    :-len("-domains.list")
                ]
            )

        elif filename.endswith(
            "-ipcidr.list"
        ):

            existing_names.add(
                filename[
                    :-len("-ipcidr.list")
                ]
            )

    stale = (
        existing_names
        - current_names
    )

    for name in sorted(stale):

        print(
            f"[STALE] Custom removed: "
            f"{name}"
        )

        clear_custom_rule(
            name
        )


# ============================================================
# Main
# ============================================================

def main():

    print(
        "========================================"
    )

    print(
        "Clash-rule generator"
    )

    print(
        "========================================"
    )

    # ========================================================
    # BlackMatrix
    # ========================================================

    print("")
    print(
        "=== BlackMatrix ==="
    )

    rules = get_blackmatrix_rules()

    if rules is None:

        print(
            "[KEEP] BlackMatrix rules"
        )

    else:

        print(
            f"[INFO] Found "
            f"{len(rules)} rules"
        )

        # ----------------------------------------------------
        # 并发下载
        # ----------------------------------------------------

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as executor:

            futures = [
                executor.submit(
                    process_blackmatrix,
                    rule
                )
                for rule in rules
            ]

            for future in as_completed(
                futures
            ):

                try:
                    future.result()

                except Exception as e:

                    print(
                        f"[ERROR] Worker: "
                        f"{e}"
                    )

        # ----------------------------------------------------
        # 清理已经被删除的规则
        # ----------------------------------------------------

        cleanup_stale_blackmatrix_rules(
            rules
        )

    # ========================================================
    # Custom
    # ========================================================

    print("")
    print(
        "=== Custom Rules ==="
    )

    process_custom()

    # ========================================================
    # Done
    # ========================================================

    print("")
    print(
        "========================================"
    )

    print(
        "All rules done."
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()

