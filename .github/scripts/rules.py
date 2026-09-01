import os
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml


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

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(OTHER_DIR, exist_ok=True)


# ============================================================
# 通用文件操作
# ============================================================

def remove_file(path):
    """
    删除文件。
    文件不存在时忽略。
    """
    try:
        if os.path.isfile(path):
            os.remove(path)
            print(f"[DELETE] {path}")
    except OSError as e:
        print(f"[ERROR] Failed to delete {path}: {e}")


def remove_rule_files(path):
    """
    删除某个规则对应的所有生成文件。

    例如：
        domains.list
        domains.mrs
        domains.srs

    或：
        ipcidr.list
        ipcidr.mrs
        ipcidr.srs
    """
    base, _ = os.path.splitext(path)

    for target in (
        path,
        f"{base}.mrs",
        f"{base}.srs",
    ):
        remove_file(target)


def cleanup_empty_rule_dir(directory):
    """
    如果规则目录已经没有任何文件，则删除目录。
    """
    if not os.path.isdir(directory):
        return

    try:
        if not os.listdir(directory):
            os.rmdir(directory)
            print(f"[DELETE DIR] {directory}")
    except OSError:
        pass


# ============================================================
# Clash 规则解析
# ============================================================

def parse_clash_list(text: str):
    """
    解析 Clash .list。

    支持：
        DOMAIN
        DOMAIN-SUFFIX
        IP-CIDR
        IP-CIDR6

    输出：
        domains
        ipcidr
    """

    domains = set()
    ipcidr = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = [p.strip() for p in line.split(",")]

        if len(parts) < 2:
            continue

        rule_type = parts[0]
        value = parts[1]

        if not value:
            continue

        if rule_type == "DOMAIN":
            domains.add(value)

        elif rule_type == "DOMAIN-SUFFIX":
            domains.add(f"+.{value}")

        elif rule_type in ("IP-CIDR", "IP-CIDR6"):
            ipcidr.add(value)

    return sorted(domains), sorted(ipcidr)


# ============================================================
# 写入规则
# ============================================================

def write_list(path, items):
    """
    写入规则文件。

    items 有内容：
        覆盖写入

    items 为空：
        删除旧的 .list
        同时删除对应 .mrs / .srs
    """

    items = sorted(set(items))

    if items:
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(items) + "\n")

        print(f"[WRITE] {path}: {len(items)}")
        return

    # 上游已经没有这类规则
    remove_rule_files(path)


# ============================================================
# 清理一个 BlackMatrix 规则
# ============================================================

def clear_blackmatrix_rule(name):
    """
    上游规则不存在、404 或返回空内容时，
    删除本地旧规则。

    删除：
        Rule/<name>/domains.list
        Rule/<name>/domains.mrs
        Rule/<name>/domains.srs
        Rule/<name>/ipcidr.list
        Rule/<name>/ipcidr.mrs
        Rule/<name>/ipcidr.srs
    """

    out = os.path.join(BASE_DIR, name)

    remove_rule_files(
        os.path.join(out, "domains.list")
    )

    remove_rule_files(
        os.path.join(out, "ipcidr.list")
    )

    cleanup_empty_rule_dir(out)


# ============================================================
# BlackMatrix
# ============================================================

def process_blackmatrix(rule):
    """
    下载并处理单个 BlackMatrix 规则。

    状态处理：

    200 + 有规则
        -> 更新本地文件

    200 + 空规则
        -> 删除旧规则

    404
        -> 删除旧规则

    其他 HTTP 错误
        -> 保留旧规则

    网络异常 / 超时
        -> 保留旧规则
    """

    name = rule.get("name")

    if not name:
        return False

    enc = urllib.parse.quote(name, safe="")

    url = (
        f"{BLACKMATRIX_RAW}/"
        f"{enc}/"
        f"{enc}.list"
    )

    try:
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as e:
        print(
            f"[ERROR] {name}: "
            f"request failed: {e}"
        )
        print(
            f"[KEEP] {name}: "
            f"keep existing files"
        )
        return False

    # --------------------------------------------------------
    # 404：规则已经从上游删除
    # --------------------------------------------------------

    if r.status_code == 404:
        print(
            f"[404] {name}: "
            f"upstream rule not found"
        )

        clear_blackmatrix_rule(name)
        return True

    # --------------------------------------------------------
    # 非 200：可能是临时故障
    # 不删除本地旧规则
    # --------------------------------------------------------

    if r.status_code != 200:
        print(
            f"[ERROR] {name}: "
            f"HTTP {r.status_code}"
        )
        print(
            f"[KEEP] {name}: "
            f"keep existing files"
        )
        return False

    # --------------------------------------------------------
    # 正常解析
    # --------------------------------------------------------

    domains, ipcidr = parse_clash_list(r.text)

    out = os.path.join(BASE_DIR, name)

    # --------------------------------------------------------
    # 上游成功返回，但是整个文件为空
    # --------------------------------------------------------

    if not domains and not ipcidr:
        print(
            f"[EMPTY] {name}: "
            f"upstream returned no rules"
        )

        clear_blackmatrix_rule(name)
        return True

    # --------------------------------------------------------
    # 正常写入
    # --------------------------------------------------------

    os.makedirs(out, exist_ok=True)

    write_list(
        os.path.join(out, "domains.list"),
        domains
    )

    write_list(
        os.path.join(out, "ipcidr.list"),
        ipcidr
    )

    print(
        f"[OK] {name}: "
        f"{len(domains)} domains / "
        f"{len(ipcidr)} ip"
    )

    return True


# ============================================================
# 获取 BlackMatrix 规则列表
# ============================================================

def get_blackmatrix_rules():
    """
    获取 BlackMatrix 当前所有规则目录。

    返回：
        list
    """

    try:
        r = requests.get(
            BLACKMATRIX_API,
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as e:
        print(
            f"[ERROR] Failed to fetch "
            f"BlackMatrix rule list: {e}"
        )
        return None

    if r.status_code != 200:
        print(
            f"[ERROR] BlackMatrix API "
            f"HTTP {r.status_code}"
        )
        return None

    try:
        data = r.json()
    except ValueError as e:
        print(
            f"[ERROR] Invalid BlackMatrix API "
            f"response: {e}"
        )
        return None

    if not isinstance(data, list):
        print(
            "[ERROR] BlackMatrix API "
            "response is not a list"
        )
        return None

    return [
        item
        for item in data
        if item.get("type") == "dir"
        and item.get("name")
    ]


# ============================================================
# BlackMatrix 旧规则清理
# ============================================================

def cleanup_stale_blackmatrix_rules(current_rules):
    """
    如果 BlackMatrix 某个规则目录已经被删除，
    但本地仓库还留着，则删除本地旧规则。

    注意：
        只有成功拿到完整上游规则列表时才执行。
        如果 API 本身失败，则绝不会执行这里，
        防止网络异常造成整库被清空。
    """

    current_names = {
        rule["name"]
        for rule in current_rules
        if rule.get("name")
    }

    if not os.path.isdir(BASE_DIR):
        return

    for name in os.listdir(BASE_DIR):
        if name == "Other":
            continue

        path = os.path.join(BASE_DIR, name)

        if not os.path.isdir(path):
            continue

        if name not in current_names:
            print(
                f"[STALE] BlackMatrix rule removed upstream: "
                f"{name}"
            )

            clear_blackmatrix_rule(name)


# ============================================================
# Custom Rules
# ============================================================

def clear_custom_rule(name):
    """
    删除 Rule/Other 下对应规则的全部生成文件。
    """

    remove_rule_files(
        os.path.join(
            OTHER_DIR,
            f"{name}-domains.list"
        )
    )

    remove_rule_files(
        os.path.join(
            OTHER_DIR,
            f"{name}-ipcidr.list"
        )
    )


def process_custom():
    """
    获取自定义规则仓库：

        Misaka09982/Clash/Rules

    规则格式：

        payload:
          - DOMAIN,example.com
          - DOMAIN-SUFFIX,google.com
          - IP-CIDR,1.1.1.0/24
    """

    try:
        r = requests.get(
            CUSTOM_API,
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as e:
        print(
            f"[ERROR] Failed to fetch custom "
            f"rule list: {e}"
        )
        return False

    if r.status_code != 200:
        print(
            f"[ERROR] Custom API "
            f"HTTP {r.status_code}"
        )
        print(
            "[KEEP] Existing custom rules"
        )
        return False

    try:
        files = r.json()
    except ValueError as e:
        print(
            f"[ERROR] Invalid custom API "
            f"response: {e}"
        )
        return False

    if not isinstance(files, list):
        print(
            "[ERROR] Custom API "
            "response is not a list"
        )
        return False

    current_names = set()

    for item in files:

        if item.get("type") != "file":
            continue

        filename = item.get("name", "")

        if not filename.endswith(".yaml"):
            continue

        download_url = item.get("download_url")

        if not download_url:
            continue

        name = filename.rsplit(".", 1)[0]

        current_names.add(name)

        try:
            rr = requests.get(
                download_url,
                timeout=REQUEST_TIMEOUT
            )

        except requests.RequestException as e:
            print(
                f"[ERROR] Other/{name}: "
                f"request failed: {e}"
            )
            print(
                f"[KEEP] Other/{name}: "
                f"keep existing files"
            )
            continue

        if rr.status_code == 404:
            print(
                f"[404] Other/{name}"
            )
            clear_custom_rule(name)
            continue

        if rr.status_code != 200:
            print(
                f"[ERROR] Other/{name}: "
                f"HTTP {rr.status_code}"
            )
            print(
                f"[KEEP] Other/{name}: "
                f"keep existing files"
            )
            continue

        # --------------------------------------------
        # YAML
        # --------------------------------------------

        try:
            data = yaml.safe_load(rr.text) or {}

        except yaml.YAMLError as e:
            print(
                f"[ERROR] Other/{name}: "
                f"invalid YAML: {e}"
            )
            print(
                f"[KEEP] Other/{name}: "
                f"keep existing files"
            )
            continue

        domains = set()
        ipcidr = set()

        payload = data.get("payload", [])

        if not isinstance(payload, list):
            payload = []

        for rule in payload:

            if not isinstance(rule, str):
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

            if rule_type == "DOMAIN":
                domains.add(value)

            elif rule_type == "DOMAIN-SUFFIX":
                domains.add(f"+.{value}")

            elif rule_type in (
                "IP-CIDR",
                "IP-CIDR6"
            ):
                ipcidr.add(value)

        # --------------------------------------------
        # 上游 YAML 正常，但没有规则
        # --------------------------------------------

        if not domains and not ipcidr:
            print(
                f"[EMPTY] Other/{name}: "
                f"upstream returned no rules"
            )

            clear_custom_rule(name)
            continue

        # --------------------------------------------
        # 正常写入
        # --------------------------------------------

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
    # 清理上游已经删除的自定义 YAML
    # --------------------------------------------------------

    cleanup_stale_custom_rules(
        current_names
    )

    return True


# ============================================================
# Custom 旧规则清理
# ============================================================

def cleanup_stale_custom_rules(current_names):
    """
    如果自定义仓库中 YAML 已经被删除，
    则删除 Rule/Other 中对应旧规则。

    只有在 API 请求成功后才调用。
    """

    if not os.path.isdir(OTHER_DIR):
        return

    existing_names = set()

    for filename in os.listdir(OTHER_DIR):

        if filename.endswith(
            "-domains.list"
        ):
            existing_names.add(
                filename[:-len("-domains.list")]
            )

        elif filename.endswith(
            "-ipcidr.list"
        ):
            existing_names.add(
                filename[:-len("-ipcidr.list")]
            )

    stale_names = (
        existing_names - current_names
    )

    for name in sorted(stale_names):
        print(
            f"[STALE] Custom rule removed upstream: "
            f"{name}"
        )

        clear_custom_rule(name)


# ============================================================
# 主程序
# ============================================================

def main():

    print("========================================")
    print("Clash-rule generator")
    print("========================================")

    # ========================================================
    # BlackMatrix
    # ========================================================

    print("")
    print("=== Fetch BlackMatrix rules ===")

    rules = get_blackmatrix_rules()

    if rules is None:
        print(
            "[ERROR] BlackMatrix rule list "
            "could not be fetched."
        )

        print(
            "[KEEP] Existing BlackMatrix "
            "rules will NOT be removed."
        )

        blackmatrix_ok = False

    else:
        blackmatrix_ok = True

        print(
            f"[INFO] Found {len(rules)} "
            f"BlackMatrix rules"
        )

        # ----------------------------------------------------
        # 并发处理
        # ----------------------------------------------------

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as pool:

            futures = [
                pool.submit(
                    process_blackmatrix,
                    rule
                )
                for rule in rules
            ]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(
                        f"[ERROR] Worker exception: {e}"
                    )

        # ----------------------------------------------------
        # 清理已经从上游删除的目录
        # ----------------------------------------------------

        cleanup_stale_blackmatrix_rules(
            rules
        )

    # ========================================================
    # Custom
    # ========================================================

    print("")
    print("=== Fetch Custom rules ===")

    process_custom()

    # ========================================================
    # 完成
    # ========================================================

    print("")
    print("========================================")
    print("All rules done.")
    print("========================================")


if __name__ == "__main__":
    main()

