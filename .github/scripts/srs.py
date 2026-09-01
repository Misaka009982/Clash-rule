#!/usr/bin/env python3

import ipaddress
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# ============================================================
# 配置
# ============================================================

BASE_DIR = Path("Rule")

# sing-box Source Format
#
# version 2:
#   兼容较新的 sing-box
#   对 domain_suffix 有优化
SING_BOX_RULESET_VERSION = 2


# ============================================================
# 日志
# ============================================================

def log(message=""):
    print(message, flush=True)


# ============================================================
# 文件工具
# ============================================================

def safe_remove(path):
    """
    删除文件。
    """
    try:
        if path.is_file() or path.is_symlink():
            path.unlink()
            log(
                f"[DELETE] {path}"
            )
    except OSError as e:
        log(
            f"[WARN] Failed to delete "
            f"{path}: {e}"
        )


def read_list(path):
    """
    读取 .list。

    自动：
    - UTF-8
    - 去除空白
    - 跳过空行
    - 跳过 #
    - 去重
    """

    if not path.is_file():
        return []

    result = set()

    try:
        with path.open(
            "r",
            encoding="utf-8"
        ) as f:

            for raw in f:

                line = raw.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                result.add(line)

    except UnicodeDecodeError:

        log(
            f"[WARN] Invalid UTF-8: "
            f"{path}"
        )

        try:
            with path.open(
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                for raw in f:

                    line = raw.strip()

                    if not line:
                        continue

                    if line.startswith("#"):
                        continue

                    result.add(line)

        except OSError as e:

            log(
                f"[ERROR] Read failed "
                f"{path}: {e}"
            )

    except OSError as e:

        log(
            f"[ERROR] Read failed "
            f"{path}: {e}"
        )

    return sorted(result)


# ============================================================
# IPv4 / IPv6
# ============================================================

def normalize_ipcidr(value):
    """
    修复并规范化 IP。

    支持：

        1.2.3.4
        1.2.3.4/32

        2001:db8::1
        2001:db8::1/128

    同时修复：

        2001:678\\:b28::118

    """

    if not isinstance(
        value,
        str
    ):
        return None

    value = value.strip()

    if not value:
        return None

    # --------------------------------------------------------
    # 修复错误转义
    # --------------------------------------------------------

    value = value.replace(
        "\\:",
        ":"
    )

    value = value.strip()

    # --------------------------------------------------------
    # CIDR
    # --------------------------------------------------------

    try:

        if "/" in value:

            network = ipaddress.ip_network(
                value,
                strict=False
            )

            return str(network)

        # ----------------------------------------------------
        # 单独 IP
        # ----------------------------------------------------

        ip = ipaddress.ip_address(
            value
        )

        if ip.version == 4:
            return f"{ip}/32"

        return f"{ip}/128"

    except ValueError:

        log(
            f"[INVALID IP] "
            f"{value}"
        )

        return None


# ============================================================
# Domain
# ============================================================

def build_domain_rule(items):
    """
    Clash 风格：

        example.com
        +.google.com

    →

        domain
        domain_suffix
    """

    domains = set()
    domain_suffix = set()

    for item in items:

        item = item.strip()

        if not item:
            continue

        # DOMAIN-SUFFIX
        if item.startswith("+."):

            value = item[2:].strip()

            if value:
                domain_suffix.add(
                    value
                )

            continue

        # DOMAIN
        domains.add(
            item
        )

    rule = {}

    if domains:
        rule["domain"] = sorted(
            domains
        )

    if domain_suffix:
        rule["domain_suffix"] = sorted(
            domain_suffix
        )

    return rule


# ============================================================
# IP-CIDR
# ============================================================

def build_ipcidr_rule(items):
    """
    将 IP 列表转换为 sing-box ip_cidr。
    """

    ip_cidr = set()

    for item in items:

        normalized = (
            normalize_ipcidr(
                item
            )
        )

        if normalized:
            ip_cidr.add(
                normalized
            )

    if not ip_cidr:
        return {}

    return {
        "ip_cidr": sorted(
            ip_cidr
        )
    }


# ============================================================
# Source Format
# ============================================================

def build_source(rule):
    """
    创建 sing-box Rule Set Source Format。
    """

    return {
        "version": (
            SING_BOX_RULESET_VERSION
        ),
        "rules": (
            [rule]
            if rule
            else []
        ),
    }


# ============================================================
# 查找 sing-box
# ============================================================

def find_sing_box():
    """
    查找 sing-box。
    """

    path = shutil.which(
        "sing-box"
    )

    if path:
        return path

    candidates = [
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        "./sing-box",
    ]

    for candidate in candidates:

        p = Path(candidate)

        if p.is_file():
            return str(p)

    return None


# ============================================================
# 检查 sing-box
# ============================================================

def check_sing_box():
    """
    检查 sing-box 是否存在。
    """

    sing_box = find_sing_box()

    if not sing_box:

        log(
            "[ERROR] sing-box not found"
        )

        return None

    try:

        result = subprocess.run(
            [
                sing_box,
                "version",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    except OSError as e:

        log(
            f"[ERROR] sing-box execute "
            f"failed: {e}"
        )

        return None

    if result.returncode != 0:

        log(
            "[ERROR] sing-box version "
            "check failed"
        )

        if result.stderr.strip():
            log(
                result.stderr.strip()
            )

        return None

    log(
        "========================================"
    )

    log(
        "sing-box"
    )

    log(
        "========================================"
    )

    if result.stdout.strip():

        log(
            result.stdout.strip()
        )

    return sing_box


# ============================================================
# 编译 SRS
# ============================================================

def compile_srs(
    sing_box,
    source_data,
    output_path,
):
    """
    使用：

        sing-box rule-set compile

    将 JSON 编译为 SRS。
    """

    temp_path = None

    try:

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        # ----------------------------------------------------
        # 临时 JSON
        # ----------------------------------------------------

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".json",
            prefix="sing-box-",
            delete=False,
        ) as f:

            json.dump(
                source_data,
                f,
                ensure_ascii=False,
                separators=(
                    ",",
                    ":"
                ),
            )

            f.write("\n")

            temp_path = Path(
                f.name
            )

        # ----------------------------------------------------
        # 删除旧 SRS
        # ----------------------------------------------------

        safe_remove(
            output_path
        )

        # ----------------------------------------------------
        # 编译
        # ----------------------------------------------------

        command = [
            sing_box,
            "rule-set",
            "compile",
            "--output",
            str(output_path),
            str(temp_path),
        ]

        log(
            "[COMPILE] "
            + " ".join(command)
        )

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        if result.stdout.strip():

            log(
                result.stdout.strip()
            )

        if result.returncode != 0:

            log(
                f"[ERROR] SRS compile failed: "
                f"{output_path}"
            )

            if result.stderr.strip():

                log(
                    result.stderr.strip()
                )

            safe_remove(
                output_path
            )

            return False

        # ----------------------------------------------------
        # 验证
        # ----------------------------------------------------

        if not output_path.is_file():

            log(
                f"[ERROR] SRS not created: "
                f"{output_path}"
            )

            return False

        size = output_path.stat().st_size

        if size <= 0:

            log(
                f"[ERROR] Empty SRS: "
                f"{output_path}"
            )

            safe_remove(
                output_path
            )

            return False

        log(
            f"[OK] {output_path} "
            f"({size:,} bytes)"
        )

        return True

    except OSError as e:

        log(
            f"[ERROR] OS error: "
            f"{output_path}: {e}"
        )

        safe_remove(
            output_path
        )

        return False

    except Exception as e:

        log(
            f"[ERROR] Unexpected error: "
            f"{output_path}: {e}"
        )

        safe_remove(
            output_path
        )

        return False

    finally:

        if temp_path is not None:

            safe_remove(
                temp_path
            )


# ============================================================
# Domain
# ============================================================

def process_domain(
    sing_box,
    source_path,
):
    """
    domains.list -> domains.srs
    """

    output_path = (
        source_path.with_suffix(
            ".srs"
        )
    )

    # --------------------------------------------------------
    # 不存在
    # --------------------------------------------------------

    if not source_path.is_file():

        safe_remove(
            output_path
        )

        return True

    # --------------------------------------------------------
    # 读取
    # --------------------------------------------------------

    items = read_list(
        source_path
    )

    if not items:

        log(
            f"[EMPTY] {source_path}"
        )

        safe_remove(
            output_path
        )

        return True

    # --------------------------------------------------------
    # 转换
    # --------------------------------------------------------

    rule = build_domain_rule(
        items
    )

    if not rule:

        log(
            f"[EMPTY] {source_path}"
        )

        safe_remove(
            output_path
        )

        return True

    source_data = build_source(
        rule
    )

    log("")
    log(
        f"[DOMAIN] {source_path}"
    )

    log(
        f"         rules = {len(items)}"
    )

    return compile_srs(
        sing_box,
        source_data,
        output_path,
    )


# ============================================================
# IP
# ============================================================

def process_ipcidr(
    sing_box,
    source_path,
):
    """
    ipcidr.list -> ipcidr.srs
    """

    output_path = (
        source_path.with_suffix(
            ".srs"
        )
    )

    # --------------------------------------------------------
    # 不存在
    # --------------------------------------------------------

    if not source_path.is_file():

        safe_remove(
            output_path
        )

        return True

    # --------------------------------------------------------
    # 读取
    # --------------------------------------------------------

    items = read_list(
        source_path
    )

    if not items:

        log(
            f"[EMPTY] {source_path}"
        )

        safe_remove(
            output_path
        )

        return True

    # --------------------------------------------------------
    # 转换
    # --------------------------------------------------------

    rule = build_ipcidr_rule(
        items
    )

    if not rule:

        log(
            f"[EMPTY] {source_path}"
        )

        safe_remove(
            output_path
        )

        return True

    source_data = build_source(
        rule
    )

    log("")
    log(
        f"[IPCIDR] {source_path}"
    )

    log(
        f"         rules = {len(items)}"
    )

    return compile_srs(
        sing_box,
        source_data,
        output_path,
    )


# ============================================================
# 普通目录
# ============================================================

def process_normal_rules(
    sing_box
):
    """
    处理：

        Rule/<name>/domains.list
        Rule/<name>/ipcidr.list
    """

    generated = 0
    failed = 0

    if not BASE_DIR.is_dir():
        return generated, failed

    for directory in sorted(
        BASE_DIR.iterdir()
    ):

        if not directory.is_dir():
            continue

        if directory.name == "Other":
            continue

        log("")
        log(
            "========================================"
        )

        log(
            f"Processing: {directory}"
        )

        log(
            "========================================"
        )

        # ----------------------------------------------------
        # Domain
        # ----------------------------------------------------

        domain_file = (
            directory / "domains.list"
        )

        if domain_file.is_file():

            result = process_domain(
                sing_box,
                domain_file
            )

            if result:
                generated += 1
            else:
                failed += 1

        else:

            # list 已删除
            safe_remove(
                directory / "domains.srs"
            )

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        ip_file = (
            directory / "ipcidr.list"
        )

        if ip_file.is_file():

            result = process_ipcidr(
                sing_box,
                ip_file
            )

            if result:
                generated += 1
            else:
                failed += 1

        else:

            safe_remove(
                directory / "ipcidr.srs"
            )

    return generated, failed


# ============================================================
# Rule/Other
# ============================================================

def process_other_rules(
    sing_box
):
    """
    处理：

        Rule/Other/*-domains.list
        Rule/Other/*-ipcidr.list
    """

    generated = 0
    failed = 0

    other_dir = (
        BASE_DIR / "Other"
    )

    if not other_dir.is_dir():
        return generated, failed

    log("")
    log(
        "========================================"
    )

    log(
        "Processing: Rule/Other"
    )

    log(
        "========================================"
    )

    for source_path in sorted(
        other_dir.iterdir()
    ):

        if not source_path.is_file():
            continue

        filename = source_path.name

        # ----------------------------------------------------
        # Domain
        # ----------------------------------------------------

        if filename.endswith(
            "-domains.list"
        ):

            result = process_domain(
                sing_box,
                source_path
            )

            if result:
                generated += 1
            else:
                failed += 1

            continue

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        if filename.endswith(
            "-ipcidr.list"
        ):

            result = process_ipcidr(
                sing_box,
                source_path
            )

            if result:
                generated += 1
            else:
                failed += 1

            continue

    return generated, failed


# ============================================================
# 清理孤立 SRS
# ============================================================

def cleanup_orphan_srs():
    """
    如果：

        xxx.srs

    但：

        xxx.list

    不存在，删除 SRS。
    """

    deleted = 0

    if not BASE_DIR.is_dir():
        return deleted

    log("")
    log(
        "========================================"
    )

    log(
        "Cleanup orphan SRS"
    )

    log(
        "========================================"
    )

    for srs_path in sorted(
        BASE_DIR.rglob("*.srs")
    ):

        list_path = (
            srs_path.with_suffix(
                ".list"
            )
        )

        if not list_path.is_file():

            log(
                f"[ORPHAN] {srs_path}"
            )

            safe_remove(
                srs_path
            )

            deleted += 1

    return deleted


# ============================================================
# 清理空目录
# ============================================================

def cleanup_empty_dirs():

    if not BASE_DIR.is_dir():
        return

    dirs = sorted(
        (
            p
            for p in BASE_DIR.rglob("*")
            if p.is_dir()
        ),
        key=lambda p: len(p.parts),
        reverse=True,
    )

    for directory in dirs:

        if directory == (
            BASE_DIR / "Other"
        ):
            continue

        try:

            if not any(
                directory.iterdir()
            ):

                directory.rmdir()

                log(
                    f"[DELETE DIR] "
                    f"{directory}"
                )

        except OSError:
            pass


# ============================================================
# 统计
# ============================================================

def show_statistics():

    log("")
    log(
        "========================================"
    )

    log(
        "SRS Statistics"
    )

    log(
        "========================================"
    )

    if not BASE_DIR.is_dir():
        return 0

    files = sorted(
        BASE_DIR.rglob("*.srs")
    )

    total_size = 0

    for path in files:

        size = path.stat().st_size

        total_size += size

        log(
            f"{path} "
            f"{size:,} bytes"
        )

    log("")
    log(
        f"SRS count : {len(files)}"
    )

    log(
        f"Total size: {total_size:,} bytes"
    )

    return len(files)


# ============================================================
# Main
# ============================================================

def main():

    log(
        "========================================"
    )

    log(
        "Clash-rule -> sing-box SRS"
    )

    log(
        "========================================"
    )

    log(
        f"Rule directory: {BASE_DIR}"
    )

    log(
        f"Rule version: "
        f"{SING_BOX_RULESET_VERSION}"
    )

    # --------------------------------------------------------
    # sing-box
    # --------------------------------------------------------

    sing_box = check_sing_box()

    if not sing_box:
        return 1

    # --------------------------------------------------------
    # Rule
    # --------------------------------------------------------

    if not BASE_DIR.is_dir():

        log(
            f"[ERROR] Rule directory "
            f"not found: {BASE_DIR}"
        )

        return 1

    # --------------------------------------------------------
    # 普通规则
    # --------------------------------------------------------

    normal_generated, normal_failed = (
        process_normal_rules(
            sing_box
        )
    )

    # --------------------------------------------------------
    # Other
    # --------------------------------------------------------

    other_generated, other_failed = (
        process_other_rules(
            sing_box
        )
    )

    # --------------------------------------------------------
    # 孤立 SRS
    # --------------------------------------------------------

    orphan_deleted = (
        cleanup_orphan_srs()
    )

    # --------------------------------------------------------
    # 空目录
    # --------------------------------------------------------

    cleanup_empty_dirs()

    # --------------------------------------------------------
    # 统计
    # --------------------------------------------------------

    total_generated = (
        normal_generated
        + other_generated
    )

    total_failed = (
        normal_failed
        + other_failed
    )

    srs_count = show_statistics()

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    log("")
    log(
        "========================================"
    )

    log(
        "Summary"
    )

    log(
        "========================================"
    )

    log(
        f"Processed: {total_generated}"
    )

    log(
        f"Failed   : {total_failed}"
    )

    log(
        f"Orphan   : {orphan_deleted}"
    )

    log(
        f"SRS total: {srs_count}"
    )

    log("")

    # --------------------------------------------------------
    # 某个文件编译失败不能静默成功
    # --------------------------------------------------------

    if total_failed > 0:

        log(
            "[ERROR] One or more SRS "
            "files failed to compile."
        )

        return 1

    log(
        "[DONE] SRS generation completed."
    )

    return 0


# ============================================================
# Entry
# ============================================================

if __name__ == "__main__":
    sys.exit(
        main()
    )
