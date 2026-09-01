#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


# ============================================================
# 配置
# ============================================================

BASE_DIR = Path("Rule")
OTHER_DIR = BASE_DIR / "Other"

# sing-box Rule Set Source Format
#
# version 2:
# - sing-box 1.10.0+
# - 优化 domain_suffix 在二进制规则集中的内存占用
#
# 如果你明确只支持 sing-box 1.14+，也可以改成 5。
SING_BOX_RULESET_VERSION = 2


# ============================================================
# 基础工具
# ============================================================

def log(message: str) -> None:
    print(message, flush=True)


def read_lines(path: Path) -> list[str]:
    """
    读取 .list 文件。

    自动：
    - 去除首尾空白
    - 跳过空行
    - 跳过 # 注释
    - 去重
    """
    if not path.is_file():
        return []

    result = set()

    try:
        with path.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                result.add(line)

    except UnicodeDecodeError:
        # 万一某些规则不是 UTF-8，尝试忽略非法字符
        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:
            for raw_line in f:
                line = raw_line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                result.add(line)

    return sorted(result)


def safe_unlink(path: Path) -> None:
    """
    安全删除文件。
    """
    try:
        if path.exists():
            path.unlink()
    except OSError as e:
        log(f"[WARN] Failed to delete {path}: {e}")


# ============================================================
# DOMAIN 转换
# ============================================================

def build_domain_rule(items: list[str]) -> dict:
    """
    将 Clash-rule 风格的 domains.list 转换为
    sing-box Rule Set Source Format。

    例如：

    example.com
    +.google.com
    +.googleusercontent.com

    转换为：

    {
        "domain": [
            "example.com"
        ],
        "domain_suffix": [
            "google.com",
            "googleusercontent.com"
        ]
    }
    """

    domains = set()
    domain_suffix = set()

    for item in items:
        item = item.strip()

        if not item:
            continue

        # Clash-rule.py 使用 "+." 表示 DOMAIN-SUFFIX
        if item.startswith("+."):
            suffix = item[2:].strip()

            if suffix:
                domain_suffix.add(suffix)

            continue

        # 普通 DOMAIN
        domains.add(item)

    rule = {}

    if domains:
        rule["domain"] = sorted(domains)

    if domain_suffix:
        rule["domain_suffix"] = sorted(domain_suffix)

    return rule


# ============================================================
# IP-CIDR 转换
# ============================================================

def build_ipcidr_rule(items: list[str]) -> dict:
    """
    将 IP-CIDR / IP-CIDR6 列表转换成：

    {
        "ip_cidr": [
            "1.1.1.0/24",
            "8.8.8.0/24"
        ]
    }
    """

    ipcidr = set()

    for item in items:
        item = item.strip()

        if not item:
            continue

        ipcidr.add(item)

    if not ipcidr:
        return {}

    return {
        "ip_cidr": sorted(ipcidr)
    }


# ============================================================
# 创建 sing-box Source Format
# ============================================================

def build_source_format(rule: dict) -> dict:
    """
    生成 sing-box Rule Set Source Format。

    官方格式：

    {
      "version": 2,
      "rules": [
        {
          ...
        }
      ]
    }
    """

    if not rule:
        return {
            "version": SING_BOX_RULESET_VERSION,
            "rules": []
        }

    return {
        "version": SING_BOX_RULESET_VERSION,
        "rules": [
            rule
        ]
    }


# ============================================================
# 调用 sing-box 编译
# ============================================================

def compile_srs(source_data: dict, output_path: Path) -> bool:
    """
    将 Source Format JSON 编译为 .srs。

    实际调用：

    sing-box rule-set compile \
        --output output.srs \
        input.json
    """

    json_path: Path | None = None

    try:
        # 使用系统临时文件
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".json",
            prefix="sing-box-rule-",
            delete=False
        ) as f:
            json.dump(
                source_data,
                f,
                ensure_ascii=False,
                separators=(",", ":")
            )

            f.write("\n")
            json_path = Path(f.name)

        # 确保输出目录存在
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        # 删除旧文件，避免编译异常时残留旧版本
        safe_unlink(output_path)

        command = [
            "sing-box",
            "rule-set",
            "compile",
            "--output",
            str(output_path),
            str(json_path),
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
            log(result.stdout.strip())

        if result.returncode != 0:
            log("[ERROR] sing-box compile failed")

            if result.stderr.strip():
                log(result.stderr.strip())

            safe_unlink(output_path)

            return False

        if not output_path.is_file():
            log(
                f"[ERROR] sing-box reported success but "
                f"{output_path} does not exist"
            )

            return False

        size = output_path.stat().st_size

        if size <= 0:
            log(
                f"[ERROR] Generated SRS is empty: "
                f"{output_path}"
            )

            safe_unlink(output_path)

            return False

        log(
            f"[OK] {output_path} "
            f"({size:,} bytes)"
        )

        return True

    except FileNotFoundError:
        log(
            "[ERROR] sing-box command not found. "
            "Please install sing-box first."
        )

        return False

    except Exception as e:
        log(
            f"[ERROR] Unexpected compile error: {e}"
        )

        safe_unlink(output_path)

        return False

    finally:
        if json_path is not None:
            safe_unlink(json_path)


# ============================================================
# DOMAIN SRS
# ============================================================

def process_domain_file(source_path: Path) -> bool:
    """
    处理单个 domains.list。
    """

    if not source_path.is_file():
        return False

    output_path = source_path.with_suffix(".srs")

    items = read_lines(source_path)

    if not items:
        log(
            f"[EMPTY] {source_path}"
        )

        # 防止规则已经为空，但仓库还保留旧 SRS
        safe_unlink(output_path)

        return False

    rule = build_domain_rule(items)

    if not rule:
        log(
            f"[EMPTY] {source_path} "
            f"(no valid domain rules)"
        )

        safe_unlink(output_path)

        return False

    source_data = build_source_format(rule)

    log(
        f"[DOMAIN] {source_path} "
        f"-> {output_path} "
        f"({len(items)} lines)"
    )

    return compile_srs(
        source_data,
        output_path
    )


# ============================================================
# IP-CIDR SRS
# ============================================================

def process_ipcidr_file(source_path: Path) -> bool:
    """
    处理单个 ipcidr.list。
    """

    if not source_path.is_file():
        return False

    output_path = source_path.with_suffix(".srs")

    items = read_lines(source_path)

    if not items:
        log(
            f"[EMPTY] {source_path}"
        )

        safe_unlink(output_path)

        return False

    rule = build_ipcidr_rule(items)

    if not rule:
        log(
            f"[EMPTY] {source_path} "
            f"(no valid IP-CIDR rules)"
        )

        safe_unlink(output_path)

        return False

    source_data = build_source_format(rule)

    log(
        f"[IPCIDR] {source_path} "
        f"-> {output_path} "
        f"({len(items)} lines)"
    )

    return compile_srs(
        source_data,
        output_path
    )


# ============================================================
# 清理孤立的 SRS
# ============================================================

def remove_orphan_srs() -> None:
    """
    删除不存在对应 .list 的 .srs。

    例如：

    domains.srs
    domains.list 不存在

    则删除 domains.srs。

    防止旧规则在仓库中一直残留。
    """

    if not BASE_DIR.is_dir():
        return

    log("")
    log("=== Check orphan SRS ===")

    for srs_path in BASE_DIR.rglob("*.srs"):

        # 例如：
        # domains.srs -> domains.list
        list_path = srs_path.with_suffix(".list")

        if not list_path.is_file():
            log(
                f"[DELETE] Orphan SRS: "
                f"{srs_path}"
            )

            safe_unlink(srs_path)


# ============================================================
# 扫描普通 Rule 目录
# ============================================================

def process_normal_rules() -> tuple[int, int]:
    """
    处理：

    Rule/<name>/domains.list
    Rule/<name>/ipcidr.list

    不处理 Rule/Other。
    """

    success = 0
    failed = 0

    if not BASE_DIR.is_dir():
        log(
            f"[ERROR] Rule directory does not exist: "
            f"{BASE_DIR}"
        )

        return success, failed

    for directory in sorted(BASE_DIR.iterdir()):

        if not directory.is_dir():
            continue

        # Other 下面是另一种平铺结构
        if directory.name == "Other":
            continue

        log("")
        log(
            f"=== Processing {directory} ==="
        )

        # ----------------------------
        # domains.list
        # ----------------------------

        domain_file = (
            directory / "domains.list"
        )

        if domain_file.is_file():
            if process_domain_file(domain_file):
                success += 1
            else:
                # 空规则不算编译失败
                if domain_file.stat().st_size > 0:
                    # 不直接把所有异常都当失败，
                    # 这里只保守统计
                    pass

        # ----------------------------
        # ipcidr.list
        # ----------------------------

        ip_file = (
            directory / "ipcidr.list"
        )

        if ip_file.is_file():
            if process_ipcidr_file(ip_file):
                success += 1
            else:
                if ip_file.stat().st_size > 0:
                    pass

    return success, failed


# ============================================================
# 处理 Rule/Other
# ============================================================

def process_other_rules() -> tuple[int, int]:
    """
    处理 rules.py 生成的：

    Rule/Other/<name>-domains.list
    Rule/Other/<name>-ipcidr.list
    """

    success = 0
    failed = 0

    if not OTHER_DIR.is_dir():
        return success, failed

    log("")
    log("=== Processing Rule/Other ===")

    for source_path in sorted(
        OTHER_DIR.iterdir()
    ):
        if not source_path.is_file():
            continue

        filename = source_path.name

        # --------------------------------
        # *-domains.list
        # --------------------------------

        if filename.endswith(
            "-domains.list"
        ):
            if process_domain_file(
                source_path
            ):
                success += 1

            continue

        # --------------------------------
        # *-ipcidr.list
        # --------------------------------

        if filename.endswith(
            "-ipcidr.list"
        ):
            if process_ipcidr_file(
                source_path
            ):
                success += 1

            continue

    return success, failed


# ============================================================
# 输出统计
# ============================================================

def show_statistics() -> None:
    """
    输出最终 SRS 文件统计。
    """

    log("")
    log("========================================")
    log("Generated SRS files")
    log("========================================")

    if not BASE_DIR.is_dir():
        log("No Rule directory.")
        return

    files = sorted(
        BASE_DIR.rglob("*.srs")
    )

    if not files:
        log("No SRS files generated.")
        return

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
        f"Total: {len(files)} SRS files"
    )

    log(
        f"Total size: {total_size:,} bytes"
    )


# ============================================================
# 检查 sing-box
# ============================================================

def check_sing_box() -> bool:
    """
    检查 sing-box 是否可执行。
    """

    try:
        result = subprocess.run(
            [
                "sing-box",
                "version"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            log(
                "[ERROR] Unable to execute sing-box"
            )

            if result.stderr.strip():
                log(result.stderr.strip())

            return False

        log("========================================")
        log("sing-box")
        log("========================================")

        if result.stdout.strip():
            log(result.stdout.strip())

        return True

    except FileNotFoundError:
        log(
            "[ERROR] sing-box is not installed "
            "or not in PATH."
        )

        return False

    except Exception as e:
        log(
            f"[ERROR] Failed to check sing-box: {e}"
        )

        return False


# ============================================================
# Main
# ============================================================

def main() -> int:

    log("========================================")
    log("Clash-rule -> sing-box SRS")
    log("========================================")

    log(
        f"Rule directory: {BASE_DIR}"
    )

    log(
        f"Other directory: {OTHER_DIR}"
    )

    log(
        f"Rule Set version: "
        f"{SING_BOX_RULESET_VERSION}"
    )

    # ----------------------------------------
    # 检查 sing-box
    # ----------------------------------------

    if not check_sing_box():
        return 1

    # ----------------------------------------
    # 检查 Rule
    # ----------------------------------------

    if not BASE_DIR.exists():
        log(
            f"[ERROR] Directory not found: "
            f"{BASE_DIR}"
        )

        return 1

    # ----------------------------------------
    # 处理普通规则
    # ----------------------------------------

    normal_success, normal_failed = (
        process_normal_rules()
    )

    # ----------------------------------------
    # 处理 Other
    # ----------------------------------------

    other_success, other_failed = (
        process_other_rules()
    )

    # ----------------------------------------
    # 删除孤立 SRS
    # ----------------------------------------

    remove_orphan_srs()

    # ----------------------------------------
    # 统计
    # ----------------------------------------

    show_statistics()

    success = (
        normal_success +
        other_success
    )

    failed = (
        normal_failed +
        other_failed
    )

    log("")
    log("========================================")
    log("Summary")
    log("========================================")

    log(
        f"Successful: {success}"
    )

    log(
        f"Failed: {failed}"
    )

    log("")

    # 即使部分规则为空，也不认为整个任务失败。
    # 但如果完全没有生成任何 SRS，返回失败，
    # 避免 GitHub Actions 错误地提交空结果。
    if success == 0:
        log(
            "[ERROR] No SRS files were generated."
        )

        return 1

    log(
        "[DONE] SRS generation completed."
    )

    return 0


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    sys.exit(main())
