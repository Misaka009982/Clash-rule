#!/usr/bin/env python3

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

# sing-box Rule Set Source Format
#
# version 2:
#   兼容 sing-box 1.10+
#   对 domain_suffix 的二进制规则集有优化
#
# 如果你的 sing-box 全部 >= 1.14，
# 可以自行改成 5。
SING_BOX_RULESET_VERSION = 2


# ============================================================
# 日志
# ============================================================

def log(message: str = "") -> None:
    print(message, flush=True)


# ============================================================
# 文件工具
# ============================================================

def safe_remove(path: Path) -> None:
    """
    删除文件。
    不存在时忽略。
    """
    try:
        if path.is_file() or path.is_symlink():
            path.unlink()
            log(f"[DELETE] {path}")
    except OSError as e:
        log(f"[WARN] Failed to delete {path}: {e}")


def read_rule_file(path: Path) -> list[str]:
    """
    读取 .list 文件。

    自动：
    - 去除前后空格
    - 跳过空行
    - 跳过 # 注释
    - 去重
    """
    if not path.is_file():
        return []

    rules = set()

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

                rules.add(line)

    except OSError as e:
        log(
            f"[ERROR] Failed to read "
            f"{path}: {e}"
        )

    except UnicodeDecodeError:
        log(
            f"[WARN] Invalid UTF-8 in "
            f"{path}, retrying with errors=ignore"
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

                    rules.add(line)

        except OSError as e:
            log(
                f"[ERROR] Failed to read "
                f"{path}: {e}"
            )

    return sorted(rules)


# ============================================================
# DOMAIN 转换
# ============================================================

def convert_domains(items: list[str]) -> dict:
    """
    Clash 风格：

        example.com
        +.google.com

    转成 sing-box：

        domain
        domain_suffix
    """

    domains = set()
    domain_suffix = set()

    for item in items:
        item = item.strip()

        if not item:
            continue

        # Clash DOMAIN-SUFFIX
        if item.startswith("+."):
            value = item[2:].strip()

            if value:
                domain_suffix.add(value)

            continue

        # 普通 DOMAIN
        domains.add(item)

    rule = {}

    if domains:
        rule["domain"] = sorted(domains)

    if domain_suffix:
        rule["domain_suffix"] = sorted(
            domain_suffix
        )

    return rule


# ============================================================
# IP-CIDR 转换
# ============================================================

def convert_ipcidr(items: list[str]) -> dict:
    """
    Clash：

        IP-CIDR
        IP-CIDR6

    统一转成 sing-box：

        ip_cidr
    """

    ip_cidr = set()

    for item in items:
        item = item.strip()

        if not item:
            continue

        ip_cidr.add(item)

    if not ip_cidr:
        return {}

    return {
        "ip_cidr": sorted(ip_cidr)
    }


# ============================================================
# sing-box Source Format
# ============================================================

def make_source(rule: dict) -> dict:
    """
    生成 sing-box Rule Set Source Format。
    """

    return {
        "version": SING_BOX_RULESET_VERSION,
        "rules": [rule] if rule else []
    }


# ============================================================
# 查找 sing-box
# ============================================================

def find_sing_box() -> str | None:
    """
    查找 sing-box 可执行文件。
    """

    path = shutil.which("sing-box")

    if path:
        return path

    common_paths = (
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        "./sing-box",
    )

    for candidate in common_paths:
        p = Path(candidate)

        if p.is_file():
            return str(p)

    return None


# ============================================================
# 检查 sing-box
# ============================================================

def check_sing_box() -> str | None:
    """
    检查 sing-box 是否可用。
    """

    sing_box = find_sing_box()

    if not sing_box:
        log(
            "[ERROR] sing-box not found."
        )

        return None

    try:
        result = subprocess.run(
            [
                sing_box,
                "version"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    except OSError as e:
        log(
            f"[ERROR] Failed to execute "
            f"sing-box: {e}"
        )

        return None

    if result.returncode != 0:
        log(
            "[ERROR] sing-box version check failed."
        )

        if result.stderr.strip():
            log(result.stderr.strip())

        return None

    log("========================================")
    log("sing-box")
    log("========================================")

    if result.stdout.strip():
        log(result.stdout.strip())

    return sing_box


# ============================================================
# 编译 SRS
# ============================================================

def compile_srs(
    sing_box: str,
    source_data: dict,
    output_path: Path,
) -> bool:
    """
    将 Source Format JSON 编译成 SRS。

    临时 JSON 保存在系统临时目录，
    不进入 Git 仓库。
    """

    temp_path: Path | None = None

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
                separators=(",", ":"),
            )

            f.write("\n")

            temp_path = Path(f.name)

        # ----------------------------------------------------
        # 编译前删除旧 SRS
        # ----------------------------------------------------

        safe_remove(output_path)

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
                f"[ERROR] Compile failed: "
                f"{output_path}"
            )

            if result.stderr.strip():
                log(
                    result.stderr.strip()
                )

            safe_remove(output_path)

            return False

        # ----------------------------------------------------
        # 验证输出
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

            safe_remove(output_path)

            return False

        log(
            f"[OK] {output_path} "
            f"({size:,} bytes)"
        )

        return True

    except OSError as e:
        log(
            f"[ERROR] OS error while compiling "
            f"{output_path}: {e}"
        )

        safe_remove(output_path)

        return False

    except Exception as e:
        log(
            f"[ERROR] Unexpected error "
            f"while compiling {output_path}: {e}"
        )

        safe_remove(output_path)

        return False

    finally:
        # ----------------------------------------------------
        # 删除临时 JSON
        # ----------------------------------------------------

        if temp_path is not None:
            safe_remove(temp_path)


# ============================================================
# 处理 domains.list
# ============================================================

def process_domain(
    sing_box: str,
    source_path: Path,
) -> tuple[bool, bool]:
    """
    返回：

        (是否成功生成, 是否跳过)
    """

    output_path = source_path.with_suffix(".srs")

    items = read_rule_file(source_path)

    # --------------------------------------------------------
    # 文件不存在
    # --------------------------------------------------------

    if not source_path.is_file():
        safe_remove(output_path)
        return False, True

    # --------------------------------------------------------
    # 文件为空
    # --------------------------------------------------------

    if not items:
        log(
            f"[EMPTY] {source_path}"
        )

        # 上游已经为空：
        # 删除旧 SRS
        safe_remove(output_path)

        return False, True

    # --------------------------------------------------------
    # 转换
    # --------------------------------------------------------

    rule = convert_domains(items)

    if not rule:
        log(
            f"[EMPTY] {source_path} "
            f"(no valid domain rules)"
        )

        safe_remove(output_path)

        return False, True

    source_data = make_source(rule)

    log("")
    log(
        f"[DOMAIN] {source_path}"
    )

    log(
        f"         rules = {len(items)}"
    )

    success = compile_srs(
        sing_box,
        source_data,
        output_path,
    )

    return success, False


# ============================================================
# 处理 ipcidr.list
# ============================================================

def process_ipcidr(
    sing_box: str,
    source_path: Path,
) -> tuple[bool, bool]:
    """
    处理 ipcidr.list。
    """

    output_path = source_path.with_suffix(".srs")

    items = read_rule_file(source_path)

    # --------------------------------------------------------
    # 文件不存在
    # --------------------------------------------------------

    if not source_path.is_file():
        safe_remove(output_path)
        return False, True

    # --------------------------------------------------------
    # 文件为空
    # --------------------------------------------------------

    if not items:
        log(
            f"[EMPTY] {source_path}"
        )

        safe_remove(output_path)

        return False, True

    # --------------------------------------------------------
    # 转换
    # --------------------------------------------------------

    rule = convert_ipcidr(items)

    if not rule:
        log(
            f"[EMPTY] {source_path} "
            f"(no valid IP-CIDR rules)"
        )

        safe_remove(output_path)

        return False, True

    source_data = make_source(rule)

    log("")
    log(
        f"[IPCIDR] {source_path}"
    )

    log(
        f"         rules = {len(items)}"
    )

    success = compile_srs(
        sing_box,
        source_data,
        output_path,
    )

    return success, False


# ============================================================
# 扫描普通 Rule
# ============================================================

def process_normal_rules(
    sing_box: str,
) -> tuple[int, int]:
    """
    处理：

        Rule/<name>/domains.list
        Rule/<name>/ipcidr.list
    """

    success_count = 0
    skipped_count = 0

    if not BASE_DIR.is_dir():
        log(
            f"[ERROR] Rule directory not found: "
            f"{BASE_DIR}"
        )

        return success_count, skipped_count

    for directory in sorted(
        BASE_DIR.iterdir()
    ):

        if not directory.is_dir():
            continue

        # Rule/Other 单独处理
        if directory.name == "Other":
            continue

        log("")
        log("========================================")
        log(
            f"Processing: {directory}"
        )
        log("========================================")

        # ----------------------------------------------------
        # domains.list
        # ----------------------------------------------------

        domain_file = (
            directory / "domains.list"
        )

        if domain_file.is_file():

            success, skipped = process_domain(
                sing_box,
                domain_file,
            )

            if success:
                success_count += 1

            if skipped:
                skipped_count += 1

        elif (
            directory / "domains.srs"
        ).is_file():

            # list 不存在，但旧 SRS 存在
            log(
                f"[ORPHAN] {directory / 'domains.srs'}"
            )

            safe_remove(
                directory / "domains.srs"
            )

        # ----------------------------------------------------
        # ipcidr.list
        # ----------------------------------------------------

        ipcidr_file = (
            directory / "ipcidr.list"
        )

        if ipcidr_file.is_file():

            success, skipped = process_ipcidr(
                sing_box,
                ipcidr_file,
            )

            if success:
                success_count += 1

            if skipped:
                skipped_count += 1

        elif (
            directory / "ipcidr.srs"
        ).is_file():

            # list 不存在，但旧 SRS 存在
            log(
                f"[ORPHAN] {directory / 'ipcidr.srs'}"
            )

            safe_remove(
                directory / "ipcidr.srs"
            )

    return success_count, skipped_count


# ============================================================
# 扫描 Rule/Other
# ============================================================

def process_other_rules(
    sing_box: str,
) -> tuple[int, int]:
    """
    处理：

        Rule/Other/*-domains.list
        Rule/Other/*-ipcidr.list
    """

    success_count = 0
    skipped_count = 0

    other_dir = (
        BASE_DIR / "Other"
    )

    if not other_dir.is_dir():
        return success_count, skipped_count

    log("")
    log("========================================")
    log("Processing: Rule/Other")
    log("========================================")

    for source_path in sorted(
        other_dir.iterdir()
    ):

        if not source_path.is_file():
            continue

        filename = source_path.name

        # ----------------------------------------------------
        # domains
        # ----------------------------------------------------

        if filename.endswith(
            "-domains.list"
        ):

            success, skipped = process_domain(
                sing_box,
                source_path,
            )

            if success:
                success_count += 1

            if skipped:
                skipped_count += 1

            continue

        # ----------------------------------------------------
        # ipcidr
        # ----------------------------------------------------

        if filename.endswith(
            "-ipcidr.list"
        ):

            success, skipped = process_ipcidr(
                sing_box,
                source_path,
            )

            if success:
                success_count += 1

            if skipped:
                skipped_count += 1

            continue

    return success_count, skipped_count


# ============================================================
# 清理孤立 SRS
# ============================================================

def cleanup_orphan_srs() -> int:
    """
    扫描整个 Rule 目录。

    如果：

        xxx.srs

    但对应：

        xxx.list

    不存在，

    则删除 xxx.srs。

    这样即使旧版本脚本留下了 SRS，
    也可以一次性清理掉。
    """

    deleted = 0

    if not BASE_DIR.is_dir():
        return deleted

    log("")
    log("========================================")
    log("Cleanup orphan SRS")
    log("========================================")

    for srs_path in sorted(
        BASE_DIR.rglob("*.srs")
    ):

        list_path = (
            srs_path.with_suffix(".list")
        )

        if not list_path.is_file():

            log(
                f"[ORPHAN] "
                f"{srs_path}"
            )

            safe_remove(
                srs_path
            )

            deleted += 1

    return deleted


# ============================================================
# 清理空目录
# ============================================================

def cleanup_empty_directories() -> None:
    """
    删除已经没有任何文件的规则目录。
    """

    if not BASE_DIR.is_dir():
        return

    directories = sorted(
        (
            p
            for p in BASE_DIR.rglob("*")
            if p.is_dir()
        ),
        key=lambda p: len(p.parts),
        reverse=True,
    )

    for directory in directories:

        # Rule/Other 不删
        if directory == BASE_DIR / "Other":
            continue

        try:
            if not any(directory.iterdir()):
                directory.rmdir()

                log(
                    f"[DELETE DIR] "
                    f"{directory}"
                )

        except OSError:
            pass


# ============================================================
# 输出统计
# ============================================================

def show_statistics() -> int:
    """
    输出最终所有 SRS。
    """

    log("")
    log("========================================")
    log("SRS Statistics")
    log("========================================")

    if not BASE_DIR.is_dir():
        log(
            "No Rule directory."
        )

        return 0

    files = sorted(
        BASE_DIR.rglob("*.srs")
    )

    if not files:
        log(
            "No SRS files."
        )

        return 0

    total_size = 0

    for path in files:
        size = path.stat().st_size

        total_size += size

        log(
            f"{path}: "
            f"{size:,} bytes"
        )

    log("")
    log(
        f"SRS files : {len(files)}"
    )

    log(
        f"Total size: {total_size:,} bytes"
    )

    return len(files)


# ============================================================
# Main
# ============================================================

def main() -> int:

    log("========================================")
    log("Clash-rule -> sing-box SRS")
    log("========================================")

    log(
        f"Rule directory : {BASE_DIR}"
    )

    log(
        f"Rule Set version: "
        f"{SING_BOX_RULESET_VERSION}"
    )

    # --------------------------------------------------------
    # 检查 sing-box
    # --------------------------------------------------------

    sing_box = check_sing_box()

    if not sing_box:
        return 1

    # --------------------------------------------------------
    # 检查 Rule
    # --------------------------------------------------------

    if not BASE_DIR.is_dir():
        log(
            f"[ERROR] Directory not found: "
            f"{BASE_DIR}"
        )

        return 1

    # --------------------------------------------------------
    # 普通规则
    # --------------------------------------------------------

    normal_success, normal_skipped = (
        process_normal_rules(
            sing_box
        )
    )

    # --------------------------------------------------------
    # Other
    # --------------------------------------------------------

    other_success, other_skipped = (
        process_other_rules(
            sing_box
        )
    )

    # --------------------------------------------------------
    # 清理孤立 SRS
    # --------------------------------------------------------

    orphan_deleted = (
        cleanup_orphan_srs()
    )

    # --------------------------------------------------------
    # 清理空目录
    # --------------------------------------------------------

    cleanup_empty_directories()

    # --------------------------------------------------------
    # 最终统计
    # --------------------------------------------------------

    srs_count = show_statistics()

    total_success = (
        normal_success +
        other_success
    )

    total_skipped = (
        normal_skipped +
        other_skipped
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    log("")
    log("========================================")
    log("Summary")
    log("========================================")

    log(
        f"Generated : {total_success}"
    )

    log(
        f"Skipped   : {total_skipped}"
    )

    log(
        f"Orphan del: {orphan_deleted}"
    )

    log(
        f"SRS total : {srs_count}"
    )

    # --------------------------------------------------------
    # 没有任何 SRS
    #
    # 注意：
    # 这里不因为“全部为空”就认为失败。
    #
    # 例如所有上游规则真的被清空，
    # 这是一个合法状态。
    # --------------------------------------------------------

    log("")
    log(
        "[DONE] SRS generation completed."
    )

    return 0


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    sys.exit(main())
