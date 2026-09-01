#!/usr/bin/env python3

import json
import os
import subprocess
import tempfile

BASE_DIR = "Rule"


def read_list(path):
    if not os.path.isfile(path):
        return []

    result = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            result.append(line)

    return sorted(set(result))


def build_domain_json(items):
    domains = []
    domain_suffix = []

    for item in items:
        if item.startswith("+."):
            suffix = item[2:].strip()

            if suffix:
                domain_suffix.append(suffix)
        else:
            domains.append(item)

    rule = {}

    if domains:
        rule["domain"] = domains

    if domain_suffix:
        rule["domain_suffix"] = domain_suffix

    return {
        "version": 2,
        "rules": [rule] if rule else []
    }


def build_ipcidr_json(items):
    return {
        "version": 2,
        "rules": [
            {
                "ip_cidr": sorted(set(items))
            }
        ] if items else []
    }


def compile_srs(json_data, output_path):
    if not json_data["rules"]:
        return False

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".json",
        delete=False
    ) as f:
        json.dump(
            json_data,
            f,
            ensure_ascii=False,
            separators=(",", ":")
        )
        temp_path = f.name

    try:
        subprocess.run(
            [
                "sing-box",
                "rule-set",
                "compile",
                "--output",
                output_path,
                temp_path,
            ],
            check=True,
        )
    finally:
        os.unlink(temp_path)

    return True


def process_domain(src, dst):
    items = read_list(src)

    if not items:
        if os.path.exists(dst):
            os.remove(dst)
        print(f"[SKIP] {src}")
        return

    data = build_domain_json(items)

    if compile_srs(data, dst):
        size = os.path.getsize(dst)

        print(
            f"[SRS] {src} -> {dst} "
            f"({len(items)} rules, {size} bytes)"
        )


def process_ipcidr(src, dst):
    items = read_list(src)

    if not items:
        if os.path.exists(dst):
            os.remove(dst)
        print(f"[SKIP] {src}")
        return

    data = build_ipcidr_json(items)

    if compile_srs(data, dst):
        size = os.path.getsize(dst)

        print(
            f"[SRS] {src} -> {dst} "
            f"({len(items)} rules, {size} bytes)"
        )


def main():
    if not os.path.isdir(BASE_DIR):
        print("[ERROR] Rule directory not found")
        return

    # Rule/<name>/*
    for name in sorted(os.listdir(BASE_DIR)):
        directory = os.path.join(BASE_DIR, name)

        if not os.path.isdir(directory):
            continue

        # Rule/Other 单独处理下面的平铺文件
        if name == "Other":
            continue

        process_domain(
            os.path.join(directory, "domains.list"),
            os.path.join(directory, "domains.srs"),
        )

        process_ipcidr(
            os.path.join(directory, "ipcidr.list"),
            os.path.join(directory, "ipcidr.srs"),
        )

    # Rule/Other/*-domains.list
    other_dir = os.path.join(BASE_DIR, "Other")

    if os.path.isdir(other_dir):
        for filename in sorted(os.listdir(other_dir)):
            path = os.path.join(other_dir, filename)

            if filename.endswith("-domains.list"):
                process_domain(
                    path,
                    os.path.join(
                        other_dir,
                        filename[:-5] + "srs"
                    ),
                )

            elif filename.endswith("-ipcidr.list"):
                process_ipcidr(
                    path,
                    os.path.join(
                        other_dir,
                        filename[:-5] + "srs"
                    ),
                )

    print("All SRS rules done.")


if __name__ == "__main__":
    main()
