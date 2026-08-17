#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

import yara
from colorama import init as colorama_init, Fore, Style

colorama_init(autoreset=True)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan files against YARA rules and report a risk score."
    )
    parser.add_argument(
        "-r", "--rules",
        default="rules",
        help="Path to a .yar file or a folder of .yar files (default: ./rules)",
    )
    parser.add_argument(
        "-f", "--target",
        default=".",
        help="File or folder to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of a colored report",
    )
    return parser.parse_args()


def load_rule_files(rules_path):
    if os.path.isfile(rules_path):
        return {os.path.basename(rules_path): rules_path}

    rule_files = {}
    for root, _, files in os.walk(rules_path):
        for name in files:
            if name.endswith(".yar") or name.endswith(".yara"):
                full_path = os.path.join(root, name)
                namespace = os.path.relpath(full_path, rules_path)
                rule_files[namespace] = full_path
    return rule_files


def collect_targets(target_path):
    if os.path.isfile(target_path):
        return [target_path]

    targets = []
    for root, _, files in os.walk(target_path):
        for name in files:
            targets.append(os.path.join(root, name))
    return targets


def sha256_of(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def score_color(score):
    if score >= 100:
        return Fore.RED
    if score >= 60:
        return Fore.YELLOW
    return Fore.GREEN


def scan_file(rules, filepath):
    try:
        matches = rules.match(filepath)
    except yara.Error:
        return None

    if not matches:
        return None

    total_score = 0
    matched_rules = []
    for match in matches:
        rule_score = int(match.meta.get("score", 10))
        total_score += rule_score
        matched_rules.append({
            "rule": match.rule,
            "score": rule_score,
            "description": match.meta.get("description", ""),
            "strings": [s.identifier for s in match.strings],
        })

    return {
        "file": filepath,
        "sha256": sha256_of(filepath),
        "score": total_score,
        "matches": matched_rules,
    }


def print_report(result):
    color = score_color(result["score"])
    print(f"{color}{Style.BRIGHT}[{result['score']} pts] {result['file']}{Style.RESET_ALL}")
    print(f"  sha256: {result['sha256']}")
    for m in result["matches"]:
        print(f"  - {m['rule']} (+{m['score']}): {m['description']}")
        print(f"      matched strings: {', '.join(m['strings']) or 'n/a'}")


def main():
    args = parse_args()

    rule_files = load_rule_files(args.rules)
    if not rule_files:
        print(f"{Fore.RED}No .yar rule files found in '{args.rules}'{Style.RESET_ALL}")
        sys.exit(1)

    try:
        rules = yara.compile(filepaths=rule_files)
    except yara.SyntaxError as e:
        print(f"{Fore.RED}Rule compile error: {e}{Style.RESET_ALL}")
        sys.exit(1)

    targets = collect_targets(args.target)
    if not targets:
        print(f"{Fore.RED}No files found to scan in '{args.target}'{Style.RESET_ALL}")
        sys.exit(1)

    results = []
    for filepath in targets:
        result = scan_file(rules, filepath)
        if result:
            results.append(result)

    if args.json:
        output = {
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": args.target,
            "rules_loaded": list(rule_files.keys()),
            "files_scanned": len(targets),
            "flagged": results,
        }
        print(json.dumps(output, indent=2))
        return

    print(f"Loaded {len(rule_files)} rule(s), scanned {len(targets)} file(s).\n")

    if not results:
        print(f"{Fore.GREEN}Clean — no matches.{Style.RESET_ALL}")
        return

    for result in sorted(results, key=lambda r: r["score"], reverse=True):
        print_report(result)
        print()

    print(f"{Fore.RED}{len(results)} file(s) flagged out of {len(targets)} scanned.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()