# YARA Scanner

A command-line tool that scans files against custom YARA rules and reports a weighted risk score.

## What it does

- Loads all `.yar` rule files from a rules folder (or a single rule file)
- Recursively scans every file in a target folder
- For every rule that matches a file, adds that rule's `score` (defined in the rule's `meta` block) to a running total
- Reports flagged files sorted highest-risk first, with SHA-256 hashes for tracking
- Supports both a human-readable colored report and machine-readable `--json` output

## Why weighted scoring instead of just match/no-match

A single suspicious string alone (e.g. the word "bitcoin") isn't a reliable signal — it causes false positives. Each rule requires multiple related indicators to be present together, and contributes a score rather than a flat flag, so a file matching several suspicious patterns is clearly distinguishable from one matching just one weak signal.

## Included rules

| Rule | Detects | Score |
|---|---|---|
| `EICAR_Test_File` | The standard EICAR antivirus test string | 100 |
| `Ransomware_Note` | 2+ common ransomware note phrases | 60 |
| `PowerShell_Download` | 2+ indicators of silent download-and-execute PowerShell | 70 |
| `PHP_Webshell` | 3+ common PHP webshell functions | 80 |

## Installation

    pip install -r requirements.txt

## Usage

    python scanner.py -r rules -f samples

| Flag | Description | Default |
|---|---|---|
| `-r`, `--rules` | Path to a `.yar` file or folder of rules | `rules` |
| `-f`, `--target` | File or folder to scan | current directory |
| `--json` | Output as JSON instead of a colored report | off |

### Example output

    [60 pts] samples\ransom_note_test.txt
      sha256: fea52442208f8a15fd78bf77b24f99295695f0370c633593adb82bf88990c14d
      - Suspicious_Ransomware_Note (+60): Flags common ransomware note phrasing
          matched strings: $s1, $s2, $s3, $s4

## Project structure

    Scanner/
    ├── scanner.py              # CLI entry point and scanning engine
    ├── requirements.txt
    ├── rules/                  # Custom YARA rules
    │   ├── eicar_test.yar
    │   ├── suspicious_strings.yar
    │   └── webshell_indicators.yar
    └── samples/                # Test files

## Built with

- [yara-python](https://github.com/VirusTotal/yara-python) — Python bindings for the YARA pattern-matching engine
- [colorama](https://github.com/tartley/colorama) — cross-platform colored terminal output
