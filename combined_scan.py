#!/usr/bin/env python3
"""
combined_scan.py

IAM Security Auditor -- Cloudsplaining + PassRole blind-spot detector
This runs two layers of analysis against an IAM policy file

"""

import argparse
import json
import sys
from pathlib import Path

from cloudsplaining.scan.policy_document import PolicyDocument

from privesc_detector import find_passrole_blind_spots, load_policy


def run_combined_scan(policy_path: Path) -> dict:
    policy_document_json = load_policy(policy_path)
    pd = PolicyDocument(policy_document_json)

    cloudsplaining_privesc = pd.allows_privilege_escalation  # list[{"type": ..., "actions": [...]}]
    cloudsplaining_flagged_methods = {finding["type"] for finding in cloudsplaining_privesc}

    blind_spots = find_passrole_blind_spots(policy_document_json, cloudsplaining_flagged_methods)

    return {
        "file": str(policy_path),
        "cloudsplaining": {
            "privilege_escalation": cloudsplaining_privesc,
            "data_exfiltration_actions": sorted(pd.allows_data_exfiltration_actions),
            "resource_exposure": sorted(pd.permissions_management_without_constraints),
            "service_wildcard": sorted(pd.service_wildcard),
            "credentials_exposure": sorted(pd.credentials_exposure),
        },
        "passrole_blind_spots": blind_spots,
    }


def print_human_readable(result: dict) -> None:
    print(f"\n{'=' * 72}")
    print(f"POLICY: {result['file']}")
    print(f"{'=' * 72}")

    cs = result["cloudsplaining"]
    print("\n[Cloudsplaining]")
    if cs["privilege_escalation"]:
        for finding in cs["privilege_escalation"]:
            print(f"  - Privilege escalation: {finding['type']} ({', '.join(finding['actions'])})")
    else:
        print("  - No privilege escalation flagged")
    for key in ("data_exfiltration_actions", "resource_exposure", "service_wildcard", "credentials_exposure"):
        if cs[key]:
            print(f"  - {key}: {', '.join(cs[key])}")

    print("\n[privesc_detector -- PassRole resource-scoping blind spots]")
    if not result["passrole_blind_spots"]:
        print("  - None found for this policy")
    else:
        for finding in result["passrole_blind_spots"]:
            print(f"  [BLIND SPOT] {finding['method']}")
            print(f"      Required actions: {', '.join(finding['required_actions'])}")
            print(f"      Unrestricted PassRole resource(s): "
                  f"{', '.join(finding['unrestricted_passrole_resource_patterns'])}")
            print(f"      Why Cloudsplaining misses it: {finding['why_this_is_a_blind_spot']}")
    print()


def main():
    parser = argparse.ArgumentParser(description="IAM Security Auditor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input-file", help="Path to a single IAM policy JSON file")
    group.add_argument("--input-dir", help="Path to a directory of IAM policy JSON files")
    parser.add_argument("--output", help="Optional path to write the combined report as JSON")
    args = parser.parse_args()

    policy_paths = [Path(args.input_file)] if args.input_file else sorted(Path(args.input_dir).glob("*.json"))
    if not policy_paths:
        print("No policy files found.", file=sys.stderr)
        sys.exit(1)

    all_results = []
    for policy_path in policy_paths:
        try:
            result = run_combined_scan(policy_path)
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to scan {policy_path}: {exc}", file=sys.stderr)
            continue
        all_results.append(result)
        print_human_readable(result)

    total_blind_spots = sum(len(r["passrole_blind_spots"]) for r in all_results)
    print(f"{'=' * 72}")
    print(f"SUMMARY: {len(all_results)} polic{'y' if len(all_results) == 1 else 'ies'} scanned, "
          f"{total_blind_spots} PassRole blind-spot finding(s)")
    print(f"{'=' * 72}\n")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"Full JSON report written to {args.output}")


if __name__ == "__main__":
    main()
