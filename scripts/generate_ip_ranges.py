#!/usr/bin/env python3
"""Fetch IANA special-purpose registries and cloud provider service IP ranges.

Updates:
  - crates/ressrf-core/config/ip_ranges.json (IANA deny tiers)
  - crates/ressrf-core/config/domains_{aws,azure,gcp}.json (deny ranges, domains, service ranges)

Dependencies: Python 3.10+ stdlib only (no pip packages).

Usage:
  python scripts/generate_ip_ranges.py           # fetch all upstream sources
  python scripts/generate_ip_ranges.py --iana-only   # only fetch IANA CSVs
  python scripts/generate_ip_ranges.py --validate-only  # validate existing JSON, no network
  python scripts/generate_ip_ranges.py --dry-run     # print changes without writing
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import io
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "crates" / "ressrf-core" / "config"

IANA_IPV4_URL = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv"
IANA_IPV6_URL = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv"

AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_CLOUD_URL = "https://www.gstatic.com/ipranges/cloud.json"
GCP_GOOG_URL = "https://www.gstatic.com/ipranges/goog.json"

TIER_1B_NAMES = {"AS112-v4", "AMT", "Direct Delegation AS112"}
TIER_1B_CIDRS = {"192.31.196.0/24", "192.52.193.0/24", "192.175.48.0/24", "192.88.99.0/24"}


def fetch_url(url: str) -> bytes:
    """Fetch a URL and return raw bytes, logging SHA-256 for auditability."""
    print(f"  Fetching {url} ...", end=" ", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "ressrf-codegen/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    sha = hashlib.sha256(data).hexdigest()
    print(f"OK ({len(data)} bytes, sha256={sha[:16]}...)")
    return data


def parse_iana_csv(raw: bytes, version: int) -> list[dict[str, Any]]:
    """Parse IANA special-purpose registry CSV and extract deny-worthy entries."""
    text = raw.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))

    entries = []
    for row in reader:
        address_block = row.get("Address Block", row.get("Address  Block", "")).strip()
        name = row.get("Name", "").strip()
        rfc_ref = row.get("RFC", row.get("Reference", "")).strip()
        globally_reachable = row.get("Globally Reachable", row.get("Global", "")).strip().lower()

        if not address_block:
            continue

        # Tier 1a: Globally Reachable == False
        is_tier_1a = globally_reachable in ("false", "no", "n/a")
        # Tier 1b: infrastructure-only ranges
        is_tier_1b = name in TIER_1B_NAMES or address_block in TIER_1B_CIDRS

        if not (is_tier_1a or is_tier_1b):
            continue

        # Normalize CIDR: IANA sometimes uses ranges like "192.0.0.0/24 [2]"
        cidr = address_block.split("[")[0].strip().split(" ")[0].strip()

        # Some IANA entries have multiple CIDRs separated by commas or newlines
        for part in cidr.replace("\n", ",").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if version == 4:
                    ipaddress.IPv4Network(part, strict=False)
                else:
                    ipaddress.IPv6Network(part, strict=False)
            except (ValueError, ipaddress.AddressValueError):
                print(f"  WARNING: skipping unparseable CIDR '{part}' from {name}")
                continue

            tier_label = "[Tier 1b]" if is_tier_1b and not is_tier_1a else ""
            entry_name = f"{name} {tier_label}".strip()
            rfc_str = rfc_ref.split(",")[0].strip("[] ") if rfc_ref else None

            entries.append({
                "cidr": part,
                "rfc": rfc_str if rfc_str else None,
                "name": entry_name,
            })

    return entries


def fetch_iana(ip_ranges: dict) -> dict:
    """Fetch IANA registries and update ip_ranges tiers."""
    print("Fetching IANA IPv4 special-purpose registry...")
    ipv4_data = fetch_url(IANA_IPV4_URL)
    ipv4_entries = parse_iana_csv(ipv4_data, 4)

    print("Fetching IANA IPv6 special-purpose registry...")
    ipv6_data = fetch_url(IANA_IPV6_URL)
    ipv6_entries = parse_iana_csv(ipv6_data, 6)

    ip_ranges["tiers"]["iana_ipv4"]["entries"] = ipv4_entries
    ip_ranges["tiers"]["iana_ipv6"]["entries"] = ipv6_entries
    return ip_ranges


def fetch_aws_ranges() -> dict[str, list[str]]:
    """Fetch AWS ip-ranges.json and group by service."""
    print("Fetching AWS service ranges...")
    data = json.loads(fetch_url(AWS_RANGES_URL))
    service_map: dict[str, list[str]] = {}

    for prefix in data.get("prefixes", []):
        service = prefix.get("service", "UNKNOWN")
        cidr = prefix.get("ip_prefix", "")
        if cidr:
            service_map.setdefault(service, []).append(cidr)

    for prefix in data.get("ipv6_prefixes", []):
        service = prefix.get("service", "UNKNOWN")
        cidr = prefix.get("ipv6_prefix", "")
        if cidr:
            service_map.setdefault(service, []).append(cidr)

    # Sort for deterministic output
    for svc in service_map:
        service_map[svc] = sorted(set(service_map[svc]))

    total = sum(len(v) for v in service_map.values())
    print(f"  AWS: {total} prefixes across {len(service_map)} services")
    return {"sync_token": data.get("syncToken", ""), "prefixes": dict(sorted(service_map.items()))}


def fetch_gcp_ranges() -> dict[str, list[str]]:
    """Fetch GCP cloud.json and goog.json."""
    print("Fetching GCP service ranges...")
    cloud_data = json.loads(fetch_url(GCP_CLOUD_URL))
    goog_data = json.loads(fetch_url(GCP_GOOG_URL))

    cloud_prefixes = []
    for prefix in cloud_data.get("prefixes", []):
        cidr = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix", "")
        if cidr:
            cloud_prefixes.append(cidr)

    goog_prefixes = []
    for prefix in goog_data.get("prefixes", []):
        cidr = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix", "")
        if cidr:
            goog_prefixes.append(cidr)

    service_map = {
        "CLOUD": sorted(set(cloud_prefixes)),
        "GOOGLE": sorted(set(goog_prefixes)),
    }
    total = sum(len(v) for v in service_map.values())
    print(f"  GCP: {total} prefixes across {len(service_map)} categories")
    return {"prefixes": service_map}


def fetch_azure_ranges() -> dict[str, list[str]]:
    """Fetch Azure ServiceTags JSON.

    The download URL rotates weekly. We try the well-known download page
    to discover the current URL, falling back to a direct attempt.
    """
    print("Fetching Azure service ranges...")
    discovery_url = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
    try:
        page = fetch_url(discovery_url).decode("utf-8", errors="replace")
        match = re.search(r'https://download\.microsoft\.com/[^"\']+ServiceTags_Public_\d+\.json', page)
        if match:
            json_url = match.group(0)
            data = json.loads(fetch_url(json_url))
        else:
            print("  WARNING: Could not find Azure ServiceTags URL, skipping service ranges")
            return {"prefixes": {}}
    except Exception as e:
        print(f"  WARNING: Azure fetch failed ({e}), skipping service ranges")
        return {"prefixes": {}}

    service_map: dict[str, list[str]] = {}
    for value in data.get("values", []):
        name = value.get("name", "UNKNOWN")
        props = value.get("properties", {})
        prefixes = props.get("addressPrefixes", [])
        if prefixes:
            service_map[name] = sorted(set(prefixes))

    total = sum(len(v) for v in service_map.values())
    print(f"  Azure: {total} prefixes across {len(service_map)} services")
    return {"prefixes": dict(sorted(service_map.items()))}


def update_domain_file(provider: str, service_ranges: dict) -> None:
    """Update the service_ranges field of a domains_*.json file."""
    path = CONFIG_DIR / f"domains_{provider}.json"
    data = json.loads(path.read_text())
    data["service_ranges"] = service_ranges
    write_json(path, data)


def validate_ip_ranges(ip_ranges: dict) -> list[str]:
    """Validate all CIDRs in ip_ranges.json parse correctly."""
    errors = []
    for tier_name, tier_data in ip_ranges.get("tiers", {}).items():
        seen = set()
        for entry in tier_data.get("entries", []):
            cidr = entry.get("cidr", "")
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                errors.append(f"{tier_name}: invalid CIDR '{cidr}': {e}")
            if cidr in seen:
                errors.append(f"{tier_name}: duplicate CIDR '{cidr}'")
            seen.add(cidr)
    return errors


def validate_domain_file(path: Path) -> list[str]:
    """Validate a domains_*.json file."""
    errors = []
    data = json.loads(path.read_text())

    for entry in data.get("deny_ranges", []):
        cidr = entry.get("cidr", "")
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            errors.append(f"{path.name}: invalid deny CIDR '{cidr}': {e}")

    service_ranges = data.get("service_ranges", {})
    for svc, cidrs in service_ranges.get("prefixes", {}).items():
        for cidr in cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                errors.append(f"{path.name}: invalid service CIDR '{cidr}' in {svc}: {e}")

    return errors


def cross_check_csp_metadata(ip_ranges: dict) -> list[str]:
    """Verify every CIDR in csp_metadata appears in at least one provider's deny_ranges."""
    errors = []
    csp_cidrs = {
        entry["cidr"]
        for entry in ip_ranges.get("tiers", {}).get("csp_metadata", {}).get("entries", [])
    }

    provider_deny_cidrs: set[str] = set()
    for provider in ["aws", "azure", "gcp"]:
        path = CONFIG_DIR / f"domains_{provider}.json"
        if path.exists():
            data = json.loads(path.read_text())
            for entry in data.get("deny_ranges", []):
                provider_deny_cidrs.add(entry.get("cidr", ""))

    for cidr in sorted(csp_cidrs - provider_deny_cidrs):
        errors.append(f"csp_metadata CIDR '{cidr}' not found in any provider's deny_ranges")

    return errors


def write_json(path: Path, data: dict) -> None:
    """Write JSON with deterministic formatting."""
    content = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    path.write_text(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iana-only", action="store_true", help="Only fetch IANA CSVs, skip cloud service ranges")
    parser.add_argument("--validate-only", action="store_true", help="Validate existing JSON, no network")
    parser.add_argument("--dry-run", action="store_true", help="Print changes without writing")
    args = parser.parse_args()

    ip_ranges_path = CONFIG_DIR / "ip_ranges.json"
    ip_ranges = json.loads(ip_ranges_path.read_text())

    # Validate-only mode
    if args.validate_only:
        print("Validating existing config files...")
        errors = validate_ip_ranges(ip_ranges)
        for provider in ["aws", "azure", "gcp"]:
            errors.extend(validate_domain_file(CONFIG_DIR / f"domains_{provider}.json"))
        errors.extend(cross_check_csp_metadata(ip_ranges))

        if errors:
            print(f"\n{len(errors)} validation error(s):")
            for e in errors:
                print(f"  - {e}")
            return 1
        print("All config files valid.")
        return 0

    # Fetch mode
    print("=" * 60)
    print("ressrf IP ranges codegen")
    print("=" * 60)

    # Fetch IANA
    ip_ranges = fetch_iana(ip_ranges)

    # Fetch cloud service ranges (unless --iana-only)
    if not args.iana_only:
        aws_ranges = fetch_aws_ranges()
        gcp_ranges = fetch_gcp_ranges()
        azure_ranges = fetch_azure_ranges()

    # Validate
    errors = validate_ip_ranges(ip_ranges)
    if errors:
        print(f"\nValidation failed with {len(errors)} error(s):")
        for e in errors:
            print(f"  - {e}")
        return 1

    if args.dry_run:
        print("\n[DRY RUN] Would write updated files. No changes made.")
        return 0

    # Write outputs
    print("\nWriting updated config files...")
    write_json(ip_ranges_path, ip_ranges)
    print(f"  Updated {ip_ranges_path.relative_to(REPO_ROOT)}")

    if not args.iana_only:
        update_domain_file("aws", aws_ranges)
        print(f"  Updated config/domains_aws.json (service_ranges)")
        update_domain_file("gcp", gcp_ranges)
        print(f"  Updated config/domains_gcp.json (service_ranges)")
        update_domain_file("azure", azure_ranges)
        print(f"  Updated config/domains_azure.json (service_ranges)")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
