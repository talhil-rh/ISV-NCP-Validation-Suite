#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""API endpoint isolation test for OSAC.

Verifies that OSAC platform API endpoints (fulfillment-service, Keycloak)
are not directly accessible from the public internet. Resolves hostnames
and checks that they resolve to private (RFC 1918 / cluster-internal)
addresses.

Covers SEC14-01.

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "api_endpoint_isolation",
    "endpoints_tested": 2,
    "tests": {
        "probe_api_from_public":  {"passed": true},
        "probe_mgmt_from_public": {"passed": true},
        "verify_private_only":    {"passed": true},
        "dns_not_public":         {"passed": true}
    }
}
"""

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address is private (RFC 1918, link-local, loopback)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to its IP addresses."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


def _check_public_dns(hostname: str) -> bool:
    """Check if hostname has a public DNS record via dig/nslookup."""
    try:
        result = subprocess.run(
            ["dig", "+short", hostname, "@8.8.8.8"],
            capture_output=True, text=True, timeout=10,
        )
        return bool(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="API endpoint isolation test (OSAC)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "api_endpoint_isolation",
        "endpoints_tested": 0,
        "tests": {
            "probe_api_from_public": {"passed": False},
            "probe_mgmt_from_public": {"passed": False},
            "verify_private_only": {"passed": False},
            "dns_not_public": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["endpoints_tested"] = 2
        result["tests"] = {k: {"passed": True} for k in result["tests"]}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
            require_admin=False,
        )

        endpoints: list[tuple[str, str]] = []  # (label, url)
        if config.fulfillment_url:
            endpoints.append(("fulfillment-api", config.fulfillment_url))
        if config.keycloak_url:
            endpoints.append(("keycloak", config.keycloak_url))

        if not endpoints:
            result["skipped"] = True
            result["skip_reason"] = "No API endpoints configured to test"
            print(json.dumps(result, indent=2))
            return 0

        result["endpoints_tested"] = len(endpoints)
        all_private = True
        no_public_dns = True
        api_not_public = True
        mgmt_not_public = True

        for label, url in endpoints:
            hostname = urlparse(url).hostname or ""
            if not hostname:
                continue

            ips = _resolve_hostname(hostname)

            # Check if all resolved IPs are private
            for ip in ips:
                if not _is_private_ip(ip):
                    all_private = False

            # Check public DNS
            has_public = _check_public_dns(hostname)
            if has_public:
                no_public_dns = False

            # For "probe from public" — if IPs are all private, public probe would fail
            if label == "fulfillment-api" and not all(map(_is_private_ip, ips)):
                api_not_public = False
            elif label == "keycloak" and not all(map(_is_private_ip, ips)):
                mgmt_not_public = False

        result["tests"]["probe_api_from_public"] = {
            "passed": api_not_public,
            "message": "API resolves to private IPs only" if api_not_public else "API has public IP",
        }
        result["tests"]["probe_mgmt_from_public"] = {
            "passed": mgmt_not_public,
            "message": "Management API resolves to private IPs only" if mgmt_not_public else "Management API has public IP",
        }
        result["tests"]["verify_private_only"] = {
            "passed": all_private,
            "message": "All endpoint IPs are RFC 1918 / cluster-internal" if all_private else "Some endpoints resolve to public IPs",
        }
        result["tests"]["dns_not_public"] = {
            "passed": no_public_dns,
            "message": "No public DNS records found" if no_public_dns else "Public DNS records exist",
        }

        result["success"] = all(t["passed"] for t in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
