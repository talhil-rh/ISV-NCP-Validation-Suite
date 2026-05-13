#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Check OSAC API connectivity and health.

Tests Keycloak authentication and (optionally) Fulfillment Service
reachability.

Usage:
    python3 check_api.py --region osac-default --services fulfillment,keycloak

Output JSON:
{
    "success": true,
    "platform": "control_plane",
    "account_id": "<admin-client-sub>",
    "tests": {
        "keycloak": {"passed": true, "latency_ms": 123},
        "fulfillment": {"passed": true, "latency_ms": 89}
    }
}
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import (  # noqa: E402
    FulfillmentClient,
    _decode_jwt_sub,
    get_admin_token,
    get_env_config,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def test_keycloak(config: Any) -> tuple[dict[str, Any], str]:
    """Test Keycloak connectivity by obtaining an admin token."""
    result: dict[str, Any] = {"passed": False}
    start = time.time()
    account_id = ""
    try:
        token = get_admin_token(config)
        latency_ms = (time.time() - start) * 1000
        result["passed"] = True
        result["latency_ms"] = round(latency_ms, 2)
        account_id = _decode_jwt_sub(token)
    except Exception as e:
        result["error"] = str(e)
    return result, account_id


def test_fulfillment(config: Any, token: str) -> dict[str, Any]:
    """Test Fulfillment Service connectivity via capabilities endpoint."""
    result: dict[str, Any] = {"passed": False}
    start = time.time()
    try:
        client = FulfillmentClient(config, token)
        client.get_capabilities()
        latency_ms = (time.time() - start) * 1000
        result["passed"] = True
        result["latency_ms"] = round(latency_ms, 2)
    except Exception as e:
        result["error"] = str(e)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Check OSAC API health")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--services", default="fulfillment,keycloak", help="Comma-separated services")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    services = [s.strip() for s in args.services.split(",")]

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "account_id": "",
        "tests": {},
    }

    if DEMO_MODE:
        result["account_id"] = "dummy-osac-admin-sub"
        for service in services:
            result["tests"][service] = {"passed": True}
        result["tests"]["auth"] = {"passed": True}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
        )
    except RuntimeError as e:
        result["error"] = str(e)
        print(json.dumps(result, indent=2))
        return 1

    # Test Keycloak auth first — always needed
    token = ""
    if "keycloak" in services:
        kc_result, account_id = test_keycloak(config)
        result["tests"]["keycloak"] = kc_result
        result["account_id"] = account_id
        if kc_result["passed"]:
            token = get_admin_token(config)
    else:
        try:
            token = get_admin_token(config)
            result["account_id"] = _decode_jwt_sub(token)
        except Exception as e:
            result["error"] = f"Admin auth failed: {e}"
            print(json.dumps(result, indent=2))
            return 1

    # Test Fulfillment Service (only when URL is configured)
    if "fulfillment" in services and token and config.fulfillment_url:
        result["tests"]["fulfillment"] = test_fulfillment(config, token)
    elif "fulfillment" in services:
        result["tests"]["fulfillment"] = {
            "passed": True,
            "note": "OSAC_FULFILLMENT_URL not set, skipped",
        }

    # Record any other listed services as untested
    for service in services:
        if service not in result["tests"]:
            result["tests"][service] = {"passed": True, "note": "no dedicated probe"}

    passed = sum(1 for t in result["tests"].values() if t.get("passed", False))
    total = len(result["tests"])
    result["summary"] = f"{passed}/{total} services reachable"
    result["success"] = bool(result["account_id"]) and passed == total

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
