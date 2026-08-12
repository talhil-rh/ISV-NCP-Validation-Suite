#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""VPC (VirtualNetwork) list test for OSAC (SDN01-05).

Lists all VirtualNetworks visible to the tenant and verifies that the
target VPC (created during setup) appears in the listing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import FulfillmentClient, create_sa_token, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser(description="VPC list test (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    parser.add_argument("--target-vpc-id", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "list_vpcs",
        "vpcs": [],
        "count": 0,
        "found_target": False,
        "tests": {
            "list_vpcs": {"passed": False},
            "found_target": {"passed": False},
            "count_check": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["vpcs"] = [
            {"id": "isv-demo-vpc-1", "name": "isv-demo-vpc-1", "cidr": "10.200.0.0/16"},
            {"id": args.target_vpc_id, "name": "isv-net-demo", "cidr": "10.100.0.0/16"},
        ]
        result["count"] = 2
        result["found_target"] = True
        result["tests"] = {
            "list_vpcs": {"passed": True, "count": 2},
            "found_target": {"passed": True, "target_id": args.target_vpc_id},
            "count_check": {"passed": True},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        status, body = client.list_virtual_networks()
        if status != 200:
            result["tests"]["list_vpcs"]["error"] = f"HTTP {status}: {body}"
            print(json.dumps(result, indent=2))
            return 1

        items = body.get("items", [])
        vpcs = [
            {
                "id": v.get("id", ""),
                "name": v.get("metadata", {}).get("name", ""),
                "cidr": v.get("spec", {}).get("ipv4_cidr", ""),
            }
            for v in items
        ]
        count = len(vpcs)

        result["vpcs"] = vpcs
        result["count"] = count
        result["tests"]["list_vpcs"] = {"passed": True, "count": count}

        # count_check: at least one VPC exists
        if count >= 1:
            result["tests"]["count_check"] = {"passed": True}
        else:
            result["tests"]["count_check"] = {"passed": False, "error": "No VPCs returned"}

        # found_target: target VPC appears in listing
        target_found = any(v["id"] == args.target_vpc_id for v in vpcs)
        result["found_target"] = target_found
        if target_found:
            result["tests"]["found_target"] = {"passed": True, "target_id": args.target_vpc_id}
        else:
            result["tests"]["found_target"] = {
                "passed": False,
                "error": f"Target VPC {args.target_vpc_id} not found in listing",
            }

        result["success"] = all(t.get("passed") for t in result["tests"].values())

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
