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

"""Verify a subnet is assigned to the target VNet (VpcContainsExpectedSubnetCheck)."""

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
    parser = argparse.ArgumentParser(description="Check subnet assignment to VNet (OSAC)")
    parser.add_argument("--vnet-id", required=True, help="VNet UUID from create_network")
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "subnet_assignment",
        "vpc_id": args.vnet_id,
        "subnets": [],
        "subnet_count": 0,
        "tests": {
            "subnet_assigned": {"passed": False},
        },
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "subnets": [{"subnet_id": "isv-sub-demo", "cidr": "10.200.0.0/24"}],
                "subnet_count": 1,
                "tests": {"subnet_assigned": {"passed": True}},
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        status, body = client.list_subnets()
        if status != 200:
            result["tests"]["subnet_assigned"]["error"] = f"list_subnets failed (HTTP {status})"
            print(json.dumps(result, indent=2))
            return 1

        items = body if isinstance(body, list) else body.get("items", [])
        subnets = []
        for item in items:
            spec = item.get("spec", {})
            vnet_ref = spec.get("virtual_network") or spec.get("virtualNetwork") or {}
            vnet_ref_id = vnet_ref.get("id") or vnet_ref.get("name") or ""
            if vnet_ref_id == args.vnet_id:
                sub_id = item.get("id", "")
                sub_cidr = spec.get("ipv4_cidr") or spec.get("ipv4Cidr") or ""
                subnets.append({"subnet_id": sub_id, "cidr": sub_cidr})

        result["subnets"] = subnets
        result["subnet_count"] = len(subnets)
        assigned = len(subnets) > 0
        result["tests"]["subnet_assigned"] = {
            "passed": assigned,
            "message": f"{len(subnets)} subnet(s) found in VNet {args.vnet_id}"
            if assigned
            else f"No subnets found in VNet {args.vnet_id}",
        }
        result["success"] = assigned

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
