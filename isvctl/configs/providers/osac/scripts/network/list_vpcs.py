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

"""List VirtualNetworks and confirm the target VNet is present (VpcListedCheck)."""

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
    parser = argparse.ArgumentParser(description="List VirtualNetworks (OSAC)")
    parser.add_argument("--vnet-id", required=True, help="Target VNet UUID to confirm is listed")
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "list_vpcs",
        "vpcs": [],
        "count": 0,
        "found_target": False,
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "vpcs": [{"vpc_id": args.vnet_id, "vpc_name": "isv-net-demo"}],
                "count": 1,
                "found_target": True,
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        status, body = client.list_virtual_networks()
        if status != 200:
            result["error"] = f"list_virtual_networks failed (HTTP {status}): {body}"
            print(json.dumps(result, indent=2))
            return 1

        items = body if isinstance(body, list) else body.get("items", [])
        vpcs = []
        found = False
        for item in items:
            vpc_id = item.get("id", "")
            vpc_name = item.get("metadata", {}).get("name", "")
            vpcs.append({"vpc_id": vpc_id, "vpc_name": vpc_name})
            if vpc_id == args.vnet_id:
                found = True

        result["vpcs"] = vpcs
        result["count"] = len(vpcs)
        result["found_target"] = found
        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
