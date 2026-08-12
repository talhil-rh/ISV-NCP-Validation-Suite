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

"""GET a single VirtualNetwork by ID (VpcReadFromInventoryCheck / SDN01-02)."""

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
    parser = argparse.ArgumentParser(description="GET VirtualNetwork by ID (OSAC)")
    parser.add_argument("--vnet-id", required=True, help="VNet UUID from create_network")
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "get_vpc",
        "vpc_id": "",
        "vpc_name": "",
    }

    if DEMO_MODE:
        result.update({
            "success": True,
            "vpc_id": args.vnet_id,
            "vpc_name": "isv-net-demo",
        })
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        status, body = client.get_virtual_network(args.vnet_id)
        if status != 200:
            result["error"] = f"get_virtual_network failed (HTTP {status}): {body}"
            print(json.dumps(result, indent=2))
            return 1

        result["vpc_id"] = body.get("id", "")
        result["vpc_name"] = body.get("metadata", {}).get("name", "")
        result["success"] = bool(result["vpc_id"] and result["vpc_name"])

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
