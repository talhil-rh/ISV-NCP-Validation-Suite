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

"""List BareMetalInstances visible to the tenant and locate a target instance.

Test step for InstanceListCheck: lists all BMIs and verifies the target
instance (from launch_instance) is present in the result.
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
    parser = argparse.ArgumentParser(description="List BareMetalInstances (OSAC)")
    parser.add_argument("--target-id", required=True, help="Instance ID to search for in the list")
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "list_instances",
        "instances": [],
        "count": 0,
        "found_target": False,
        "target_instance": args.target_id,
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "instances": [
                    {
                        "instance_id": args.target_id,
                        "state": "running",
                        "vpc_id": "none",
                    }
                ],
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

        status, body = client.list_bare_metal_instances()
        if status != 200:
            result["error"] = f"List BareMetalInstances failed (HTTP {status}): {body}"
            print(json.dumps(result, indent=2))
            return 1

        items = body.get("items", []) if isinstance(body, dict) else []
        instances: list[dict[str, Any]] = []
        found = False

        for item in items:
            bmi_id = item.get("id", "")
            raw_state = item.get("status", {}).get("state", "")
            # Use the first network attachment's subnet as a rough vpc_id equivalent
            attachments = item.get("spec", {}).get("network_attachments", [])
            vpc_id = attachments[0].get("subnet", "none") if attachments else "none"
            instances.append(
                {
                    "instance_id": bmi_id,
                    "state": raw_state.lower(),
                    "vpc_id": vpc_id,
                }
            )
            if bmi_id == args.target_id:
                found = True

        result.update(
            {
                "success": True,
                "instances": instances,
                "count": len(instances),
                "found_target": found,
            }
        )

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
