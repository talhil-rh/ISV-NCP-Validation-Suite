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

"""Emit SSH connection details for the DhcpIpManagementCheck validation.

The validation itself SSHes into the instance and probes DHCP state.
This script confirms the BMI is running and outputs the connection
details (public_ip, private_ip, key_file, ssh_user) that the
validation needs.
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
    parser = argparse.ArgumentParser(description="DHCP/IP management test (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    parser.add_argument("--key-file", default="", help="Path to private SSH key")
    parser.add_argument("--external-ip", default="", help="External/BMH IP")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "dhcp_ip_test",
        "public_ip": args.external_ip or None,
        "private_ip": args.external_ip or None,
        "key_file": args.key_file or "",
        "ssh_user": "fedora",
        "instance_id": args.instance_id,
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "public_ip": args.external_ip or "192.0.2.1",
                "private_ip": args.external_ip or "192.0.2.1",
                "key_file": args.key_file or "/tmp/demo-bmi.pem",
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        status, body = client.get_bare_metal_instance(args.instance_id)
        if status != 200:
            result["error"] = f"GET BareMetalInstance failed (HTTP {status}): {body}"
            print(json.dumps(result, indent=2))
            return 1

        raw_state = body.get("status", {}).get("state", "")
        state = raw_state.lower().removeprefix("bare_metal_instance_state_")
        if state != "running":
            result["error"] = f"BMI not running (state={state})"
            print(json.dumps(result, indent=2))
            return 1

        ip = args.external_ip
        if not ip:
            bmi_status = body.get("status", {})
            for field in ("external_ip", "externalIp", "public_ip", "publicIp"):
                if bmi_status.get(field):
                    ip = str(bmi_status[field])
                    break

        if not ip:
            result["error"] = "No IP available for SSH"
            print(json.dumps(result, indent=2))
            return 1

        result.update(
            {
                "success": True,
                "public_ip": ip,
                "private_ip": ip,
            }
        )

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
