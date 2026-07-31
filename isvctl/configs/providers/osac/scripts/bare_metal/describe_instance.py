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

"""Describe (GET) a BareMetalInstance and emit its current state.

Test step: reads instance state via the public fulfillment API.
Passes ``public_ip`` and ``key_file`` through from launch so that
downstream SSH-labeled checks can reference ``steps.describe_instance.*``
via Jinja2 without reconfiguration.
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


def extract_external_ip(body: dict[str, Any]) -> str | None:
    """Return the external/public IP from a BMI status dict, or None."""
    status = body.get("status", {})
    for field in ("external_ip", "externalIp", "public_ip", "publicIp"):
        ip = status.get(field)
        if ip:
            return str(ip)
    for attachment in status.get("network_attachments", []):
        for field in ("external_ip", "public_ip"):
            ip = attachment.get(field)
            if ip:
                return str(ip)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Describe BareMetalInstance (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    parser.add_argument("--key-file", default="", help="Path to private SSH key (pass-through)")
    parser.add_argument("--external-ip", default="", help="External IP (pass-through)")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "describe_instance",
        "instance_id": args.instance_id,
        "state": "",
        "public_ip": args.external_ip or None,
        "key_file": args.key_file or "",
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "state": "running",
                "public_ip": args.external_ip or "192.0.2.1",
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
        result["state"] = raw_state.lower().removeprefix("bare_metal_instance_state_")

        # Try to read the external IP from the API response; fall back to
        # what was passed in via --external-ip (set during launch).
        api_ip = extract_external_ip(body)
        result["public_ip"] = api_ip or args.external_ip or None
        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
