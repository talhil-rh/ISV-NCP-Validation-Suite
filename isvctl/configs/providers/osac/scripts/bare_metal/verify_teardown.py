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

"""Verify a BareMetalInstance was fully deleted (SEC21-01).

Teardown step for StepSuccessCheck / sanitization: GETs the BMI and
expects HTTP 404, confirming the instance is gone from the API.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import FulfillmentClient, get_admin_token, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify BareMetalInstance deleted (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "verify_teardown",
        "tests": {
            "sanitization_confirmed": {"passed": False, "message": ""},
        },
    }

    if DEMO_MODE:
        result["success"] = True
        result["tests"]["sanitization_confirmed"] = {
            "passed": True,
            "message": f"BareMetalInstance {args.instance_id} confirmed deleted (demo mode)",
        }
        print(json.dumps(result, indent=2))
        return 0

    try:
        # Use admin Keycloak credentials — the ephemeral tenant namespace is
        # already deleted by teardown, and the admin token has cross-tenant
        # visibility so it correctly returns 404 once the BMI is gone.
        config = get_env_config(require_admin=True)
        token = get_admin_token(config)
        client = FulfillmentClient(config, token)

        status, _ = client.get_bare_metal_instance(args.instance_id)
        if status in (404, 410):
            result["success"] = True
            result["tests"]["sanitization_confirmed"] = {
                "passed": True,
                "message": f"BareMetalInstance {args.instance_id} confirmed deleted (404)",
            }
        else:
            result["tests"]["sanitization_confirmed"] = {
                "passed": False,
                "message": f"BareMetalInstance {args.instance_id} still exists (HTTP {status})",
            }

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
        result["tests"]["sanitization_confirmed"]["message"] = str(exc)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
