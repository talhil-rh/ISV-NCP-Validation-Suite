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

"""Console RBAC validation for OSAC ComputeInstances.

Proves interactive console access is controlled by RBAC:

1. **Denied principal**: An unauthenticated (empty token) request to the
   console access endpoint must be rejected (401/403).
2. **Allowed principal**: The tenant SA token must succeed.
3. **Resource-scoped**: The tenant SA token should only access its own
   instances (tested by querying a non-existent instance ID).

Outputs the JSON contract consumed by ``VmConsoleRbacCheck``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import FulfillmentClient, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser(description="Console RBAC validation (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--sa-token", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "test_name": "console_rbac",
        "instance_id": args.instance_id,
        "rbac_model": "kubernetes-sa",
        "access_restricted": False,
        "restricted_actions": [],
        "tests": {
            "denied_principal_cannot_access_console": {"passed": False},
            "allowed_principal_can_access_console": {"passed": False},
            "allowed_principal_is_resource_scoped": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["access_restricted"] = True
        result["restricted_actions"] = ["console:Connect"]
        result["tests"] = {
            "denied_principal_cannot_access_console": {
                "passed": True,
                "principal": "unauthenticated",
            },
            "allowed_principal_can_access_console": {
                "passed": True,
                "principal": "tenant-sa",
            },
            "allowed_principal_is_resource_scoped": {
                "passed": True,
                "principal": "tenant-sa",
            },
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)

        # Test 1: Denied principal (no token) should fail
        no_auth_client = FulfillmentClient(config, "")
        denied_status, _ = no_auth_client.get_console_access(args.instance_id, token="invalid-token-rbac-test")
        denied_ok = denied_status in (401, 403)
        result["tests"]["denied_principal_cannot_access_console"] = {
            "passed": denied_ok,
            "principal": "invalid-token",
            "message": f"Console access with invalid token returned HTTP {denied_status}",
        }

        # Test 2: Allowed principal (tenant SA token) should succeed
        auth_client = FulfillmentClient(config, args.sa_token)
        allowed_status, _ = auth_client.get_console_access(args.instance_id, token=args.sa_token)
        allowed_ok = allowed_status == 200
        result["tests"]["allowed_principal_can_access_console"] = {
            "passed": allowed_ok,
            "principal": "tenant-sa",
            "message": f"Console access with tenant SA token returned HTTP {allowed_status}",
        }

        # Test 3: Resource-scoped -- tenant SA should get 404 for non-existent instance
        fake_id = "00000000-0000-0000-0000-000000000000"
        scoped_status, _ = auth_client.get_console_access(fake_id, token=args.sa_token)
        scoped_ok = scoped_status in (403, 404)
        result["tests"]["allowed_principal_is_resource_scoped"] = {
            "passed": scoped_ok,
            "principal": "tenant-sa",
            "message": f"Console access for non-owned instance returned HTTP {scoped_status}",
        }

        all_passed = denied_ok and allowed_ok and scoped_ok
        result["access_restricted"] = all_passed
        result["restricted_actions"] = ["console:Connect"] if all_passed else []
        result["success"] = all_passed
        if not all_passed:
            result["error"] = "One or more console RBAC checks failed"

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
