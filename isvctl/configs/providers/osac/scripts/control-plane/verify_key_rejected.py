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

"""Verify disabled access key is rejected.

Attempts ``client_credentials`` grant with the disabled client's
credentials — expects Keycloak to return an error.

Always exits 0; the validation checks the ``rejected`` field.

Output JSON:
{
    "success": true,
    "platform": "control_plane",
    "rejected": true,
    "error_code": "unauthorized_client"
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

from common.osac_client import authenticate_with_client_credentials, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--access-key-id", required=True)
    parser.add_argument("--secret-access-key", required=True)
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--wait", type=int, default=2, help="Initial wait for propagation")
    parser.add_argument("--retries", type=int, default=3, help="Number of retry attempts")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "rejected": False,
    }

    if DEMO_MODE:
        result["rejected"] = True
        result["error_code"] = "unauthorized_client"
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
    except RuntimeError as e:
        result["error"] = str(e)
        print(json.dumps(result, indent=2))
        return 0

    # Wait for disable to propagate
    if args.wait > 0:
        time.sleep(args.wait)

    for attempt in range(args.retries):
        auth_result = authenticate_with_client_credentials(config, args.access_key_id, args.secret_access_key)

        if not auth_result["success"]:
            # Auth failed = key was rejected (expected)
            result["rejected"] = True
            result["error_code"] = auth_result.get("error_code", "unknown")
            result["success"] = True
            break

        # Key still active — retry if attempts remaining
        if attempt < args.retries - 1:
            time.sleep(2 ** (attempt + 1))
            continue

        # Final attempt — key still active
        result["rejected"] = False
        result["error"] = "Key was not rejected after retries - still active"

    print(json.dumps(result, indent=2))
    # Always exit 0 — let validation check the 'rejected' field
    return 0


if __name__ == "__main__":
    sys.exit(main())
