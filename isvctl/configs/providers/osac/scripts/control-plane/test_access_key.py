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

"""Test access key authentication via Keycloak client_credentials grant.

Output JSON:
{
    "success": true,
    "platform": "control_plane",
    "authenticated": true,
    "identity_id": "<jwt-sub>"
}
"""

import argparse
import json
import os
import sys
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
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "authenticated": False,
    }

    if DEMO_MODE:
        result["authenticated"] = True
        result["identity_id"] = "demo-sub-osac-12345"
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        auth_result = authenticate_with_client_credentials(config, args.access_key_id, args.secret_access_key)

        if auth_result["success"]:
            result["authenticated"] = True
            result["identity_id"] = auth_result["sub"]
            result["success"] = True
        else:
            result["authenticated"] = False
            result["error"] = auth_result.get("error", "Authentication failed")

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
