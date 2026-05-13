#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

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

from common.osac_client import authenticate_with_client_credentials, get_env_config  # noqa: E402

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
        auth_result = authenticate_with_client_credentials(
            config, args.access_key_id, args.secret_access_key
        )

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
