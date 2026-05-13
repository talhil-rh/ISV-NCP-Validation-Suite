#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Create Keycloak OAuth2 client (access key equivalent).

Creates a Keycloak client with service accounts enabled and retrieves
its client secret. Maps to the IAM access-key lifecycle.

Output JSON:
{
    "success": true,
    "platform": "control_plane",
    "username": "isv-access-key-test-a1b2c3d4",
    "access_key_id": "isv-access-key-test-a1b2c3d4",
    "secret_access_key": "<client-secret>"
}
"""

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import KeycloakAdmin, get_admin_token, get_env_config  # noqa: E402

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--username-prefix", default="isv-access-key-test")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    client_id = f"{args.username_prefix}-{uuid.uuid4().hex[:8]}"

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "username": client_id,
        "access_key_id": client_id,
    }

    if DEMO_MODE:
        result["secret_access_key"] = "demo-secret-key-osac"
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
        )
        token = get_admin_token(config)
        admin = KeycloakAdmin(config, token)

        # Create Keycloak client
        client_rep = admin.create_client(client_id)
        client_uuid = client_rep["id"]

        # Retrieve the generated client secret
        secret = admin.get_client_secret(client_uuid)
        result["secret_access_key"] = secret
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
