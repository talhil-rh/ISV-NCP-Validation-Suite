#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Disable access key by disabling the Keycloak client.

Receives ``--username`` (= clientId) and looks up the internal UUID
via ``get_client_by_client_id``, then sets ``enabled: false``.

Output JSON:
{
    "success": true,
    "platform": "control_plane",
    "access_key_id": "isv-access-key-test-...",
    "status": "Inactive"
}
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import KeycloakAdmin, get_admin_token, get_env_config  # noqa: E402

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--access-key-id", required=True)
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "access_key_id": args.access_key_id,
    }

    if DEMO_MODE:
        result["status"] = "Inactive"
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

        # Look up client UUID by clientId (= username)
        client_rep = admin.get_client_by_client_id(args.username)
        client_uuid = client_rep["id"]

        # Disable the client
        admin.disable_client(client_uuid)
        result["status"] = "Inactive"
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
