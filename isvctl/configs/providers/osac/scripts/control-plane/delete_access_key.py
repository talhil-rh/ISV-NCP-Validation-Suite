#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Delete Keycloak client (access key teardown).

Receives ``--username`` (= clientId), looks up the internal UUID,
and deletes the client.

Output JSON:
{
    "success": true,
    "platform": "control_plane",
    "deleted_key": "isv-access-key-test-..."
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
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--skip-destroy", action="store_true")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    result: dict[str, Any] = {"success": False, "platform": "control_plane"}

    if args.skip_destroy:
        result["success"] = True
        result["skipped"] = True
        print(json.dumps(result, indent=2))
        return 0

    if DEMO_MODE:
        result["deleted_key"] = args.access_key_id
        result["deleted_user"] = args.username
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

        # Delete the client
        admin.delete_client(client_uuid)
        result["deleted_key"] = args.access_key_id
        result["deleted_user"] = args.username
        result["success"] = True

    except RuntimeError as e:
        err_msg = str(e)
        if "not found" in err_msg.lower():
            result["success"] = True
            result["already_deleted"] = True
        else:
            result["error"] = err_msg

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
