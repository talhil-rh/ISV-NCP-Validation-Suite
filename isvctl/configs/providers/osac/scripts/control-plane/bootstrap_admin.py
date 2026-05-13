#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Bootstrap an ephemeral Keycloak admin client with manage-clients role.

Uses master-realm admin credentials (OSAC_KEYCLOAK_ADMIN_USER /
OSAC_KEYCLOAK_ADMIN_PASSWORD) to create a short-lived service-account
client that all subsequent steps use for Keycloak admin operations.

Output JSON:
{
    "success": true,
    "platform": "control_plane",
    "admin_client_id": "isv-admin-<hex>",
    "admin_client_secret": "<secret>",
    "admin_client_uuid": "<uuid>"
}
"""

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import bootstrap_admin_client  # noqa: E402

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    result: dict[str, Any] = {"success": False, "platform": "control_plane"}

    if DEMO_MODE:
        result["admin_client_id"] = "demo-isv-admin"
        result["admin_client_secret"] = "demo-admin-secret"
        result["admin_client_uuid"] = "demo-uuid"
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    keycloak_url = os.environ.get("OSAC_KEYCLOAK_URL", "").rstrip("/")
    realm = os.environ.get("OSAC_KEYCLOAK_REALM", "")
    verify_ssl = os.environ.get("OSAC_VERIFY_SSL", "true").lower() != "false"

    if not keycloak_url or not realm:
        result["error"] = "OSAC_KEYCLOAK_URL and OSAC_KEYCLOAK_REALM are required"
        print(json.dumps(result, indent=2))
        return 1

    client_id = f"isv-admin-{uuid.uuid4().hex[:8]}"

    try:
        info = bootstrap_admin_client(keycloak_url, realm, client_id, verify_ssl)
        result["admin_client_id"] = info["client_id"]
        result["admin_client_secret"] = info["client_secret"]
        result["admin_client_uuid"] = info["client_uuid"]
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
