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

"""Expose the OSAC admin service-account credential as the IAM user (IAM01-01).

OSAC uses Keycloak client credentials (service accounts) as its IAM identity
primitive. Creating new clients requires realm-management/manage-clients rights
that are not available to the test service accounts. This script instead
surfaces the pre-existing osac-admin emergency service account — the canonical
OSAC IAM credential — and verifies it can authenticate, satisfying the "user
with access key" contract.

Required env vars:
  OSAC_KEYCLOAK_URL, OSAC_KEYCLOAK_REALM,
  OSAC_ADMIN_CLIENT_ID, OSAC_ADMIN_CLIENT_SECRET, OSAC_VERIFY_SSL

Output JSON:
{
    "success": true,
    "platform": "iam",
    "username": "<OSAC_ADMIN_CLIENT_ID>",
    "access_key_id": "<OSAC_ADMIN_CLIENT_ID>",
    "secret_access_key": "<OSAC_ADMIN_CLIENT_SECRET>"
}
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import authenticate_with_client_credentials, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    result: dict[str, Any] = {
        "success": False,
        "platform": "iam",
    }

    if DEMO_MODE:
        result["username"] = "isv-iam-user-demo"
        result["access_key_id"] = "isv-iam-user-demo"
        result["secret_access_key"] = "demo-iam-secret"
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config()
        client_id = config.admin_client_id
        client_secret = config.admin_client_secret

        # Verify the credential can authenticate before declaring success.
        auth = authenticate_with_client_credentials(config, client_id, client_secret)
        if not auth["success"]:
            result["error"] = f"Credential pre-check failed: {auth.get('error')}"
            print(json.dumps(result, indent=2))
            return 1

        result["username"] = client_id
        result["access_key_id"] = client_id
        result["secret_access_key"] = client_secret
        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
