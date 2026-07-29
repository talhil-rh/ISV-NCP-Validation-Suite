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

"""Test service account long-lived credential authentication via Keycloak.

Creates a temporary Keycloak client (service account), authenticates with
its client credentials, and reports the result. The temporary client is
cleaned up regardless of outcome.

Covers SEC03-01: service account long-lived credential auth.

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "sa_credential_test",
    "authenticated": true,
    "credential_type": "client_credentials",
    "identity": "<jwt-sub>",
    "expires_at": null
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

from common.osac_client import (
    KeycloakAdmin,
    authenticate_with_client_credentials,
    get_admin_token,
    get_env_config,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser(description="SA credential test (OSAC/Keycloak)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "sa_credential_test",
        "authenticated": False,
        "credential_type": "",
        "identity": "",
        "expires_at": None,
    }

    if DEMO_MODE:
        result["authenticated"] = True
        result["credential_type"] = "client_credentials"
        result["identity"] = "demo-sa-osac-12345"
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    test_client_id = f"isv-sa-cred-test-{uuid.uuid4().hex[:8]}"
    client_uuid = ""

    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
        )
        token = get_admin_token(config)
        admin = KeycloakAdmin(config, token)

        # Create a temporary service-account client
        client_rep = admin.create_client(test_client_id)
        client_uuid = client_rep["id"]
        secret = admin.get_client_secret(client_uuid)

        # Authenticate with the SA's own credentials
        auth_result = authenticate_with_client_credentials(config, test_client_id, secret)

        if auth_result["success"]:
            result["authenticated"] = True
            result["credential_type"] = "client_credentials"
            result["identity"] = auth_result["sub"]
            result["success"] = True
        else:
            result["error"] = auth_result.get("error", "Authentication failed")

    except Exception as e:
        result["error"] = str(e)
    finally:
        # Best-effort cleanup of the temporary client
        if client_uuid:
            try:
                admin.delete_client(client_uuid)
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
