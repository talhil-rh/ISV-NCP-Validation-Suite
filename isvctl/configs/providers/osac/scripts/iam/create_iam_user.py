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

"""Create an ephemeral Keycloak client to act as an IAM user (IAM01-01).

Uses the permanent OSAC admin client credentials from the environment to create
a new service-account-enabled Keycloak client. The client id/secret are the
OSAC equivalent of an IAM user access key pair.

Output JSON:
{
    "success": true,
    "platform": "iam",
    "username": "isv-iam-user-<hex>",
    "access_key_id": "isv-iam-user-<hex>",
    "secret_access_key": "<client-secret>",
    "client_uuid": "<keycloak-internal-uuid>"
}
"""

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import KeycloakAdmin, get_admin_token, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    client_id = f"isv-iam-user-{uuid.uuid4().hex[:8]}"

    result: dict[str, Any] = {
        "success": False,
        "platform": "iam",
        "username": client_id,
        "access_key_id": client_id,
    }

    if DEMO_MODE:
        result["secret_access_key"] = "demo-iam-secret"
        result["client_uuid"] = "demo-uuid-0000-0000-0000-000000000000"
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config()
        token = get_admin_token(config)
        admin = KeycloakAdmin(config, token)

        client_rep = admin.create_client(client_id)
        client_uuid = client_rep["id"]
        secret = admin.get_client_secret(client_uuid)

        result["secret_access_key"] = secret
        result["client_uuid"] = client_uuid
        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
