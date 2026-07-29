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

"""Delete the ephemeral IAM user Keycloak client created by create_iam_user.py.

Best-effort: logs a warning on failure but always exits 0 so teardown does
not block the test run result.

Output JSON:
{
    "success": true,
    "platform": "iam",
    "deleted_client_uuid": "<uuid>"
}
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import KeycloakAdmin, get_admin_token, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-uuid", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "iam",
        "deleted_client_uuid": args.client_uuid,
    }

    if DEMO_MODE:
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config()
        token = get_admin_token(config)
        admin = KeycloakAdmin(config, token)
        admin.delete_client(args.client_uuid)
        result["success"] = True
    except Exception as exc:
        # Best-effort teardown — report warning but succeed
        result["success"] = True
        result["warning"] = str(exc)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
