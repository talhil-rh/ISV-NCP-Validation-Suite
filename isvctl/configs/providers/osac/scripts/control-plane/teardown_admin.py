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

"""Delete the ephemeral admin client created by bootstrap_admin.py.

Output JSON:
{
    "success": true,
    "platform": "control_plane",
    "deleted_client": "isv-admin-<hex>"
}
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import cleanup_admin_client

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-client-id", required=True)
    parser.add_argument("--admin-client-uuid", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {"success": False, "platform": "control_plane"}

    if DEMO_MODE:
        result["deleted_client"] = args.admin_client_id
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    keycloak_url = os.environ.get("OSAC_KEYCLOAK_URL", "").rstrip("/")
    realm = os.environ.get("OSAC_KEYCLOAK_REALM", "")
    verify_ssl = os.environ.get("OSAC_VERIFY_SSL", "true").lower() != "false"

    try:
        cleanup_admin_client(keycloak_url, realm, args.admin_client_uuid, verify_ssl)
        result["deleted_client"] = args.admin_client_id
        result["success"] = True
    except Exception as e:
        # Best-effort teardown — don't fail the run
        result["deleted_client"] = args.admin_client_id
        result["success"] = True
        result["warning"] = str(e)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
