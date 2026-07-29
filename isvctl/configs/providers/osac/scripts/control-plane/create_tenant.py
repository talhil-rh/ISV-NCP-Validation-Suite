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

"""Create OSAC Tenant CRD.

Output JSON:
{
    "success": true,
    "platform": "control_plane",
    "tenant_name": "isv-tenant-test-a1b2c3d4",
    "tenant_id": "<uid>"
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

from common.osac_client import TenantClient, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--name-prefix", default="isv-tenant-test")
    args = parser.parse_args()

    tenant_name = f"{args.name_prefix}-{uuid.uuid4().hex[:8]}"

    result: dict[str, Any] = {
        "success": False,
        "platform": "control_plane",
        "tenant_name": tenant_name,
    }

    if DEMO_MODE:
        result["tenant_id"] = tenant_name
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        client = TenantClient(config)

        resp = client.create(tenant_name)
        metadata = resp.get("metadata", {})
        result["tenant_id"] = metadata.get("uid", metadata.get("name", tenant_name))
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
