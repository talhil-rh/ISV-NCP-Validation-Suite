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

"""Read metadata labels from a BareMetalInstance (CNP05-01).

Test step for InstanceTagCheck: GETs the BMI and emits its
``metadata.labels`` as ``tags`` for the validation to inspect.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import FulfillmentClient, create_sa_token, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify BareMetalInstance tags (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "verify_tags",
        "instance_id": args.instance_id,
        "tags": {},
        "tag_count": 0,
    }

    if DEMO_MODE:
        tags = {"Name": "osac-bm-validation", "CreatedBy": "isv-validation"}
        result.update(
            {
                "success": True,
                "tags": tags,
                "tag_count": len(tags),
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        status, body = client.get_bare_metal_instance(args.instance_id)
        if status != 200:
            result["error"] = f"GET BareMetalInstance failed (HTTP {status}): {body}"
            print(json.dumps(result, indent=2))
            return 1

        tags: dict[str, str] = body.get("metadata", {}).get("labels", {})
        result.update(
            {
                "success": True,
                "tags": tags,
                "tag_count": len(tags),
            }
        )

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
