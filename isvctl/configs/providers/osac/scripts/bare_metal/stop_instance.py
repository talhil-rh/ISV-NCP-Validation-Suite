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

"""Stop a BareMetalInstance by setting run_strategy to HALTED (CNP01-07).

Test step for InstanceStopCheck: PATCHes ``spec.run_strategy`` to HALTED
and polls until ``status.state == STOPPED``.
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
RUN_STRATEGY_HALTED = "BARE_METAL_INSTANCE_RUN_STRATEGY_HALTED"
STOP_TIMEOUT = 600


def main() -> int:
    parser = argparse.ArgumentParser(description="Stop BareMetalInstance (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "stop_instance",
        "instance_id": args.instance_id,
        "stop_initiated": False,
        "state": "",
    }

    if DEMO_MODE:
        result.update({"success": True, "stop_initiated": True, "state": "stopped"})
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        status, resp = client.update_bare_metal_instance(
            args.instance_id,
            {"spec": {"run_strategy": RUN_STRATEGY_HALTED}},
            ["spec.run_strategy"],
        )
        if status not in (200, 204):
            result["error"] = f"PATCH run_strategy=HALTED failed (HTTP {status}): {resp}"
            print(json.dumps(result, indent=2))
            return 1
        result["stop_initiated"] = True

        final_body = client.wait_bare_metal_instance_state(args.instance_id, "stopped", timeout=STOP_TIMEOUT)
        raw_state = final_body.get("status", {}).get("state", "")
        result["state"] = raw_state.lower()
        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
