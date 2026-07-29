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

"""Power-cycle a BareMetalInstance (CNP01-06).

Test step for InstancePowerCycleCheck: performs a hard power-off followed
by a power-on and verifies the instance recovers to RUNNING with SSH.

Sequence:
1. PATCH run_strategy=HALTED → poll state==stopped (power off confirmed)
2. PATCH run_strategy=ALWAYS → poll state==running (power on confirmed)
3. SSH probe; record recovery_seconds (t_start to SSH ready)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import FulfillmentClient, create_sa_token, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
RUN_STRATEGY_ALWAYS = "BARE_METAL_INSTANCE_RUN_STRATEGY_ALWAYS"
RUN_STRATEGY_HALTED = "BARE_METAL_INSTANCE_RUN_STRATEGY_HALTED"
STOP_TIMEOUT = 600
START_TIMEOUT = 900
SSH_RETRIES = 5
SSH_SLEEP = 10


def ssh_probe(key_file: str, external_ip: str) -> tuple[bool, str]:
    """SSH connectivity probe. Returns (success, message)."""
    if not key_file or not external_ip:
        return False, "No key_file or external_ip — skipping SSH probe"
    for attempt in range(SSH_RETRIES):
        try:
            proc = subprocess.run(
                [
                    "ssh",
                    "-i",
                    key_file,
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "BatchMode=yes",
                    f"root@{external_ip}",
                    "echo ok",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode == 0 and "ok" in proc.stdout:
                return True, "SSH connected successfully"
        except Exception:
            pass
        if attempt < SSH_RETRIES - 1:
            time.sleep(SSH_SLEEP)
    return False, f"SSH not available after {SSH_RETRIES} attempts"


def main() -> int:
    parser = argparse.ArgumentParser(description="Power-cycle BareMetalInstance (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    parser.add_argument("--key-file", default="")
    parser.add_argument("--external-ip", default="")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "power_cycle_instance",
        "instance_id": args.instance_id,
        "power_cycle_initiated": False,
        "power_was_off": False,
        "state": "",
        "ssh_ready": False,
        "recovery_seconds": None,
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "power_cycle_initiated": True,
                "power_was_off": True,
                "state": "running",
                "ssh_ready": True,
                "recovery_seconds": 180,
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        t_start = time.time()

        # Step 1: Power off (HALTED)
        status, resp = client.update_bare_metal_instance(
            args.instance_id,
            {"spec": {"run_strategy": RUN_STRATEGY_HALTED}},
            ["spec.run_strategy"],
        )
        if status not in (200, 204):
            result["error"] = f"PATCH run_strategy=HALTED failed (HTTP {status}): {resp}"
            print(json.dumps(result, indent=2))
            return 1
        result["power_cycle_initiated"] = True

        client.wait_bare_metal_instance_state(args.instance_id, "stopped", timeout=STOP_TIMEOUT)
        result["power_was_off"] = True

        # Step 2: Power on (ALWAYS)
        status, resp = client.update_bare_metal_instance(
            args.instance_id,
            {"spec": {"run_strategy": RUN_STRATEGY_ALWAYS}},
            ["spec.run_strategy"],
        )
        if status not in (200, 204):
            result["error"] = f"PATCH run_strategy=ALWAYS failed (HTTP {status}): {resp}"
            print(json.dumps(result, indent=2))
            return 1

        final_body = client.wait_bare_metal_instance_state(args.instance_id, "running", timeout=START_TIMEOUT)
        raw_state = final_body.get("status", {}).get("state", "")
        result["state"] = raw_state.lower()

        # Step 3: SSH probe
        ssh_ready, _ = ssh_probe(args.key_file, args.external_ip)
        result["ssh_ready"] = ssh_ready
        result["recovery_seconds"] = round(time.time() - t_start, 1)
        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
