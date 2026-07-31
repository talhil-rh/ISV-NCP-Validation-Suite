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

"""Start a stopped BareMetalInstance by setting run_strategy to ALWAYS (CNP01-08).

Test step for InstanceStartCheck: PATCHes ``spec.run_strategy`` to ALWAYS,
polls until ``status.state == RUNNING``, then probes SSH connectivity to
confirm the OS is accessible.
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
START_TIMEOUT = 900
SSH_RETRIES = 5
SSH_SLEEP = 10


def ssh_probe(key_file: str, external_ip: str) -> tuple[bool, str]:
    """Attempt SSH connectivity. Returns (success, message)."""
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
                    f"fedora@{external_ip}",
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
    parser = argparse.ArgumentParser(description="Start BareMetalInstance (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    parser.add_argument("--key-file", default="", help="Path to SSH private key")
    parser.add_argument("--external-ip", default="", help="External IP for SSH probe")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "start_instance",
        "instance_id": args.instance_id,
        "start_initiated": False,
        "state": "",
        "ssh_ready": False,
    }

    if DEMO_MODE:
        result.update({"success": True, "start_initiated": True, "state": "running", "ssh_ready": True})
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        status, resp = client.update_bare_metal_instance(
            args.instance_id,
            {"spec": {"run_strategy": RUN_STRATEGY_ALWAYS}},
            ["spec.run_strategy"],
        )
        if status not in (200, 204):
            result["error"] = f"PATCH run_strategy=ALWAYS failed (HTTP {status}): {resp}"
            print(json.dumps(result, indent=2))
            return 1
        result["start_initiated"] = True

        final_body = client.wait_bare_metal_instance_state(args.instance_id, "running", timeout=START_TIMEOUT)
        raw_state = final_body.get("status", {}).get("state", "")
        result["state"] = raw_state.lower().removeprefix("bare_metal_instance_state_")

        ssh_ready, ssh_msg = ssh_probe(args.key_file, args.external_ip)
        result["ssh_ready"] = ssh_ready
        if not ssh_ready:
            result["ssh_note"] = ssh_msg

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
