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

"""Reboot a BareMetalInstance by incrementing restart_trigger (CNP01-05).

Test step for InstanceRebootCheck:
1. GETs the current ``spec.restart_trigger`` value.
2. PATCHes it with +1 to trigger an OS-level restart.
3. Polls ``status.conditions`` for RESTART_IN_PROGRESS=True.
4. Polls ``status.state == RUNNING``.
5. SSH probe; reads ``/proc/uptime`` to confirm the reboot happened.

Emits ``reboot_confirmed: True`` only when the post-reboot uptime is below
the threshold (600 s), providing the affirmative proof required by
``InstanceRebootCheck``.
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
REBOOT_TIMEOUT = 900
SSH_RETRIES = 5
SSH_SLEEP = 10
RESTART_CONFIRMED_UPTIME_MAX = 600  # seconds — confirms a recent boot


def _has_condition(body: dict[str, Any], cond_type: str, expected_status: str = "True") -> bool:
    """Return True when *body* contains a matching ``status.conditions`` entry."""
    for cond in body.get("status", {}).get("conditions", []):
        if cond.get("type") == cond_type and cond.get("status") == expected_status:
            return True
    return False


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


def get_uptime_seconds(key_file: str, external_ip: str) -> float | None:
    """Read /proc/uptime via SSH. Returns uptime float or None on failure."""
    if not key_file or not external_ip:
        return None
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
                "cat /proc/uptime",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return float(proc.stdout.split()[0])
    except Exception:
        pass
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Reboot BareMetalInstance (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    parser.add_argument("--key-file", default="")
    parser.add_argument("--external-ip", default="")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "reboot_instance",
        "instance_id": args.instance_id,
        "reboot_initiated": False,
        "state": "",
        "ssh_ready": False,
        "uptime_seconds": None,
        "reboot_confirmed": False,
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "reboot_initiated": True,
                "state": "running",
                "ssh_ready": True,
                "uptime_seconds": 45.0,
                "reboot_confirmed": True,
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        # Step 1: read current restart_trigger
        status, body = client.get_bare_metal_instance(args.instance_id)
        if status != 200:
            result["error"] = f"GET BareMetalInstance failed (HTTP {status}): {body}"
            print(json.dumps(result, indent=2))
            return 1
        current_trigger = body.get("spec", {}).get("restart_trigger", 0)
        new_trigger = current_trigger + 1

        # Step 2: PATCH restart_trigger
        status, resp = client.update_bare_metal_instance(
            args.instance_id,
            {"spec": {"restart_trigger": new_trigger}},
            ["spec.restart_trigger"],
        )
        if status not in (200, 204):
            result["error"] = f"PATCH restart_trigger failed (HTTP {status}): {resp}"
            print(json.dumps(result, indent=2))
            return 1
        result["reboot_initiated"] = True

        # Step 3: poll for RESTART_IN_PROGRESS condition
        deadline = time.time() + 120
        while time.time() < deadline:
            s, b = client.get_bare_metal_instance(args.instance_id)
            if s == 200 and isinstance(b, dict) and _has_condition(b, "RESTART_IN_PROGRESS"):
                break
            time.sleep(5)

        # Step 4: poll until running
        final_body = client.wait_bare_metal_instance_state(args.instance_id, "running", timeout=REBOOT_TIMEOUT)
        raw_state = final_body.get("status", {}).get("state", "")
        result["state"] = raw_state.lower()

        # Step 5: SSH probe + uptime check
        ssh_ready, _ = ssh_probe(args.key_file, args.external_ip)
        result["ssh_ready"] = ssh_ready

        uptime = None
        if ssh_ready:
            uptime = get_uptime_seconds(args.key_file, args.external_ip)
        result["uptime_seconds"] = uptime

        # reboot_confirmed requires an affirmative True (required by InstanceRebootCheck)
        result["reboot_confirmed"] = bool(ssh_ready and uptime is not None and uptime < RESTART_CONFIRMED_UPTIME_MAX)
        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
