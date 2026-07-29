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

"""Destroy the OCP test node pool (MachineSet) created by create_node_pool.py.

Deletes the MachineSet and waits for its Machines and Nodes to be removed.
Runs before the cluster teardown so the Machines are freed cleanly.

Environment variables:
  OCP_NODE_POOL_NAME   Pool name suffix (default: isv-test-pool)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

NAMESPACE = "openshift-machine-api"
TRACKING_LABEL_KEY = "isv.ncp.validation/node-pool"


def _kubectl() -> str:
    env = os.environ.get("KUBECTL", "").strip()
    return env if env else "oc"


def _run(cmd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def _infra_id(kc: str) -> str:
    r = _run(f"{kc} get infrastructure cluster -o jsonpath='{{.status.infrastructureName}}'")
    val = r.stdout.strip().strip("'")
    if val:
        return val
    r = _run(f"{kc} get machineset -n {NAMESPACE} -o jsonpath='{{.items[0].metadata.name}}'")
    name = r.stdout.strip().strip("'")
    if name:
        parts = name.split("-worker")
        if parts:
            return parts[0]
    return ""


def main() -> int:
    kc = _kubectl()
    pool_name = os.environ.get("OCP_NODE_POOL_NAME", "isv-test-pool")

    infra = _infra_id(kc)
    ms_name = f"{infra}-{pool_name}" if infra else pool_name

    # Check if MachineSet exists
    r = _run(f"{kc} get machineset {ms_name} -n {NAMESPACE}")
    if r.returncode != 0:
        print(f"MachineSet {ms_name} not found in {NAMESPACE}; nothing to destroy.", file=sys.stderr)
        result = {
            "success": True,
            "platform": "kubernetes",
            "message": "MachineSet absent - nothing to destroy",
            "resources_deleted": [],
        }
        print(json.dumps(result, indent=2))
        return 0

    print(f"\n{'=' * 40}", file=sys.stderr)
    print("  Destroying OCP test node pool", file=sys.stderr)
    print(f"{'=' * 40}", file=sys.stderr)
    print(f"  machineset: {ms_name}\n", file=sys.stderr)

    _run(f"{kc} delete machineset {ms_name} -n {NAMESPACE} --wait=true --timeout=300s")

    # Wait for nodes to drain
    print("Waiting for nodes to be removed...", file=sys.stderr)
    timeout, elapsed = 300, 0
    while elapsed < timeout:
        r = _run(f"{kc} get nodes -l {TRACKING_LABEL_KEY}={pool_name} --no-headers")
        count = len(r.stdout.strip().splitlines()) if r.stdout.strip() else 0
        if count == 0:
            print("All nodes removed.", file=sys.stderr)
            break
        print(f"  Waiting... {count} node(s) remaining ({elapsed}s/{timeout}s)", file=sys.stderr)
        time.sleep(10)
        elapsed += 10

    result = {
        "success": True,
        "platform": "kubernetes",
        "message": "Test node pool destroyed",
        "resources_deleted": [f"machineset/{ms_name}"],
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
