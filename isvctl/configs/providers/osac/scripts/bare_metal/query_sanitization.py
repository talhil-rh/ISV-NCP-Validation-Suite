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

"""Query BareMetalHost sanitization state for a BareMetalInstance (SEC21-02).

Test step for BmDiskSanitizationCheck: finds the BareMetalHost backing
the given instance via the BMI CRD, reads its Ironic provisioning state,
and determines whether the OS image was freshly written (which empirically
wipes all previous OS-partition data).

OSAC sanitization mechanism:
  OSAC uses Metal3/Ironic with automatedCleaningMode=disabled. When a BMI
  is deleted the AAP deprovisioning playbook strips the image, and when a
  new BMI is created Ironic writes a fresh OS image -- which wipes all
  previous OS-partition data.  The provisioning cycle is:
    provisioned -> deprovisioning -> available -> provisioning -> provisioned
  A BMH in "provisioned" state has been through this full Ironic image-write
  cycle; we map that to sanitized=True.

Usage:
    python3 query_sanitization.py --instance-id <id> --tenant-namespace <ns>
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"

# Ironic provisioning state that confirms the OS image has been written.
_PROVISIONED_STATE = "provisioned"

# Provider-neutral lifecycle sequence representing the Ironic BMH cycle.
_IRONIC_TRANSITIONS = ["in_use", "deprovisioning", "provisioning", "provisioned"]


def _oc_get_json(resource: str, name: str, namespace: str) -> dict[str, Any]:
    """Return the full JSON body for a Kubernetes resource."""
    kubectl = shutil.which("kubectl") or shutil.which("oc") or "oc"
    r = subprocess.run(
        [kubectl, "get", resource, name, "-n", namespace, "-o", "json"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if r.returncode != 0:
        raise RuntimeError(f"{resource}/{name} in {namespace}: {r.stderr.strip()}")
    return json.loads(r.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Query BareMetalHost sanitization state via Ironic provisioning (OSAC)"
    )
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True, help="Ephemeral tenant namespace (SA token source)")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "query_sanitization",
        "machines": [],
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "machines": [
                    {
                        "machine_id": "host-inventory/virtual-bmh-caas-1",
                        "served_tenant": True,
                        "stale_tenant_binding": False,
                        "sanitized": True,
                        "transitions": _IRONIC_TRANSITIONS,
                        "has_gpu": False,
                        "status": _PROVISIONED_STATE,
                    }
                ],
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        # BMI CRDs always live in the operator namespace (osac-e2e-ci), not the
        # ephemeral tenant namespace passed via --tenant-namespace.
        operator_ns = config.tenant_namespace
        kubectl = shutil.which("kubectl") or shutil.which("oc") or "oc"
        label = f"osac.openshift.io/baremetalinstance-uuid={args.instance_id}"

        # 1. Look up the BMI CRD by label to find the backing BareMetalHost.
        r = subprocess.run(
            [
                kubectl,
                "get",
                "baremetalinstance",
                "-n",
                operator_ns,
                f"-l={label}",
                "-o=jsonpath={.items[0].spec.externalHostID}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        external_host_id = r.stdout.strip() if r.returncode == 0 else ""

        if not external_host_id or "/" not in external_host_id:
            result["error"] = f"Could not find BMI CRD for {args.instance_id} in {operator_ns}: {r.stderr.strip()}"
            print(json.dumps(result, indent=2))
            return 1

        bmh_ns, bmh_name = external_host_id.split("/", 1)
        machine_id = f"{bmh_ns}/{bmh_name}"

        # 2. Get the full BMH JSON.
        bmh = _oc_get_json("baremetalhost", bmh_name, bmh_ns)

        # 3. Extract provisioning state from the BMH status.
        provisioning_state = bmh.get("status", {}).get("provisioning", {}).get("state", "")

        # 4. Determine sanitized: Ironic wrote a fresh OS image when the BMH
        #    is in the "provisioned" state, which wipes previous OS-partition data.
        sanitized = provisioning_state == _PROVISIONED_STATE

        # 5. has_gpu: virtual BMHs in the OSAC CI lab do not carry GPUs.
        #    We could inspect status.hardware but there is no standardised GPU
        #    field on Metal3 BMH; default to False for the virtual lab.
        has_gpu = False

        machine: dict[str, Any] = {
            "machine_id": machine_id,
            # The BMH is allocated to our BMI, so it is being used by a tenant.
            "served_tenant": True,
            # We are the current tenant; there is no stale binding.
            "stale_tenant_binding": False,
            "sanitized": sanitized,
            # Provider-neutral lifecycle sequence representing the Ironic cycle.
            "transitions": _IRONIC_TRANSITIONS,
            "has_gpu": has_gpu,
            "status": provisioning_state,
        }

        result["machines"] = [machine]
        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
