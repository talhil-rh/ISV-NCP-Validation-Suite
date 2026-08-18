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

"""Query BareMetalHost topology labels for a BareMetalInstance (CNP01-04).

Test step for BmTopologyPlacementCheck: finds the BareMetalHost backing
the given instance via the BMI CRD, reads its Kubernetes topology labels,
and determines whether the platform supports topology-aware placement.

Checks for:
  - topology.kubernetes.io/zone
  - topology.kubernetes.io/region
  - osac.openshift.io/rack
  - osac.openshift.io/host-type  (fallback for AZ; sets strategy=host-type-aware)

Usage:
    python3 topology_placement.py --instance-id <id> [--tenant-namespace <ns>]
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

_TOPOLOGY_LABELS = (
    "topology.kubernetes.io/zone",
    "topology.kubernetes.io/region",
    "osac.openshift.io/rack",
    "osac.openshift.io/host-type",
)


def _oc_get(resource: str, name: str, namespace: str, jsonpath: str) -> str:
    kubectl = shutil.which("kubectl") or shutil.which("oc") or "oc"
    r = subprocess.run(
        [kubectl, "get", resource, name, "-n", namespace, f"-o=jsonpath={jsonpath}"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if r.returncode != 0:
        raise RuntimeError(f"{resource}/{name}: {r.stderr.strip()}")
    return r.stdout.strip()


def _get_bmh_labels(bmh_name: str, bmh_ns: str) -> dict[str, str]:
    """Return all labels from a BareMetalHost CRD as a plain dict."""
    kubectl = shutil.which("kubectl") or shutil.which("oc") or "oc"
    r = subprocess.run(
        [kubectl, "get", "baremetalhost", bmh_name, "-n", bmh_ns, "-o=json"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if r.returncode != 0:
        raise RuntimeError(f"baremetalhost/{bmh_name}: {r.stderr.strip()}")
    body = json.loads(r.stdout)
    return body.get("metadata", {}).get("labels", {})


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify BareMetalHost topology placement (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", default="", help="Override operator namespace for CRD lookup")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "topology_placement",
        "instance_id": args.instance_id,
        "placement_supported": False,
        "availability_zone": "",
        "placement_strategy": "",
        "operations": {},
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "placement_supported": True,
                "availability_zone": "rack-1",
                "placement_strategy": "host-type-aware",
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

        # 1. Look up the BMI CRD by label to find the backing BareMetalHost
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

        # 2. Read all labels from the backing BareMetalHost
        labels = _get_bmh_labels(bmh_name, bmh_ns)

        # 3. Determine the availability zone value (first matching label wins)
        az = (
            labels.get("topology.kubernetes.io/zone")
            or labels.get("topology.kubernetes.io/region")
            or labels.get("osac.openshift.io/rack")
            or labels.get("osac.openshift.io/host-type")
            or ""
        )

        # 4. Determine placement strategy
        has_host_type = "osac.openshift.io/host-type" in labels
        strategy = "host-type-aware" if has_host_type else "label-based"

        # 5. Placement is supported when any topology label is present
        placement_supported = bool(any(k in labels for k in _TOPOLOGY_LABELS))

        result.update(
            {
                "success": True,
                "placement_supported": placement_supported,
                "availability_zone": az,
                "placement_strategy": strategy,
            }
        )

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
