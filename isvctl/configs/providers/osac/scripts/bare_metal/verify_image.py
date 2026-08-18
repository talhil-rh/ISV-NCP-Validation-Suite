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

"""Verify the OS image installed on a BareMetalHost (BOOT01-03).

Test step for BmHostRunsExpectedImageCheck: reads the current
BareMetalInstance state from the fulfillment API and the BareMetalHost
spec.image.url from the cluster CRD, emitting fields consumed by
FieldExistsCheck and InstanceStateCheck.

Usage:
    python3 verify_image.py --instance-id <id> --tenant-namespace <ns>
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

from common.osac_client import FulfillmentClient, create_sa_token, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify image installed on BareMetalHost (OSAC)")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "verify_image",
        "instance_id": args.instance_id,
        "image_id": "",
        "image_name": "",
        "instance_state": "",
        "state": "",
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "image_id": "http://ironic.demo/images/fedora-44.qcow2",
                "image_name": "fedora-44",
                "instance_state": "running",
                "state": "running",
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        # 1. Get instance state from the fulfillment REST API
        status, body = client.get_bare_metal_instance(args.instance_id)
        if status != 200:
            result["error"] = f"GET BareMetalInstance failed (HTTP {status}): {body}"
            print(json.dumps(result, indent=2))
            return 1

        raw_state = body.get("status", {}).get("state", "")
        state = raw_state.lower().removeprefix("bare_metal_instance_state_")
        result["state"] = state
        result["instance_state"] = state

        # 2. Locate the backing BareMetalHost via the BMI CRD (label-based lookup)
        kubectl = shutil.which("kubectl") or shutil.which("oc") or "oc"
        label = f"osac.openshift.io/baremetalinstance-uuid={args.instance_id}"
        r = subprocess.run(
            [
                kubectl,
                "get",
                "baremetalinstance",
                "-n",
                config.tenant_namespace,
                f"-l={label}",
                "-o=jsonpath={.items[0].spec.externalHostID}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        external_host_id = r.stdout.strip() if r.returncode == 0 else ""

        if not external_host_id or "/" not in external_host_id:
            # Host not yet assigned (early provisioning) — report state but no image
            result["success"] = True
            print(json.dumps(result, indent=2))
            return 0

        bmh_ns, bmh_name = external_host_id.split("/", 1)

        # 3. Get the image URL from the BMH spec
        image_url = _oc_get(
            "baremetalhost",
            bmh_name,
            bmh_ns,
            "{.spec.image.url}",
        )

        if image_url:
            result["image_id"] = image_url
            # Strip query string then take the stem: "fedora-44.qcow2" → "fedora-44"
            result["image_name"] = Path(image_url.split("?")[0]).stem

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
