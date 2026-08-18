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

"""Create a VirtualNetwork and subnets for OSAC network validation.

Setup step: creates a shared VNet with two subnets for subsequent tests.
Outputs the JSON contract expected by NetworkProvisionedCheck.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import FulfillmentClient, create_sa_token, get_env_config, wait_crd_ready

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create VNet + subnets (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    parser.add_argument("--network-class", default="")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "network_id": "",
        "cidr": "10.200.0.0/16",
        "subnets": [],
    }

    if DEMO_MODE:
        suffix = "demo"
        result["network_id"] = f"isv-net-{suffix}"
        result["subnets"] = [
            {"subnet_id": f"isv-net-sub-0-{suffix}", "cidr": "10.200.0.0/24"},
            {"subnet_id": f"isv-net-sub-1-{suffix}", "cidr": "10.200.1.0/24"},
        ]
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    vnet_id = ""
    subnet_ids: list[str] = []
    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        network_class = args.network_class
        if not network_class:
            nc_status, nc_body = client.list_network_classes()
            if nc_status == 200:
                items = nc_body.get("items", [])
                for nc in items:
                    if nc.get("is_default"):
                        network_class = nc.get("id", "")
                        break
                if not network_class and items:
                    network_class = items[0].get("id", "")

        suffix = f"{int(time.time()) % 0xFFFF:04x}"
        vnet_name = f"isv-net-{suffix}"
        cidr = "10.200.0.0/16"

        status, body = client.create_virtual_network(vnet_name, network_class=network_class, ipv4_cidr=cidr)
        if status not in (200, 201):
            result["error"] = f"create VNet failed (HTTP {status}): {body}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_id = body["id"]

        crd_ns = config.tenant_namespace
        # The fulfillment-controller auto-creates the VirtualNetwork CRD when the
        # REST resource is created; wait for the operator to reconcile it to Ready.
        wait_crd_ready("virtualnetwork", vnet_id, crd_ns, label="osac.openshift.io/virtualnetwork-uuid", timeout=300)

        # The fulfillment service VNet state is updated asynchronously by the
        # feedback controller after the K8s CRD reaches Ready. Poll until the
        # fulfillment service confirms READY before creating subnets.
        vnet_deadline = time.time() + 120
        while time.time() < vnet_deadline:
            vnet_status, vnet_body = client.get_virtual_network(vnet_name)
            if vnet_status == 200:
                vnet_state = vnet_body.get("status", {}).get("state", "")
                if vnet_state == "VIRTUAL_NETWORK_STATE_READY":
                    break
            time.sleep(5)

        result["network_id"] = vnet_id
        result["cidr"] = cidr

        for i in range(2):
            sub_name = f"isv-net-sub-{i}-{suffix}"
            sub_cidr = f"10.200.{i}.0/24"
            s_status, s_body = client.create_subnet(sub_name, vnet_id, sub_cidr)
            if s_status not in (200, 201):
                result["error"] = f"create subnet {i} failed (HTTP {s_status}): {s_body}"
                print(json.dumps(result, indent=2))
                return 1
            sub_id = s_body["id"]
            # The fulfillment-controller auto-creates the Subnet CRD; wait for Ready.
            wait_crd_ready("subnet", sub_id, crd_ns, label="osac.openshift.io/subnet-uuid")
            subnet_ids.append(sub_id)
            result["subnets"].append({"subnet_id": sub_id, "cidr": sub_cidr})

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
