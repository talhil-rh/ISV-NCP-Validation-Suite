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

"""VPC (VirtualNetwork) CRUD lifecycle test for OSAC (SDN01-01..04).

Self-contained: create → read → update labels → delete a temporary VNet.
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
    parser = argparse.ArgumentParser(description="VPC CRUD test (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "vpc_crud",
        "tests": {
            "create_vpc": {"passed": False},
            "read_vpc": {"passed": False},
            "update_tags": {"passed": False},
            "update_dns": {"passed": False},
            "delete_vpc": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["tests"] = {
            "create_vpc": {"passed": True, "vpc_id": "isv-crud-demo"},
            "read_vpc": {"passed": True, "attributes": {"cidr": "10.201.0.0/16"}},
            "update_tags": {"passed": True},
            "update_dns": {
                "passed": True,
                "message": "OSAC VNets do not have DNS settings",
            },
            "delete_vpc": {"passed": True},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    vnet_id = ""
    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        suffix = f"{int(time.time()) % 0xFFFF:04x}"
        vnet_name = f"isv-crud-{suffix}"
        cidr = "10.201.0.0/16"

        # CREATE
        status, body = client.create_virtual_network(vnet_name, ipv4_cidr=cidr)
        if status not in (200, 201):
            result["tests"]["create_vpc"]["error"] = f"HTTP {status}: {body}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_id = body["id"]

        crd_ns = config.tenant_namespace
        wait_crd_ready("virtualnetwork", vnet_id, crd_ns, label="osac.openshift.io/virtualnetwork-uuid")
        result["tests"]["create_vpc"] = {"passed": True, "vpc_id": vnet_id}

        # READ
        status, body = client.get_virtual_network(vnet_id)
        if status == 200:
            attrs = {"cidr": body.get("spec", {}).get("ipv4_cidr", "")}
            result["tests"]["read_vpc"] = {"passed": True, "attributes": attrs}
        else:
            result["tests"]["read_vpc"]["error"] = f"HTTP {status}: {body}"

        # UPDATE (labels)
        status, body = client.update_virtual_network(
            vnet_id,
            "metadata.labels",
            {"metadata": {"labels": {"isv-test": "true"}}, "spec": {"ipv4_cidr": cidr}},
        )
        if status == 200:
            result["tests"]["update_tags"] = {"passed": True}
        else:
            result["tests"]["update_tags"]["error"] = f"HTTP {status}: {body}"

        # UPDATE DNS — OSAC VNets have no DNS toggle
        result["tests"]["update_dns"] = {
            "passed": True,
            "message": "OSAC VNets do not have DNS settings",
        }

        # DELETE
        status, body = client.delete_virtual_network(vnet_id)
        if status in (200, 204):
            result["tests"]["delete_vpc"] = {"passed": True}
            vnet_id = ""
        else:
            result["tests"]["delete_vpc"]["error"] = f"HTTP {status}: {body}"

        result["success"] = all(t.get("passed") for t in result["tests"].values())

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
    finally:
        if vnet_id:
            try:
                cleanup_token, _ttl = create_sa_token(args.tenant_namespace, "default")
                FulfillmentClient(config, cleanup_token).delete_virtual_network(vnet_id)
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
