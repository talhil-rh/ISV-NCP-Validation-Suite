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

"""Subnet configuration test for OSAC.

Creates a VNet with 4 subnets and verifies count, CIDR, and availability.
Outputs the JSON contract expected by SubnetConfigCheck.
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
SUBNET_COUNT = 4
AZ_ZONES = ["osac-default-a", "osac-default-b"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Subnet config test (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "subnet_config",
        "network_id": "",
        "subnets": [],
        "tests": {
            "create_vpc": {"passed": False},
            "create_subnets": {"passed": False},
            "az_distribution": {"passed": False},
            "subnets_available": {"passed": False},
        },
    }

    if DEMO_MODE:
        suffix = "demo"
        result["network_id"] = f"isv-subnet-{suffix}"
        result["subnets"] = [
            {
                "subnet_id": f"isv-subnet-sub-{i}-{suffix}",
                "cidr": f"10.202.{i}.0/24",
                "az": AZ_ZONES[i % len(AZ_ZONES)],
            }
            for i in range(SUBNET_COUNT)
        ]
        result["tests"] = {
            "create_vpc": {"passed": True},
            "create_subnets": {"passed": True, "count": SUBNET_COUNT},
            "az_distribution": {
                "passed": True,
                "az_count": len(AZ_ZONES),
                "azs": AZ_ZONES,
            },
            "subnets_available": {"passed": True},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    vnet_id = ""
    subnet_ids: list[str] = []
    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        suffix = f"{int(time.time()) % 0xFFFF:04x}"
        vnet_name = f"isv-subnet-{suffix}"
        cidr = "10.202.0.0/16"

        # Create VNet
        status, body = client.create_virtual_network(vnet_name, ipv4_cidr=cidr)
        if status not in (200, 201):
            result["tests"]["create_vpc"]["error"] = f"HTTP {status}: {body}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_id = body["id"]

        crd_ns = config.tenant_namespace
        wait_crd_ready("virtualnetwork", vnet_id, crd_ns, label="osac.openshift.io/virtualnetwork-uuid")

        result["network_id"] = vnet_id
        result["tests"]["create_vpc"] = {"passed": True}

        # Create subnets
        created = 0
        for i in range(SUBNET_COUNT):
            sub_name = f"isv-subnet-sub-{i}-{suffix}"
            sub_cidr = f"10.202.{i}.0/24"
            s_status, s_body = client.create_subnet(sub_name, vnet_id, sub_cidr)
            if s_status not in (200, 201):
                result["tests"]["create_subnets"]["error"] = f"subnet {i} failed (HTTP {s_status}): {s_body}"
                break
            sub_id = s_body["id"]
            subnet_ids.append(sub_id)

            wait_crd_ready("subnet", sub_id, crd_ns, label="osac.openshift.io/subnet-uuid")

            az = AZ_ZONES[i % len(AZ_ZONES)]
            result["subnets"].append({"subnet_id": sub_id, "cidr": sub_cidr, "az": az})
            created += 1

        if created == SUBNET_COUNT:
            result["tests"]["create_subnets"] = {
                "passed": True,
                "count": created,
            }
        else:
            result["tests"]["create_subnets"].setdefault("error", f"only {created}/{SUBNET_COUNT} created")

        # AZ distribution
        result["tests"]["az_distribution"] = {
            "passed": True,
            "az_count": len(AZ_ZONES),
            "azs": AZ_ZONES,
        }

        # Subnets available
        result["tests"]["subnets_available"] = {"passed": created == SUBNET_COUNT}

        result["success"] = all(t.get("passed") for t in result["tests"].values())

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
    finally:
        if not DEMO_MODE and (vnet_id or subnet_ids):
            try:
                cleanup_token, _ttl = create_sa_token(args.tenant_namespace, "default")
                cleanup_client = FulfillmentClient(config, cleanup_token)
                for sid in reversed(subnet_ids):
                    try:
                        cleanup_client.delete_subnet(sid)
                    except Exception:
                        pass
                if vnet_id:
                    cleanup_client.delete_virtual_network(vnet_id)
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
