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

"""SecurityGroup CRUD lifecycle test for OSAC (SDN02-01..04).

Self-contained: create VNet → create SG → read → update rules (add, modify,
remove) → delete SG → verify deleted. Cleanup: delete VNet.
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
    parser = argparse.ArgumentParser(description="SG CRUD test (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "sg_crud",
        "tests": {
            "create_vpc": {"passed": False},
            "create_sg": {"passed": False},
            "read_sg": {"passed": False},
            "update_sg_add_rule": {"passed": False},
            "update_sg_modify_rule": {"passed": False},
            "update_sg_remove_rule": {"passed": False},
            "delete_sg": {"passed": False},
            "verify_deleted": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["tests"] = {
            "create_vpc": {"passed": True},
            "create_sg": {"passed": True, "sg_id": "isv-sg-demo"},
            "read_sg": {"passed": True, "name": "isv-sg-demo"},
            "update_sg_add_rule": {"passed": True},
            "update_sg_modify_rule": {"passed": True},
            "update_sg_remove_rule": {"passed": True},
            "delete_sg": {"passed": True},
            "verify_deleted": {"passed": True},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    vnet_id = ""
    sg_id = ""
    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        suffix = f"{int(time.time()) % 0xFFFF:04x}"

        # Create VNet
        vnet_name = f"isv-sg-vnet-{suffix}"
        s, b = client.create_virtual_network(vnet_name, ipv4_cidr="10.205.0.0/16")
        if s not in (200, 201):
            result["tests"]["create_vpc"]["error"] = f"HTTP {s}: {b}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_id = b["id"]

        crd_ns = config.tenant_namespace
        wait_crd_ready("virtualnetwork", vnet_id, crd_ns, label="osac.openshift.io/virtualnetwork-uuid")
        result["tests"]["create_vpc"] = {"passed": True}

        # CREATE SG (empty rules)
        sg_name = f"isv-sg-{suffix}"
        s, b = client.create_security_group(sg_name, vnet_id)
        if s not in (200, 201):
            result["tests"]["create_sg"]["error"] = f"HTTP {s}: {b}"
            print(json.dumps(result, indent=2))
            return 1
        sg_id = b["id"]

        wait_crd_ready("securitygroup", sg_id, crd_ns, label="osac.openshift.io/securitygroup-uuid")
        result["tests"]["create_sg"] = {"passed": True, "sg_id": sg_id}

        # READ SG
        s, b = client.get_security_group(sg_id)
        if s == 200:
            name = b.get("metadata", {}).get("name", "")
            result["tests"]["read_sg"] = {"passed": True, "name": name}
        else:
            result["tests"]["read_sg"]["error"] = f"HTTP {s}: {b}"

        # UPDATE: add TCP 443 ingress rule
        s, b = client.update_security_group(
            sg_id,
            "spec.ingress",
            {
                "spec": {
                    "virtual_network": {"id": vnet_id},
                    "ingress": [
                        {
                            "protocol": "PROTOCOL_TCP",
                            "port_from": 443,
                            "port_to": 443,
                            "ipv4_cidr": "0.0.0.0/0",
                        }
                    ],
                }
            },
        )
        if s == 200:
            result["tests"]["update_sg_add_rule"] = {"passed": True}
        else:
            result["tests"]["update_sg_add_rule"]["error"] = f"HTTP {s}: {b}"

        # UPDATE: modify rule to TCP 8443
        s, b = client.update_security_group(
            sg_id,
            "spec.ingress",
            {
                "spec": {
                    "virtual_network": {"id": vnet_id},
                    "ingress": [
                        {
                            "protocol": "PROTOCOL_TCP",
                            "port_from": 8443,
                            "port_to": 8443,
                            "ipv4_cidr": "0.0.0.0/0",
                        }
                    ],
                }
            },
        )
        if s == 200:
            result["tests"]["update_sg_modify_rule"] = {"passed": True}
        else:
            result["tests"]["update_sg_modify_rule"]["error"] = f"HTTP {s}: {b}"

        # UPDATE: remove all ingress rules
        s, b = client.update_security_group(
            sg_id,
            "spec.ingress",
            {"spec": {"virtual_network": {"id": vnet_id}, "ingress": []}},
        )
        if s == 200:
            result["tests"]["update_sg_remove_rule"] = {"passed": True}
        else:
            result["tests"]["update_sg_remove_rule"]["error"] = f"HTTP {s}: {b}"

        # DELETE SG
        s, b = client.delete_security_group(sg_id)
        if s in (200, 204):
            result["tests"]["delete_sg"] = {"passed": True}
        else:
            result["tests"]["delete_sg"]["error"] = f"HTTP {s}: {b}"

        # VERIFY DELETED — deletion is async; poll until 404
        deadline = time.time() + 120
        while time.time() < deadline:
            s, b = client.get_security_group(sg_id)
            if s in (404, 410):
                break
            time.sleep(5)
        if s in (404, 410):
            result["tests"]["verify_deleted"] = {"passed": True}
            sg_id = ""
        else:
            result["tests"]["verify_deleted"]["error"] = f"Expected 404 but got HTTP {s}"

        result["success"] = all(t.get("passed") for t in result["tests"].values())

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
    finally:
        try:
            cleanup_token, _ttl = create_sa_token(args.tenant_namespace, "default")
            cleanup_client = FulfillmentClient(config, cleanup_token)
            if sg_id:
                try:
                    cleanup_client.delete_security_group(sg_id)
                except Exception:
                    pass
            if vnet_id:
                try:
                    cleanup_client.delete_virtual_network(vnet_id)
                except Exception:
                    pass
        except Exception:
            pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
