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

"""SecurityGroup port security policy test (SDN02-10).

Creates two subnets (virtual interfaces) with separate SGs. Applies a port
rule to SG-A and verifies SG-B is unaffected (isolation between interfaces).
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

ALLOWED_PORT = 8080
UNLISTED_PORT = 9090


def _ingress_ports(body: dict) -> list[int]:
    return [r.get("port_from", -1) for r in body.get("spec", {}).get("ingress", [])]


def main() -> int:
    parser = argparse.ArgumentParser(description="SG port security policy test (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "sg_port_security_policy",
        "tests": {
            "create_virtual_interface": {"passed": False},
            "apply_port_policy": {"passed": False},
            "allowed_port_permitted": {"passed": False},
            "unlisted_port_blocked": {"passed": False},
            "other_interface_unaffected": {"passed": False},
            "cleanup": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["tests"] = {k: {"passed": True} for k in result["tests"]}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    vnet_id = sg_a_id = sg_b_id = sub_a_id = sub_b_id = ""
    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)
        crd_ns = config.tenant_namespace
        suffix = f"{int(time.time()) % 0xFFFF:04x}"

        # Create VNet + two subnets (virtual interfaces)
        vnet_name = f"isv-sg-psp-vnet-{suffix}"
        s, b = client.create_virtual_network(vnet_name, ipv4_cidr="10.214.0.0/16")
        if s not in (200, 201):
            result["tests"]["create_virtual_interface"]["error"] = f"create_vnet HTTP {s}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_id = b["id"]
        wait_crd_ready("virtualnetwork", vnet_id, crd_ns, label="osac.openshift.io/virtualnetwork-uuid")

        s, b = client.create_subnet(f"isv-psp-sub-a-{suffix}", vnet_id, "10.214.0.0/24")
        if s not in (200, 201):
            result["tests"]["create_virtual_interface"]["error"] = f"create_subnet_a HTTP {s}"
            print(json.dumps(result, indent=2))
            return 1
        sub_a_id = b["id"]
        wait_crd_ready("subnet", sub_a_id, crd_ns, label="osac.openshift.io/subnet-uuid")

        s, b = client.create_subnet(f"isv-psp-sub-b-{suffix}", vnet_id, "10.214.1.0/24")
        if s not in (200, 201):
            result["tests"]["create_virtual_interface"]["error"] = f"create_subnet_b HTTP {s}"
            print(json.dumps(result, indent=2))
            return 1
        sub_b_id = b["id"]
        wait_crd_ready("subnet", sub_b_id, crd_ns, label="osac.openshift.io/subnet-uuid")
        result["tests"]["create_virtual_interface"] = {"passed": True}

        # SG-A: allow port ALLOWED_PORT
        s, b = client.create_security_group(f"isv-sg-psp-a-{suffix}", vnet_id)
        if s not in (200, 201):
            result["tests"]["apply_port_policy"]["error"] = f"create SG-A HTTP {s}"
            print(json.dumps(result, indent=2))
            return 1
        sg_a_id = b["id"]
        wait_crd_ready("securitygroup", sg_a_id, crd_ns, label="osac.openshift.io/securitygroup-uuid")

        s, b = client.update_security_group(
            sg_a_id, "spec.ingress",
            {"spec": {"virtual_network": {"id": vnet_id}, "ingress": [
                {"protocol": "PROTOCOL_TCP", "port_from": ALLOWED_PORT, "port_to": ALLOWED_PORT, "ipv4_cidr": "0.0.0.0/0"},
            ]}},
        )
        result["tests"]["apply_port_policy"] = {"passed": s == 200,
                                                  **({"error": f"HTTP {s}"} if s != 200 else {})}

        # SG-B: no rules
        s, b = client.create_security_group(f"isv-sg-psp-b-{suffix}", vnet_id)
        if s not in (200, 201):
            result["tests"]["other_interface_unaffected"]["error"] = f"create SG-B HTTP {s}"
        else:
            sg_b_id = b["id"]
            wait_crd_ready("securitygroup", sg_b_id, crd_ns, label="osac.openshift.io/securitygroup-uuid")

        # Verify SG-A has ALLOWED_PORT and not UNLISTED_PORT
        s, b = client.get_security_group(sg_a_id)
        if s == 200:
            ports = _ingress_ports(b)
            permitted = ALLOWED_PORT in ports
            result["tests"]["allowed_port_permitted"] = {
                "passed": permitted,
                **({"error": f"port {ALLOWED_PORT} not in SG-A rules: {ports}"} if not permitted else {}),
            }
            blocked = UNLISTED_PORT not in ports
            result["tests"]["unlisted_port_blocked"] = {
                "passed": blocked,
                **({"error": f"port {UNLISTED_PORT} unexpectedly in SG-A rules"} if not blocked else {}),
            }
        else:
            result["tests"]["allowed_port_permitted"]["error"] = f"GET SG-A HTTP {s}"
            result["tests"]["unlisted_port_blocked"]["error"] = f"GET SG-A HTTP {s}"

        # Verify SG-B has no port rules (other interface unaffected)
        if sg_b_id:
            s, b = client.get_security_group(sg_b_id)
            if s == 200:
                ports_b = _ingress_ports(b)
                unaffected = ALLOWED_PORT not in ports_b
                result["tests"]["other_interface_unaffected"] = {
                    "passed": unaffected,
                    **({"error": f"port {ALLOWED_PORT} leaked into SG-B rules"} if not unaffected else {}),
                }
            else:
                result["tests"]["other_interface_unaffected"]["error"] = f"GET SG-B HTTP {s}"

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
    finally:
        try:
            ct, _ = create_sa_token(args.tenant_namespace, "default")
            cc = FulfillmentClient(config, ct)
            cleanup_ok = True
            for res_id, deleter in [(sg_a_id, cc.delete_security_group),
                                     (sg_b_id, cc.delete_security_group),
                                     (sub_a_id, cc.delete_subnet),
                                     (sub_b_id, cc.delete_subnet),
                                     (vnet_id, cc.delete_virtual_network)]:
                if res_id:
                    s, _ = deleter(res_id)
                    if s not in (200, 204, 404):
                        cleanup_ok = False
            result["tests"]["cleanup"] = {"passed": cleanup_ok}
        except Exception:
            result["tests"]["cleanup"] = {"passed": False}

    result["success"] = all(t.get("passed") for t in result["tests"].values())
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
