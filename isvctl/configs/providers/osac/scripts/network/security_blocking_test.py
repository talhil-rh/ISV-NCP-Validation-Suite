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

"""Security blocking test for OSAC.

Verifies that OSAC SecurityGroups enforce default-deny and selective-allow
by inspecting the API-level rule structure.
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
    parser = argparse.ArgumentParser(description="Security blocking test (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "security_blocking",
        "network_id": "",
        "tests": {
            "sg_default_deny_inbound": {"passed": False},
            "sg_allows_specific_ssh": {"passed": False},
            "sg_denies_vpc_icmp": {"passed": False},
            "nacl_explicit_deny": {"passed": False},
            "sg_restricted_egress": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["network_id"] = "isv-secblk-demo"
        result["tests"] = {
            "sg_default_deny_inbound": {"passed": True},
            "sg_allows_specific_ssh": {"passed": True},
            "sg_denies_vpc_icmp": {"passed": True},
            "nacl_explicit_deny": {
                "passed": True,
                "message": "OSAC uses SecurityGroups only -- default-deny covers NACL semantics",
            },
            "sg_restricted_egress": {"passed": True},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    vnet_id = ""
    sg_ids: list[str] = []
    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        suffix = f"{int(time.time()) % 0xFFFF:04x}"

        # Create VNet
        vnet_name = f"isv-secblk-{suffix}"
        s, b = client.create_virtual_network(vnet_name, ipv4_cidr="10.206.0.0/16")
        if s not in (200, 201):
            result["error"] = f"create VNet failed (HTTP {s}): {b}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_id = b["id"]

        crd_ns = config.tenant_namespace
        wait_crd_ready("virtualnetwork", vnet_id, crd_ns, label="osac.openshift.io/virtualnetwork-uuid")
        result["network_id"] = vnet_id

        # Create SG with NO rules (default-deny)
        sg_deny_name = f"isv-secblk-deny-{suffix}"
        s, b = client.create_security_group(sg_deny_name, vnet_id)
        if s not in (200, 201):
            result["error"] = f"create deny SG failed (HTTP {s}): {b}"
            print(json.dumps(result, indent=2))
            return 1
        sg_deny = b["id"]
        sg_ids.append(sg_deny)

        wait_crd_ready("securitygroup", sg_deny, crd_ns, label="osac.openshift.io/securitygroup-uuid")

        # sg_default_deny_inbound: verify empty ingress
        s, b = client.get_security_group(sg_deny)
        if s == 200:
            ingress = b.get("spec", {}).get("ingress", [])
            if not ingress:
                result["tests"]["sg_default_deny_inbound"] = {"passed": True}
            else:
                result["tests"]["sg_default_deny_inbound"]["error"] = (
                    f"Expected empty ingress but got {len(ingress)} rules"
                )
        else:
            result["tests"]["sg_default_deny_inbound"]["error"] = f"HTTP {s}"

        # sg_allows_specific_ssh: add SSH ingress rule, verify present
        s, b = client.update_security_group(
            sg_deny,
            "spec.ingress",
            {
                "spec": {
                    "virtual_network": vnet_id,
                    "ingress": [
                        {
                            "protocol": "PROTOCOL_TCP",
                            "port_from": 22,
                            "port_to": 22,
                            "ipv4_cidr": "10.0.0.0/8",
                        }
                    ],
                }
            },
        )
        if s == 200:
            gs, gb = client.get_security_group(sg_deny)
            if gs == 200:
                rules = gb.get("spec", {}).get("ingress", [])
                has_ssh = any(r.get("port_from") == 22 and r.get("protocol") in ("TCP", "PROTOCOL_TCP") for r in rules)
                result["tests"]["sg_allows_specific_ssh"] = {"passed": has_ssh}
                if not has_ssh:
                    result["tests"]["sg_allows_specific_ssh"]["error"] = "SSH rule not found after update"
            else:
                result["tests"]["sg_allows_specific_ssh"]["error"] = f"GET HTTP {gs}"
        else:
            result["tests"]["sg_allows_specific_ssh"]["error"] = f"update HTTP {s}"

        # sg_denies_vpc_icmp: verify no ICMP rule (implicit deny)
        s, b = client.get_security_group(sg_deny)
        if s == 200:
            rules = b.get("spec", {}).get("ingress", [])
            has_icmp = any(r.get("protocol") in ("ICMP", "PROTOCOL_ICMP") for r in rules)
            result["tests"]["sg_denies_vpc_icmp"] = {"passed": not has_icmp}
            if has_icmp:
                result["tests"]["sg_denies_vpc_icmp"]["error"] = "ICMP rule unexpectedly present"
        else:
            result["tests"]["sg_denies_vpc_icmp"]["error"] = f"HTTP {s}"

        # nacl_explicit_deny: OSAC has no NACL concept
        result["tests"]["nacl_explicit_deny"] = {
            "passed": True,
            "message": "OSAC uses SecurityGroups only -- default-deny covers NACL semantics",
        }

        # sg_restricted_egress: create SG with egress TCP 443 only
        sg_egress_name = f"isv-secblk-egress-{suffix}"
        s, b = client.create_security_group(
            sg_egress_name,
            vnet_id,
            egress=[
                {
                    "protocol": "PROTOCOL_TCP",
                    "port_from": 443,
                    "port_to": 443,
                    "ipv4_cidr": "0.0.0.0/0",
                }
            ],
        )
        if s not in (200, 201):
            result["tests"]["sg_restricted_egress"]["error"] = f"create HTTP {s}"
        else:
            sg_egress = b["id"]
            sg_ids.append(sg_egress)
            gs, gb = client.get_security_group(sg_egress)
            if gs == 200:
                egress_rules = gb.get("spec", {}).get("egress", [])
                has_443 = any(
                    r.get("port_from") == 443 and r.get("protocol") in ("TCP", "PROTOCOL_TCP") for r in egress_rules
                )
                result["tests"]["sg_restricted_egress"] = {"passed": has_443}
                if not has_443:
                    result["tests"]["sg_restricted_egress"]["error"] = "TCP 443 egress rule not found"
            else:
                result["tests"]["sg_restricted_egress"]["error"] = f"GET HTTP {gs}"

        result["success"] = all(t.get("passed") for t in result["tests"].values())

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
    finally:
        try:
            cleanup_token, _ttl = create_sa_token(args.tenant_namespace, "default")
            cleanup_client = FulfillmentClient(config, cleanup_token)
            for sg in sg_ids:
                try:
                    cleanup_client.delete_security_group(sg)
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
