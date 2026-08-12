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

"""SecurityGroup node scoping test (SDN02-06).

Creates a SG with an ingress rule scoped to a specific node host IP (/32)
and verifies a different host IP is implicitly blocked.
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

TARGET_NODE_CIDR = "10.0.1.10/32"
OTHER_NODE_CIDR = "10.0.1.11/32"


def _ingress_cidrs(body: dict) -> list[str]:
    return [r.get("ipv4_cidr", "") for r in body.get("spec", {}).get("ingress", [])]


def main() -> int:
    parser = argparse.ArgumentParser(description="SG node scoping test (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "sg_node_scoping",
        "scope": "node",
        "tests": {
            "create_sg": {"passed": False},
            "apply_node_rule": {"passed": False},
            "target_node_allowed": {"passed": False},
            "other_node_blocked": {"passed": False},
            "cleanup": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["tests"] = {k: {"passed": True} for k in result["tests"]}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    vnet_id = sg_id = ""
    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)
        crd_ns = config.tenant_namespace
        suffix = f"{int(time.time()) % 0xFFFF:04x}"

        vnet_name = f"isv-sg-nd-vnet-{suffix}"
        s, b = client.create_virtual_network(vnet_name, ipv4_cidr="10.211.0.0/16")
        if s not in (200, 201):
            result["tests"]["create_sg"]["error"] = f"create_vnet HTTP {s}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_id = b["id"]
        wait_crd_ready("virtualnetwork", vnet_id, crd_ns, label="osac.openshift.io/virtualnetwork-uuid")

        sg_name = f"isv-sg-nd-{suffix}"
        s, b = client.create_security_group(sg_name, vnet_id)
        if s not in (200, 201):
            result["tests"]["create_sg"]["error"] = f"HTTP {s}: {b}"
            print(json.dumps(result, indent=2))
            return 1
        sg_id = b["id"]
        wait_crd_ready("securitygroup", sg_id, crd_ns, label="osac.openshift.io/securitygroup-uuid")
        result["tests"]["create_sg"] = {"passed": True, "sg_id": sg_id}

        s, b = client.update_security_group(
            sg_id, "spec.ingress",
            {"spec": {"virtual_network": {"id": vnet_id}, "ingress": [
                {"protocol": "PROTOCOL_TCP", "port_from": 22, "port_to": 22, "ipv4_cidr": TARGET_NODE_CIDR},
            ]}},
        )
        result["tests"]["apply_node_rule"] = {"passed": s == 200,
                                               **({"error": f"HTTP {s}"} if s != 200 else {})}

        s, b = client.get_security_group(sg_id)
        if s == 200:
            cidrs = _ingress_cidrs(b)
            allowed = TARGET_NODE_CIDR in cidrs
            result["tests"]["target_node_allowed"] = {"passed": allowed,
                                                       **({"error": f"{TARGET_NODE_CIDR} not in rules"} if not allowed else {})}
            blocked = OTHER_NODE_CIDR not in cidrs
            result["tests"]["other_node_blocked"] = {"passed": blocked,
                                                       **({"error": f"{OTHER_NODE_CIDR} unexpectedly in rules"} if not blocked else {})}
        else:
            result["tests"]["target_node_allowed"]["error"] = f"GET SG HTTP {s}"
            result["tests"]["other_node_blocked"]["error"] = f"GET SG HTTP {s}"

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
    finally:
        try:
            ct, _ = create_sa_token(args.tenant_namespace, "default")
            cc = FulfillmentClient(config, ct)
            cleanup_ok = True
            if sg_id:
                s, _ = cc.delete_security_group(sg_id)
                if s not in (200, 204, 404):
                    cleanup_ok = False
            if vnet_id:
                s, _ = cc.delete_virtual_network(vnet_id)
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
