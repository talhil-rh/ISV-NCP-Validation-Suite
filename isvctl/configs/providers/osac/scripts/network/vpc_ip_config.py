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

"""Query VNet + subnets and emit VpcIpConfigCheck-compatible output (IPAM02-01).

Reads the VirtualNetwork and its subnets from the fulfillment API and
derives DHCP/DNS info from the cluster's CoreDNS service.

Output JSON contract:
  cidr           - VNet IPv4 CIDR
  subnets        - list of {cidr} dicts (one per subnet in this VNet)
  dhcp_options   - {domain_name_servers: [...]} from CoreDNS cluster service
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


def _get_coredns_ip() -> str | None:
    """Return the CoreDNS cluster service IP via kubectl, or None on failure."""
    kubectl = shutil.which("kubectl") or shutil.which("oc")
    if not kubectl:
        return None
    for ns, svc in [("openshift-dns", "dns-default"), ("kube-system", "kube-dns")]:
        try:
            r = subprocess.run(
                [kubectl, "get", "svc", svc, "-n", ns,
                 "-o", "jsonpath={.spec.clusterIP}"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            continue
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="VPC IP config check (OSAC)")
    parser.add_argument("--vnet-id", required=True, help="VirtualNetwork UUID from create_network")
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "vpc_ip_config",
        "cidr": "",
        "subnets": [],
        "dhcp_options": {},
    }

    if DEMO_MODE:
        result.update({
            "success": True,
            "cidr": "10.200.0.0/16",
            "subnets": [
                {"cidr": "10.200.0.0/24"},
                {"cidr": "10.200.1.0/24"},
            ],
            "dhcp_options": {"domain_name_servers": ["172.30.0.10"]},
        })
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        # Get VNet CIDR
        status, body = client.get_virtual_network(args.vnet_id)
        if status != 200:
            result["error"] = f"GET VirtualNetwork {args.vnet_id} failed (HTTP {status}): {body}"
            print(json.dumps(result, indent=2))
            return 1

        spec = body.get("spec", {})
        cidr = spec.get("ipv4_cidr") or spec.get("ipv4Cidr") or ""
        result["cidr"] = cidr

        # List subnets and filter to this VNet
        s_status, s_body = client.list_subnets()
        subnets = []
        if s_status == 200:
            items = s_body if isinstance(s_body, list) else s_body.get("items", [])
            for item in items:
                item_spec = item.get("spec", {})
                vnet_ref = item_spec.get("virtual_network") or item_spec.get("virtualNetwork") or {}
                vnet_ref_id = vnet_ref.get("id") or vnet_ref.get("name") or ""
                if vnet_ref_id == args.vnet_id:
                    sub_cidr = item_spec.get("ipv4_cidr") or item_spec.get("ipv4Cidr") or ""
                    if sub_cidr:
                        subnets.append({"cidr": sub_cidr})
        result["subnets"] = subnets

        # Get DNS from CoreDNS cluster service
        dns_ip = _get_coredns_ip()
        dns_servers = [dns_ip] if dns_ip else []
        result["dhcp_options"] = {"domain_name_servers": dns_servers}

        if not cidr:
            result["error"] = f"VirtualNetwork {args.vnet_id} has no ipv4_cidr in spec"
            print(json.dumps(result, indent=2))
            return 1

        if not dns_servers:
            result["error"] = "Could not determine CoreDNS service IP from cluster"
            print(json.dumps(result, indent=2))
            return 1

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
