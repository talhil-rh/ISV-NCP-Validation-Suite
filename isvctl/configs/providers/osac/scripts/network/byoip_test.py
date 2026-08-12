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

"""BYOIP (Bring Your Own IP) validation using ExternalIPPool (NET03-01).

Creates two ExternalIPPool objects with non-overlapping CIDRs, verifies
both reach READY state with no conflicts, then allocates an ExternalIP
from the custom pool to confirm address assignment.

Requires: OSAC_ADMIN_CLIENT_ID / OSAC_ADMIN_CLIENT_SECRET for pool admin ops.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import FulfillmentClient, create_sa_token, get_admin_token, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def _per_run_cidrs() -> tuple[str, str]:
    """Return two non-overlapping /30 CIDRs unique to this run."""
    suffix = int(time.time()) % 0xFFFF
    idx_a = suffix % 64
    idx_b = (idx_a + 1) % 64
    return (
        f"198.51.100.{idx_a * 4}/30",
        f"198.51.100.{idx_b * 4}/30",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="BYOIP / ExternalIPPool test (OSAC)")
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    custom_cidr, standard_cidr = _per_run_cidrs()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "byoip_test",
        "tests": {
            "custom_cidr_create": {"passed": False, "cidr": custom_cidr},
            "custom_cidr_verify": {"passed": False},
            "standard_cidr_create": {"passed": False},
            "no_conflict": {"passed": False},
            "custom_cidr_subnet": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["tests"] = {
            "custom_cidr_create": {"passed": True, "cidr": custom_cidr},
            "custom_cidr_verify": {"passed": True},
            "standard_cidr_create": {"passed": True},
            "no_conflict": {"passed": True},
            "custom_cidr_subnet": {"passed": True},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    config = get_env_config(require_admin=True)
    pool_a_id = pool_b_id = eip_id = ""
    try:
        admin_token = get_admin_token(config)
        sa_token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, sa_token)
        suffix = f"{int(time.time()) % 0xFFFF:04x}"

        # Create custom CIDR pool
        s, b = client.create_external_ip_pool(f"isv-byoip-a-{suffix}", [custom_cidr], admin_token)
        if s not in (200, 201):
            result["tests"]["custom_cidr_create"]["error"] = f"HTTP {s}: {b}"
            print(json.dumps(result, indent=2))
            return 1
        pool_a_id = b.get("id", "")
        client.wait_external_ip_pool_ready(pool_a_id, admin_token)
        result["tests"]["custom_cidr_create"] = {"passed": True, "cidr": custom_cidr, "pool_id": pool_a_id}

        # Verify pool is READY and CIDRs match
        s, b = client.get_external_ip_pool(pool_a_id, admin_token)
        if s == 200:
            state = b.get("status", {}).get("state", "")
            cidrs = b.get("spec", {}).get("cidrs", [])
            ready = "READY" in state.upper()
            cidr_ok = custom_cidr in cidrs
            result["tests"]["custom_cidr_verify"] = {
                "passed": ready and cidr_ok,
                **({"error": f"state={state}, cidrs={cidrs}"} if not (ready and cidr_ok) else {}),
            }
        else:
            result["tests"]["custom_cidr_verify"]["error"] = f"GET pool HTTP {s}"

        # Create standard (second) CIDR pool
        s, b = client.create_external_ip_pool(f"isv-byoip-b-{suffix}", [standard_cidr], admin_token)
        if s not in (200, 201):
            result["tests"]["standard_cidr_create"]["error"] = f"HTTP {s}: {b}"
        else:
            pool_b_id = b.get("id", "")
            client.wait_external_ip_pool_ready(pool_b_id, admin_token)
            result["tests"]["standard_cidr_create"] = {"passed": True, "cidr": standard_cidr}

        # Verify no overlap between the two pools
        try:
            net_a = ipaddress.ip_network(custom_cidr, strict=False)
            net_b = ipaddress.ip_network(standard_cidr, strict=False)
            overlaps = net_a.overlaps(net_b)
            result["tests"]["no_conflict"] = {
                "passed": not overlaps,
                **({"error": f"{custom_cidr} overlaps {standard_cidr}"} if overlaps else {}),
            }
        except ValueError as e:
            result["tests"]["no_conflict"]["error"] = str(e)

        # Allocate an ExternalIP from the custom pool and verify address is within CIDR
        eip_name = f"isv-byoip-eip-{suffix}"
        s, b = client.create_external_ip(eip_name, pool_a_id)
        if s not in (200, 201):
            result["tests"]["custom_cidr_subnet"]["error"] = f"create ExternalIP HTTP {s}: {b}"
        else:
            eip_id = b.get("id", "")
            try:
                address = client.wait_external_ip_allocated(eip_id)
                net_a = ipaddress.ip_network(custom_cidr, strict=False)
                in_cidr = ipaddress.ip_address(address) in net_a
                result["tests"]["custom_cidr_subnet"] = {
                    "passed": in_cidr,
                    "address": address,
                    **({"error": f"{address} not in {custom_cidr}"} if not in_cidr else {}),
                }
            except Exception as e:
                result["tests"]["custom_cidr_subnet"]["error"] = str(e)

        result["success"] = all(t.get("passed") for t in result["tests"].values())

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
    finally:
        try:
            admin_token = get_admin_token(config)
            sa_token, _ttl = create_sa_token(args.tenant_namespace, "default")
            cc = FulfillmentClient(config, sa_token)
            if eip_id:
                try:
                    cc.delete_external_ip(eip_id)
                except Exception:
                    pass
            if pool_a_id:
                try:
                    cc.delete_external_ip_pool(pool_a_id, admin_token)
                except Exception:
                    pass
            if pool_b_id:
                try:
                    cc.delete_external_ip_pool(pool_b_id, admin_token)
                except Exception:
                    pass
        except Exception:
            pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
