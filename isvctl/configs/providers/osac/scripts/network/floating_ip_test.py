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

"""Floating IP (ExternalIP) switch test for OSAC (SDN05-01).

Validates that an ExternalIP can be reassigned between two compute
instances. The full lifecycle:

  1. Create an ephemeral ExternalIPPool (private admin API, 198.51.100.0/28).
  2. Create two ComputeInstances from the ocp_virt_vm template and wait
     for both to reach RUNNING.
  3. Allocate an ExternalIP from the pool.
  4. Attach it to instance A (ExternalIPAttachment) and verify READY.
  5. Reassign: delete attachment A, create attachment B — record elapsed.
  6. Verify attachment B is READY and attachment A is gone (404).
  7. Teardown: delete attachments, ExternalIP, instances, pool.

The ExternalIPPool CIDR (198.51.100.0/28, TEST-NET-2 per RFC 5737) is not
internet-routable; it is used only to exercise the API lifecycle. No actual
traffic probing is performed — FloatingIpCheck only asserts API-level state
and timing.
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

from common.osac_client import (
    FulfillmentClient,
    create_sa_token,
    get_admin_token,
    get_env_config,
    wait_crd_ready,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
COMPUTE_TEMPLATE = "osac.templates.ocp_virt_vm"


def main() -> int:
    parser = argparse.ArgumentParser(description="Floating IP switch test (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-namespace", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "floating_ip_test",
        "tests": {
            "allocate_eip": {"passed": False},
            "associate_to_a": {"passed": False},
            "verify_on_a": {"passed": False},
            "reassociate_to_b": {"passed": False},
            "verify_on_b": {"passed": False},
            "verify_not_on_a": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["tests"] = {
            "allocate_eip": {"passed": True, "public_ip": "198.51.100.5"},
            "associate_to_a": {"passed": True},
            "verify_on_a": {"passed": True},
            "reassociate_to_b": {"passed": True, "switch_seconds": 5},
            "verify_on_b": {"passed": True},
            "verify_not_on_a": {"passed": True},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    config = get_env_config()
    if not config.fulfillment_private_url:
        result["error"] = "OSAC_FULFILLMENT_GRPC_ADDRESS required to derive private API URL"
        print(json.dumps(result, indent=2))
        return 1

    admin_token = get_admin_token(config)
    sa_token, _ttl = create_sa_token(args.tenant_namespace, "default")
    client = FulfillmentClient(config, sa_token)

    suffix = f"{int(time.time()) % 0xFFFF:04x}"
    # Pick a unique /30 within 198.51.100.0/24 based on the run suffix so
    # concurrent or back-to-back runs don't conflict with lingering DELETING pools.
    subnet_idx = int(suffix, 16) % 64
    pool_cidr = f"198.51.100.{subnet_idx * 4}/30"

    instance_type_id = ""
    pool_id = ""
    vnet_id = ""
    subnet_id = ""
    eip_id = ""
    attach_a_id = ""
    attach_b_id = ""
    instance_a_id = ""
    instance_b_id = ""
    cleanup_errors: list[str] = []
    crd_ns = config.tenant_namespace

    try:
        # --- Create InstanceType (admin, private API) ---
        itype_name = f"isv-fip-type-{suffix}"
        s, b = client.create_instance_type(itype_name, cores=1, memory_gib=2, admin_token=admin_token)
        if s not in (200, 201) or not isinstance(b, dict):
            result["error"] = f"create InstanceType failed (HTTP {s}): {b}"
            print(json.dumps(result, indent=2))
            return 1
        instance_type_id = b.get("id", "")

        # --- Create ExternalIPPool (admin, private API) ---
        pool_name = f"isv-fip-pool-{suffix}"
        s, b = client.create_external_ip_pool(pool_name, [pool_cidr], admin_token)
        if s not in (200, 201) or not isinstance(b, dict):
            result["error"] = f"create ExternalIPPool failed (HTTP {s}): {b}"
            print(json.dumps(result, indent=2))
            return 1
        pool_id = b.get("id", "")
        client.wait_external_ip_pool_ready(pool_id, admin_token, timeout=120)

        # --- Create VNet + Subnet for instance network attachments ---
        vnet_name = f"isv-fip-vnet-{suffix}"
        s, b = client.create_virtual_network(vnet_name, ipv4_cidr="10.207.0.0/16")
        if s not in (200, 201) or not isinstance(b, dict):
            result["error"] = f"create VNet failed (HTTP {s}): {b}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_id = b.get("id", "")
        wait_crd_ready("virtualnetwork", vnet_id, crd_ns, label="osac.openshift.io/virtualnetwork-uuid")

        sub_name = f"isv-fip-sub-{suffix}"
        s, b = client.create_subnet(sub_name, vnet_id, "10.207.0.0/24")
        if s not in (200, 201) or not isinstance(b, dict):
            result["error"] = f"create Subnet failed (HTTP {s}): {b}"
            print(json.dumps(result, indent=2))
            return 1
        subnet_id = b.get("id", "")
        wait_crd_ready("subnet", subnet_id, crd_ns, label="osac.openshift.io/subnet-uuid")

        # --- Create two ComputeInstances ---
        for label in ("A", "B"):
            inst_name = f"isv-fip-vm-{label.lower()}-{suffix}"
            s, b = client.create_compute_instance_from_template(
                inst_name,
                COMPUTE_TEMPLATE,
                subnet_id=subnet_id,
                instance_type_name=itype_name,
                token=sa_token,
            )
            if s not in (200, 201) or not isinstance(b, dict):
                result["error"] = f"create ComputeInstance {label} failed (HTTP {s}): {b}"
                print(json.dumps(result, indent=2))
                return 1
            if label == "A":
                instance_a_id = b.get("id", "")
            else:
                instance_b_id = b.get("id", "")

        # Wait for both instances to reach RUNNING
        for label, iid in [("A", instance_a_id), ("B", instance_b_id)]:
            client.wait_compute_instance_running(iid, timeout=600, token=sa_token)

        # --- Allocate ExternalIP ---
        eip_name = f"isv-fip-{suffix}"
        s, b = client.create_external_ip(eip_name, pool_id)
        if s not in (200, 201) or not isinstance(b, dict):
            result["error"] = f"create ExternalIP failed (HTTP {s}): {b}"
            print(json.dumps(result, indent=2))
            return 1
        eip_id = b.get("id", "")
        address = client.wait_external_ip_allocated(eip_id, timeout=120)
        result["tests"]["allocate_eip"] = {"passed": True, "public_ip": address}

        # --- Associate to instance A ---
        attach_a_name = f"isv-fip-att-a-{suffix}"
        s, b = client.create_external_ip_attachment(attach_a_name, eip_id, instance_a_id)
        if s not in (200, 201) or not isinstance(b, dict):
            result["tests"]["associate_to_a"]["error"] = f"HTTP {s}: {b}"
        else:
            attach_a_id = b.get("id", "")
            client.wait_external_ip_attachment_ready(attach_a_id, timeout=300)
            result["tests"]["associate_to_a"] = {"passed": True}

        # --- Verify attached on A ---
        s, b = client.get_external_ip(eip_id)
        if s == 200 and isinstance(b, dict) and b.get("status", {}).get("attached"):
            result["tests"]["verify_on_a"] = {"passed": True}
        else:
            result["tests"]["verify_on_a"]["error"] = f"attached=false or HTTP {s}"

        # --- Reassociate to B (timed) ---
        t_start = time.monotonic()
        client.delete_external_ip_attachment(attach_a_id)
        # Wait for attachment A to be fully gone (404) before creating B.
        # Checking EIP.status.attached=false is not enough — the attachment
        # object must be deleted server-side or the next Create returns 409.
        deadline = time.time() + 120
        while time.time() < deadline:
            s, _ = client.get_external_ip_attachment(attach_a_id)
            if s in (404, 410):
                attach_a_id = ""
                break
            time.sleep(3)

        attach_b_name = f"isv-fip-att-b-{suffix}"
        s, b = client.create_external_ip_attachment(attach_b_name, eip_id, instance_b_id)
        if s not in (200, 201) or not isinstance(b, dict):
            result["tests"]["reassociate_to_b"]["error"] = f"create HTTP {s}: {b}"
        else:
            attach_b_id = b.get("id", "")
            client.wait_external_ip_attachment_ready(attach_b_id, timeout=300)
            switch_seconds = round(time.monotonic() - t_start, 1)
            result["tests"]["reassociate_to_b"] = {"passed": True, "switch_seconds": switch_seconds}

        # --- Verify on B ---
        s, b = client.get_external_ip_attachment(attach_b_id)
        if (
            s == 200
            and isinstance(b, dict)
            and b.get("status", {}).get("state") == "EXTERNAL_IP_ATTACHMENT_STATE_READY"
        ):
            result["tests"]["verify_on_b"] = {"passed": True}
        else:
            result["tests"]["verify_on_b"]["error"] = f"state not READY (HTTP {s})"

        # --- Verify not on A ---
        # attach_a_id is "" if the wait loop already confirmed 404 above.
        if not attach_a_id:
            result["tests"]["verify_not_on_a"] = {"passed": True}
        else:
            s, _ = client.get_external_ip_attachment(attach_a_id)
            if s in (404, 410):
                result["tests"]["verify_not_on_a"] = {"passed": True}
                attach_a_id = ""
            else:
                result["tests"]["verify_not_on_a"]["error"] = f"expected 404, got HTTP {s}"

        result["success"] = all(t.get("passed") for t in result["tests"].values())

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    finally:
        for attach_id in [attach_b_id, attach_a_id]:
            if attach_id:
                try:
                    client.delete_external_ip_attachment(attach_id)
                except Exception as e:
                    cleanup_errors.append(f"delete attachment {attach_id}: {e}")
        if eip_id:
            # Wait for detach before deleting EIP
            deadline = time.time() + 60
            while time.time() < deadline:
                s, b = client.get_external_ip(eip_id)
                if s == 200 and isinstance(b, dict) and not b.get("status", {}).get("attached"):
                    break
                time.sleep(3)
            try:
                client.delete_external_ip(eip_id)
            except Exception as e:
                cleanup_errors.append(f"delete EIP {eip_id}: {e}")
        for iid in [instance_a_id, instance_b_id]:
            if iid:
                try:
                    client.delete_compute_instance(iid, token=sa_token)
                except Exception as e:
                    cleanup_errors.append(f"delete instance {iid}: {e}")
        if subnet_id:
            try:
                client.delete_subnet(subnet_id)
            except Exception as e:
                cleanup_errors.append(f"delete subnet {subnet_id}: {e}")
        if vnet_id:
            try:
                client.delete_virtual_network(vnet_id)
            except Exception as e:
                cleanup_errors.append(f"delete vnet {vnet_id}: {e}")
        if pool_id:
            try:
                client.delete_external_ip_pool(pool_id, admin_token)
            except Exception as e:
                cleanup_errors.append(f"delete pool {pool_id}: {e}")
        if instance_type_id:
            try:
                client.delete_instance_type(instance_type_id, admin_token)
            except Exception as e:
                cleanup_errors.append(f"delete instance type {instance_type_id}: {e}")

    if cleanup_errors:
        result["cleanup_errors"] = cleanup_errors

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
