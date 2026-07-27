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

"""Teardown for OSAC network validation.

Best-effort cleanup of the shared ephemeral tenant created by
setup_tenant.py: sweeps any leftover isv-* SecurityGroups, Subnets, and
VirtualNetworks visible to that tenant's ServiceAccount token (order
matters for parent-child dependencies), deletes the fulfillment-service
Tenant record (via gRPC — not exposed on the REST gateway), then deletes
the Kubernetes Tenant CRD.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import (
    FulfillmentClient,
    TenantClient,
    create_sa_token,
    get_admin_token,
    get_env_config,
    grpcurl_call,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
PREFIX = "isv-"


def main() -> int:
    parser = argparse.ArgumentParser(description="Network teardown (OSAC)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant-name", default="")
    parser.add_argument("--tenant-namespace", default="")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "teardown",
    }

    if DEMO_MODE:
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    cleanup_errors: list[str] = []
    try:
        config = get_env_config(require_admin=False)

        # Sweep leftover network resources FIRST, while the tenant's
        # namespace and ServiceAccount still exist: deleting the
        # fulfillment tenant record below cascades to terminate the
        # namespace, after which SA tokens can no longer be minted.
        if args.tenant_namespace:
            token, _ttl = create_sa_token(args.tenant_namespace, "default")
            client = FulfillmentClient(config, token)

            # Delete SecurityGroups first (children of VNets)
            s, body = client.list_security_groups()
            if s == 200:
                for sg in body.get("items", []):
                    name = sg.get("metadata", {}).get("name", "")
                    rid = sg.get("id", "")
                    if name.startswith(PREFIX) and rid:
                        try:
                            client.delete_security_group(rid)
                        except Exception as e:
                            cleanup_errors.append(f"delete SG {name}: {e}")

            # Delete Subnets (children of VNets)
            s, body = client.list_subnets()
            if s == 200:
                for sub in body.get("items", []):
                    name = sub.get("metadata", {}).get("name", "")
                    rid = sub.get("id", "")
                    if name.startswith(PREFIX) and rid:
                        try:
                            client.delete_subnet(rid)
                        except Exception as e:
                            cleanup_errors.append(f"delete subnet {name}: {e}")

            # Delete VirtualNetworks last
            s, body = client.list_virtual_networks()
            if s == 200:
                for vnet in body.get("items", []):
                    name = vnet.get("metadata", {}).get("name", "")
                    rid = vnet.get("id", "")
                    if name.startswith(PREFIX) and rid:
                        try:
                            client.delete_virtual_network(rid)
                        except Exception as e:
                            cleanup_errors.append(f"delete VNet {name}: {e}")

        if args.tenant_name and config.fulfillment_grpc_address:
            try:
                admin_config = get_env_config()
                admin_token = get_admin_token(admin_config)
                grpcurl_call(
                    admin_config.fulfillment_grpc_address,
                    "osac.private.v1.Tenants/Delete",
                    {"id": args.tenant_name},
                    admin_token,
                    verify_ssl=admin_config.verify_ssl,
                )
            except Exception as e:
                cleanup_errors.append(f"delete fulfillment tenant: {e}")

        if args.tenant_name:
            try:
                TenantClient(config).delete(args.tenant_name)
            except Exception as e:
                cleanup_errors.append(f"delete tenant: {e}")

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    if cleanup_errors:
        result["cleanup_errors"] = cleanup_errors

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
