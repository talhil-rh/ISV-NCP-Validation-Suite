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

"""VPC (VirtualNetwork) tenant isolation test for OSAC (SDN04-02).

Creates two ephemeral tenants and VNets, verifies cross-tenant API
isolation: Tenant A cannot see or access Tenant B's VNet and vice versa.

Each tenant is registered via the fulfillment-service Tenants gRPC API
(see setup_tenant.py for why this needs gRPC, not REST, and why it
requires admin credentials distinct from the ephemeral bootstrap client).
Registration triggers osac-operator to auto-provision a matching
Kubernetes Tenant CRD and labeled namespace within seconds. Each tenant
then authenticates to the fulfillment API as the Kubernetes ServiceAccount
in its own dedicated namespace: the fulfillment-service gRPC server
trusts the in-cluster Kubernetes API server as a JWT issuer and resolves
the tenant from the SA token's `system:serviceaccount:<namespace>:<name>`
subject.
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
    TenantClient,
    create_sa_token,
    get_admin_token,
    get_env_config,
    grpcurl_call,
    wait_crd_ready,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
POLL_INTERVAL = 2
POLL_TIMEOUT = 60


def _create_tenant(config: Any, admin_token: str, tc: TenantClient, name: str, domain: str) -> str:
    """Register a fulfillment Tenant and wait for its namespace to appear.

    Returns the tenant's dedicated namespace.
    """
    grpcurl_call(
        config.fulfillment_grpc_address,
        "osac.private.v1.Tenants/Create",
        {"object": {"metadata": {"name": name}, "spec": {"domains": [domain]}}},
        admin_token,
        verify_ssl=config.verify_ssl,
    )

    deadline = time.time() + POLL_TIMEOUT
    while time.time() < deadline:
        try:
            tenant = tc.get(name)
            namespace = tenant.get("status", {}).get("namespace", "")
        except RuntimeError:
            namespace = ""
        if namespace:
            return namespace
        time.sleep(POLL_INTERVAL)
    raise RuntimeError(f"Tenant '{name}' namespace not provisioned within {POLL_TIMEOUT}s")


def main() -> int:
    parser = argparse.ArgumentParser(description="VPC isolation test (OSAC)")
    parser.add_argument("--region", required=True)
    parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "vpc_isolation",
        "vpc_a": {},
        "vpc_b": {},
        "tests": {
            "no_peering": {"passed": False},
            "no_cross_routes_a": {"passed": False},
            "no_cross_routes_b": {"passed": False},
            "sg_isolation_a": {"passed": False},
            "sg_isolation_b": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["vpc_a"] = {"id": "isv-iso-a-demo", "cidr": "10.203.0.0/16"}
        result["vpc_b"] = {"id": "isv-iso-b-demo", "cidr": "10.204.0.0/16"}
        result["tests"] = {
            "no_peering": {
                "passed": True,
                "message": "OSAC has no VPC peering API",
            },
            "no_cross_routes_a": {
                "passed": True,
                "message": "Tenant A cannot list Tenant B VNets",
            },
            "no_cross_routes_b": {
                "passed": True,
                "message": "Tenant B cannot list Tenant A VNets",
            },
            "sg_isolation_a": {"passed": True},
            "sg_isolation_b": {"passed": True},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    tenant_a_name = ""
    tenant_b_name = ""
    vnet_a_id = ""
    vnet_b_id = ""
    cleanup_errors: list[str] = []

    try:
        config = get_env_config()
        if not config.fulfillment_grpc_address:
            raise RuntimeError("OSAC_FULFILLMENT_GRPC_ADDRESS is required")
        admin_token = get_admin_token(config)
        tc = TenantClient(config)

        suffix = f"{int(time.time()) % 0xFFFF:04x}"

        tenant_a_name = f"isv-iso-a-{suffix}"
        namespace_a = _create_tenant(config, admin_token, tc, tenant_a_name, f"iso-a-{suffix}.isv-net-test.local")

        tenant_b_name = f"isv-iso-b-{suffix}"
        namespace_b = _create_tenant(config, admin_token, tc, tenant_b_name, f"iso-b-{suffix}.isv-net-test.local")

        token_a, _ttl_a = create_sa_token(namespace_a, "default")
        token_b, _ttl_b = create_sa_token(namespace_b, "default")

        client = FulfillmentClient(config, token_a)

        # Create VNet A under Tenant A's token
        vnet_a_name = f"isv-iso-vnet-a-{suffix}"
        s, b = client.create_virtual_network(vnet_a_name, token=token_a, ipv4_cidr="10.203.0.0/16")
        if s not in (200, 201):
            result["error"] = f"create VNet A failed (HTTP {s}): {b}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_a_id = b["id"]
        wait_crd_ready(
            "virtualnetwork", vnet_a_id, config.tenant_namespace, label="osac.openshift.io/virtualnetwork-uuid"
        )
        result["vpc_a"] = {"id": vnet_a_id, "cidr": "10.203.0.0/16"}

        # Create VNet B under Tenant B's token
        vnet_b_name = f"isv-iso-vnet-b-{suffix}"
        s, b = client.create_virtual_network(vnet_b_name, token=token_b, ipv4_cidr="10.204.0.0/16")
        if s not in (200, 201):
            result["error"] = f"create VNet B failed (HTTP {s}): {b}"
            print(json.dumps(result, indent=2))
            return 1
        vnet_b_id = b["id"]
        wait_crd_ready(
            "virtualnetwork", vnet_b_id, config.tenant_namespace, label="osac.openshift.io/virtualnetwork-uuid"
        )
        result["vpc_b"] = {"id": vnet_b_id, "cidr": "10.204.0.0/16"}

        # no_peering: OSAC has no peering API
        result["tests"]["no_peering"] = {
            "passed": True,
            "message": "OSAC has no VPC peering API",
        }

        # no_cross_routes_a: Tenant A lists VNets — B's should not appear
        s, body = client.list_virtual_networks(token=token_a)
        if s == 200:
            items = body.get("items", [])
            b_names = [
                it.get("metadata", {}).get("name", "")
                for it in items
                if it.get("metadata", {}).get("name") == vnet_b_name
            ]
            if not b_names:
                result["tests"]["no_cross_routes_a"] = {
                    "passed": True,
                    "message": "Tenant A cannot list Tenant B VNets",
                }
            else:
                result["tests"]["no_cross_routes_a"] = {
                    "passed": False,
                    "error": f"Tenant A can see Tenant B VNet: {b_names}",
                }
        else:
            result["tests"]["no_cross_routes_a"]["error"] = f"list failed HTTP {s}"

        # no_cross_routes_b: Tenant B lists VNets — A's should not appear
        s, body = client.list_virtual_networks(token=token_b)
        if s == 200:
            items = body.get("items", [])
            a_names = [
                it.get("metadata", {}).get("name", "")
                for it in items
                if it.get("metadata", {}).get("name") == vnet_a_name
            ]
            if not a_names:
                result["tests"]["no_cross_routes_b"] = {
                    "passed": True,
                    "message": "Tenant B cannot list Tenant A VNets",
                }
            else:
                result["tests"]["no_cross_routes_b"] = {
                    "passed": False,
                    "error": f"Tenant B can see Tenant A VNet: {a_names}",
                }
        else:
            result["tests"]["no_cross_routes_b"]["error"] = f"list failed HTTP {s}"

        # sg_isolation_a: Tenant A tries GET on VNet B — must get 403/404
        s, _ = client.get_virtual_network(vnet_b_id, token=token_a)
        result["tests"]["sg_isolation_a"] = {
            "passed": s in (401, 403, 404),
            "message": f"Tenant A GET of B's VNet returned HTTP {s}",
        }
        if s not in (401, 403, 404):
            result["tests"]["sg_isolation_a"]["error"] = f"Expected 401/403/404 but got {s}"

        # sg_isolation_b: Tenant B tries GET on VNet A — must get 403/404
        s, _ = client.get_virtual_network(vnet_a_id, token=token_b)
        result["tests"]["sg_isolation_b"] = {
            "passed": s in (401, 403, 404),
            "message": f"Tenant B GET of A's VNet returned HTTP {s}",
        }
        if s not in (401, 403, 404):
            result["tests"]["sg_isolation_b"]["error"] = f"Expected 401/403/404 but got {s}"

        result["success"] = all(t.get("passed") for t in result["tests"].values())

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
    finally:
        try:
            config = get_env_config()
            tc = TenantClient(config)

            if config.fulfillment_grpc_address:
                admin_token = get_admin_token(config)
                for vnet_id, tenant in (
                    (vnet_a_id, tenant_a_name),
                    (vnet_b_id, tenant_b_name),
                ):
                    if vnet_id and tenant:
                        try:
                            t = tc.get(tenant)
                            ns = t.get("status", {}).get("namespace", "")
                            if ns:
                                token, _ttl = create_sa_token(ns, "default")
                                FulfillmentClient(config, token).delete_virtual_network(vnet_id)
                        except Exception as e:
                            cleanup_errors.append(f"delete VNet for {tenant}: {e}")

                for t in (tenant_a_name, tenant_b_name):
                    if t:
                        try:
                            grpcurl_call(
                                config.fulfillment_grpc_address,
                                "osac.private.v1.Tenants/Delete",
                                {"id": t},
                                admin_token,
                                verify_ssl=config.verify_ssl,
                            )
                        except Exception as e:
                            cleanup_errors.append(f"delete fulfillment tenant {t}: {e}")

            for t in (tenant_a_name, tenant_b_name):
                if t:
                    try:
                        tc.delete(t)
                    except Exception as e:
                        cleanup_errors.append(f"delete tenant CRD {t}: {e}")
        except Exception as e:
            cleanup_errors.append(f"cleanup setup: {e}")

    if cleanup_errors:
        result["cleanup_errors"] = cleanup_errors

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
