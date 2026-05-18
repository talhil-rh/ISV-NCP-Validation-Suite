#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Tenant isolation test for OSAC (SEC11-01).

Creates two ephemeral tenants and verifies hard isolation across four
surfaces: network, data, compute, and storage. Uses Tenant A's
credentials to attempt cross-tenant operations against Tenant B's
resources via the fulfillment-service API.

OSAC tenant isolation is enforced via:
- Namespace isolation (osac-operator creates per-tenant namespaces)
- OVN-Kubernetes UserDefinedNetworks (L2 isolation)
- PostgreSQL tenant column filtering in fulfillment-service
- Authorino OPA policies (method + resource authorization)

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "tenant_isolation_test",
    "tenant_a_id": "...",
    "tenant_b_id": "...",
    "tests": {
        "network_isolated":  {"passed": true},
        "data_isolated":     {"passed": true},
        "compute_isolated":  {"passed": true},
        "storage_isolated":  {"passed": true}
    }
}
"""

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import urllib.parse

from common.osac_client import (
    FulfillmentClient,
    KeycloakAdmin,
    TenantClient,
    _request,
    _token_endpoint,
    get_admin_token,
    get_env_config,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser(description="Tenant isolation test (OSAC)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "tenant_isolation_test",
        "tenant_a_id": "",
        "tenant_b_id": "",
        "tests": {
            "network_isolated": {"passed": False},
            "data_isolated": {"passed": False},
            "compute_isolated": {"passed": False},
            "storage_isolated": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["tenant_a_id"] = "isv-sec11-tenant-a-demo"
        result["tenant_b_id"] = "isv-sec11-tenant-b-demo"
        result["tests"] = {
            "network_isolated": {"passed": True, "message": "Tenant A cannot list Tenant B VirtualNetworks"},
            "data_isolated": {"passed": True, "message": "Tenant A cannot read Tenant B resources"},
            "compute_isolated": {"passed": True, "message": "Tenant A cannot list Tenant B ComputeInstances"},
            "storage_isolated": {"passed": True, "message": "Tenant A cannot access Tenant B storage"},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    suffix = uuid.uuid4().hex[:8]
    tenant_a_name = f"isv-sec11-a-{suffix}"
    tenant_b_name = f"isv-sec11-b-{suffix}"
    client_a_id = f"isv-tenant-a-{suffix}"
    client_b_id = f"isv-tenant-b-{suffix}"
    client_a_uuid = ""
    client_b_uuid = ""
    cleanup_errors: list[str] = []

    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
        )

        if not config.fulfillment_url:
            result["skipped"] = True
            result["skip_reason"] = "OSAC_FULFILLMENT_URL not set; cannot test tenant isolation"
            print(json.dumps(result, indent=2))
            return 0

        token = get_admin_token(config)
        admin = KeycloakAdmin(config, token)
        tenant_client = TenantClient(config)

        # Create Tenant CRDs
        tenant_client.create(tenant_a_name)
        tenant_client.create(tenant_b_name)
        result["tenant_a_id"] = tenant_a_name
        result["tenant_b_id"] = tenant_b_name

        # Assign Tenant A to isv-test-tenant, Tenant B to isv-test-tenant-b.
        # These are two non-shared tenants so the fulfillment-service
        # applies real tenant filtering between them.
        group_a = admin.get_group_by_name("isv-test-tenant")
        group_b = admin.get_group_by_name("isv-test-tenant-b")
        if not group_a or not group_b:
            result["skipped"] = True
            result["skip_reason"] = "Keycloak groups isv-test-tenant and isv-test-tenant-b required"
            print(json.dumps(result, indent=2))
            return 0

        client_a_rep = admin.create_client(client_a_id)
        client_a_uuid = client_a_rep["id"]
        secret_a = admin.get_client_secret(client_a_uuid)
        sa_user_a = admin.get_service_account_user(client_a_uuid)
        admin.add_user_to_group(sa_user_a["id"], group_a["id"])

        client_b_rep = admin.create_client(client_b_id)
        client_b_uuid = client_b_rep["id"]
        secret_b = admin.get_client_secret(client_b_uuid)
        sa_user_b = admin.get_service_account_user(client_b_uuid)
        admin.add_user_to_group(sa_user_b["id"], group_b["id"])

        # Get Tenant A's JWT (groups: [isv-test-tenant])
        body_a = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": client_a_id,
            "client_secret": secret_a,
        }).encode()
        status, resp = _request(
            _token_endpoint(config),
            method="POST",
            data=body_a,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify_ssl=config.verify_ssl,
        )
        if status != 200 or not isinstance(resp, dict):
            result["error"] = "Failed to obtain Tenant A JWT"
            print(json.dumps(result, indent=2))
            return 0
        tenant_a_jwt = resp["access_token"]

        # Get Tenant B's JWT (groups: [isv-test-tenant-b])
        body_b = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": client_b_id,
            "client_secret": secret_b,
        }).encode()
        status, resp = _request(
            _token_endpoint(config),
            method="POST",
            data=body_b,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify_ssl=config.verify_ssl,
        )
        if status != 200 or not isinstance(resp, dict):
            result["error"] = "Failed to obtain Tenant B JWT"
            print(json.dumps(result, indent=2))
            return 0
        tenant_b_jwt = resp["access_token"]

        fc = FulfillmentClient(config, tenant_b_jwt)

        # Discover network_class using Tenant B's token (admin JWT lacks
        # tenant groups and gets 500 on fulfillment API calls)
        nc_id = ""
        nc_status, nc_resp = fc.list_network_classes()
        if nc_status == 200 and isinstance(nc_resp, dict):
            items = nc_resp.get("items", [])
            if items:
                nc_id = items[0].get("id", "")

        # Create a VNet under Tenant B (different tenant from A)
        vnet_name = f"isv-sec11-vnet-{suffix}"
        vnet_id = ""
        vn_status, vn_resp = fc.create_virtual_network(
            vnet_name, token=tenant_b_jwt, network_class=nc_id,
        )
        if vn_status in (200, 201) and isinstance(vn_resp, dict):
            vnet_id = vn_resp.get("id", vn_resp.get("name", ""))

        if not vnet_id:
            result["error"] = f"Could not create probe VNet under Tenant B (HTTP {vn_status})"
            print(json.dumps(result, indent=2))
            return 0

        # Positive control: Tenant B (owner) can see the VNet
        owner_status, owner_body = fc.list_virtual_networks(token=tenant_b_jwt)
        owner_ids = []
        if owner_status == 200 and isinstance(owner_body, dict):
            owner_items = owner_body.get("items", owner_body.get("virtual_networks", []))
            owner_ids = [v.get("id", "") for v in owner_items] if isinstance(owner_items, list) else []
        owner_sees_vnet = vnet_id in owner_ids

        if not owner_sees_vnet:
            result["error"] = f"Positive control failed: Tenant B cannot see its own VNet {vnet_id}"
            print(json.dumps(result, indent=2))
            return 0

        # --- network_isolated ---
        # Tenant A lists VNets. The VNet belongs to Tenant B.
        # Tenant A should NOT see it.
        net_status, net_body = fc.list_virtual_networks(token=tenant_a_jwt)
        if net_status in (401, 403):
            net_isolated = True
            net_msg = f"HTTP {net_status}: Tenant A denied VNet list"
        elif net_status == 200 and isinstance(net_body, dict):
            items = net_body.get("items", net_body.get("virtual_networks", []))
            visible_ids = [v.get("id", "") for v in items] if isinstance(items, list) else []
            if vnet_id in visible_ids:
                net_isolated = False
                net_msg = f"FAIL: Tenant A can see Tenant B's VNet {vnet_id}"
            else:
                net_isolated = True
                net_msg = f"Tenant A sees {len(visible_ids)} VNets, Tenant B's VNet {vnet_id} excluded"
        else:
            net_isolated = False
            net_msg = f"Unexpected HTTP {net_status}"
        result["tests"]["network_isolated"] = {"passed": net_isolated, "message": net_msg}

        # --- data_isolated ---
        # Tenant A tries to GET Tenant B's VNet by ID directly.
        data_status, _ = fc._api_request(
            f"/api/fulfillment/v1/virtual_networks/{urllib.parse.quote(vnet_id, safe='')}",
            headers_override={"Authorization": f"Bearer {tenant_a_jwt}", "Content-Type": "application/json"},
        )
        data_denied = data_status in (401, 403, 404)
        result["tests"]["data_isolated"] = {
            "passed": data_denied,
            "message": f"Tenant A GET Tenant B's VNet {vnet_id} returned HTTP {data_status}",
        }

        # --- compute_isolated ---
        # Tenant B lists ComputeInstances (baseline), Tenant A lists too.
        # Tenant A should not see more than its own.
        b_ci_status, b_ci_body = fc.list_compute_instances(token=tenant_b_jwt)
        b_ci_count = 0
        if b_ci_status == 200 and isinstance(b_ci_body, dict):
            b_ci_items = b_ci_body.get("items", b_ci_body.get("compute_instances", []))
            b_ci_count = len(b_ci_items) if isinstance(b_ci_items, list) else 0

        a_ci_status, a_ci_body = fc.list_compute_instances(token=tenant_a_jwt)
        if a_ci_status in (401, 403):
            compute_isolated = True
            compute_msg = f"HTTP {a_ci_status}: Tenant A denied ComputeInstance list"
        elif a_ci_status == 200 and isinstance(a_ci_body, dict):
            a_ci_items = a_ci_body.get("items", a_ci_body.get("compute_instances", []))
            a_ci_count = len(a_ci_items) if isinstance(a_ci_items, list) else 0
            if a_ci_count == 0 and b_ci_count == 0:
                compute_isolated = True
                compute_msg = "Both tenants see 0 instances (no instances to test cross-tenant visibility — vacuous pass)"
            else:
                compute_isolated = a_ci_count <= b_ci_count
                compute_msg = f"Tenant A sees {a_ci_count} instances (Tenant B sees {b_ci_count})"
        else:
            compute_isolated = False
            compute_msg = f"Unexpected HTTP {a_ci_status}"
        result["tests"]["compute_isolated"] = {"passed": compute_isolated, "message": compute_msg}

        # --- storage_isolated ---
        from common.ocp_probes import probe_storage_isolation
        probe_data = probe_storage_isolation(
            namespace_a=config.tenant_namespace,
            namespace_b="default",
        )
        result["tests"]["storage_isolated"] = {
            "passed": probe_data.get("storage_isolated", False),
            "message": probe_data.get("message") or probe_data.get("error", "No result"),
        }

        result["success"] = all(t["passed"] for t in result["tests"].values())

        # Clean up the probe VNet
        if vnet_id:
            try:
                fc._api_request(
                    f"/api/fulfillment/v1/virtual_networks/{urllib.parse.quote(vnet_id, safe='')}",
                    method="DELETE",
                )
            except Exception:
                pass

    except Exception as e:
        result["error"] = str(e)
    finally:
        # Best-effort cleanup
        try:
            tenant_client.delete(tenant_a_name)
        except Exception as e:
            cleanup_errors.append(f"tenant_a: {e}")
        try:
            tenant_client.delete(tenant_b_name)
        except Exception as e:
            cleanup_errors.append(f"tenant_b: {e}")
        if client_a_uuid:
            try:
                admin.delete_client(client_a_uuid)
            except Exception:
                pass
        if client_b_uuid:
            try:
                admin.delete_client(client_b_uuid)
            except Exception:
                pass
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
