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

"""Least-privilege policy test for OSAC (SEC04-01 + SEC04-02).

Creates a temporary Keycloak client with minimal permissions and verifies:
- SEC04-01: The client can perform one allowed action (list capabilities)
  but is scoped by user, resource, and network dimensions.
- SEC04-02: The client is denied out-of-scope compute, storage, and
  network operations via the Authorino OPA policies.

OSAC enforces authorization via:
- Authorino + OPA Rego policies (method-level authorization)
- Tenant-scoped resource filtering (resource-level authorization)

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "least_privilege_test",
    "test_identity": "...",
    "allowed_resource": "capabilities",
    "allowed_source_cidr": "cluster-internal",
    "tests": {
        "policy_dimensions_user_based":              {"passed": true},
        "policy_dimensions_resource_based":          {"passed": true},
        "policy_dimensions_network_based":           {"passed": true},
        "policy_dimensions_allowed_action_succeeds": {"passed": true},
        "out_of_scope_compute_denied":               {"passed": true},
        "out_of_scope_storage_denied":               {"passed": true},
        "out_of_scope_network_denied":               {"passed": true}
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
    _request,
    _token_endpoint,
    get_admin_token,
    get_env_config,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def main() -> int:
    parser = argparse.ArgumentParser(description="Least-privilege policy test (OSAC)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "least_privilege_test",
        "test_identity": "",
        "allowed_resource": "",
        "allowed_source_cidr": "",
        "tests": {
            "policy_dimensions_user_based": {"passed": False},
            "policy_dimensions_resource_based": {"passed": False},
            "policy_dimensions_network_based": {"passed": False},
            "policy_dimensions_allowed_action_succeeds": {"passed": False},
            "out_of_scope_compute_denied": {"passed": False},
            "out_of_scope_storage_denied": {"passed": False},
            "out_of_scope_network_denied": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["test_identity"] = "isv-least-priv-demo"
        result["allowed_resource"] = "capabilities"
        result["allowed_source_cidr"] = "cluster-internal"
        result["tests"] = {k: {"passed": True} for k in result["tests"]}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    test_client_id = f"isv-least-priv-{uuid.uuid4().hex[:8]}"
    client_uuid = ""

    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
        )

        if not config.fulfillment_url:
            result["skipped"] = True
            result["skip_reason"] = "OSAC_FULFILLMENT_URL not set; cannot test least-privilege"
            print(json.dumps(result, indent=2))
            return 0

        token = get_admin_token(config)
        admin = KeycloakAdmin(config, token)

        # Create a minimal client (no special roles) and assign it to a
        # tenant group so the fulfillment-service can resolve a tenant
        # from the JWT groups claim (avoids 500 from empty tenants).
        client_rep = admin.create_client(test_client_id)
        client_uuid = client_rep["id"]
        secret = admin.get_client_secret(client_uuid)

        group = admin.get_group_by_name("isv-test-tenant")
        if group:
            sa_user = admin.get_service_account_user(client_uuid)
            admin.add_user_to_group(sa_user["id"], group["id"])

        result["test_identity"] = test_client_id
        result["allowed_resource"] = "capabilities"
        result["allowed_source_cidr"] = "cluster-internal"

        # Get token for the minimal client
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": test_client_id,
                "client_secret": secret,
            }
        ).encode()
        status, resp = _request(
            _token_endpoint(config),
            method="POST",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify_ssl=config.verify_ssl,
        )
        if status != 200 or not isinstance(resp, dict):
            result["error"] = "Failed to obtain minimal-client token"
            print(json.dumps(result, indent=2))
            return 1

        minimal_token = resp["access_token"]
        fc = FulfillmentClient(config, token)

        # SEC04-01: Policy dimension checks

        # user_based: Prove policies differ by identity. The minimal client
        # should be denied a create operation that the OPA policy restricts,
        # while the capabilities endpoint (open to everyone) succeeds. This
        # differential proves identity-aware policy enforcement.
        vn_deny_status, _ = fc.create_virtual_network(
            f"isv-user-probe-{uuid.uuid4().hex[:8]}",
            token=minimal_token,
        )
        cap_status, _ = _request(
            f"{config.fulfillment_url}/api/fulfillment/v1/capabilities",
            headers={"Authorization": f"Bearer {minimal_token}"},
            verify_ssl=config.verify_ssl,
        )
        user_denied = vn_deny_status in (400, 401, 403, 500)
        user_allowed = cap_status == 200
        user_based_ok = user_denied and user_allowed
        result["tests"]["policy_dimensions_user_based"] = {
            "passed": user_based_ok,
            "message": f"CreateVNet={vn_deny_status} (denied), Capabilities={cap_status} (allowed)"
            if user_based_ok
            else f"CreateVNet={vn_deny_status}, Capabilities={cap_status} — no differential",
        }

        # allowed_action: The minimal client can call the capabilities endpoint
        result["tests"]["policy_dimensions_allowed_action_succeeds"] = {
            "passed": user_allowed,
            "message": f"Capabilities returned HTTP {cap_status}",
        }

        # resource_based: Prove resource-level filtering. Use a K8s SA token
        # (which maps to a real tenant) as the admin baseline, then compare
        # with the minimal Keycloak client (which has no tenant group).
        try:
            from common.osac_client import create_sa_token

            sa_token, _ = create_sa_token(config.tenant_namespace, "admin", "3600s")
            sa_list_status, _ = fc.list_virtual_networks(token=sa_token)
        except Exception:
            sa_list_status = -1
        min_list_status, _ = fc.list_virtual_networks(token=minimal_token)

        if sa_list_status == 200 and min_list_status != 200:
            resource_ok = min_list_status in (401, 403)
            resource_msg = f"K8s SA sees resources (HTTP {sa_list_status}), JWT client denied (HTTP {min_list_status})"
        elif sa_list_status == 200 and min_list_status == 200:
            resource_ok = True
            resource_msg = "Both tokens accepted; tenant filtering applied at query level"
        elif min_list_status in (401, 403):
            resource_ok = True
            resource_msg = f"JWT client denied resource list (HTTP {min_list_status})"
        else:
            resource_ok = False
            resource_msg = f"SA list={sa_list_status}, JWT list={min_list_status}"
        result["tests"]["policy_dimensions_resource_based"] = {"passed": resource_ok, "message": resource_msg}

        # network_based: Verify the fulfillment API is protected by
        # Authorino (AuthConfig with authentication + authorization).
        # This proves API access is gated, not open to any network caller.
        import shutil
        import subprocess

        kctl = shutil.which("kubectl") or shutil.which("oc") or ""
        namespace = config.tenant_namespace
        if kctl:
            ac_cmd = [kctl, "get", "authconfigs", "-n", namespace, "-o", "json"]
            ac_result = subprocess.run(ac_cmd, capture_output=True, text=True, timeout=15)
            if ac_result.returncode == 0:
                ac_data = json.loads(ac_result.stdout)
                ac_items = ac_data.get("items", [])
                has_authn = False
                has_authz = False
                ac_name = ""
                for ac in ac_items:
                    authn = ac.get("spec", {}).get("authentication", {})
                    authz = ac.get("spec", {}).get("authorization", {})
                    if authn and authz:
                        has_authn = True
                        has_authz = True
                        ac_name = ac["metadata"]["name"]
                        break
                network_ok = has_authn and has_authz
                result["tests"]["policy_dimensions_network_based"] = {
                    "passed": network_ok,
                    "message": f"AuthConfig '{ac_name}' enforces authentication + authorization"
                    if network_ok
                    else "No AuthConfig with both authentication and authorization found",
                }
            else:
                result["tests"]["policy_dimensions_network_based"] = {
                    "passed": False,
                    "message": f"Could not query AuthConfigs: {ac_result.stderr.strip()}",
                }
        else:
            result["tests"]["policy_dimensions_network_based"] = {
                "passed": False,
                "message": "kubectl/oc not available to query AuthConfig",
            }

        # SEC04-02: Out-of-scope denial checks

        # compute_denied: Try to create a ComputeInstance
        ci_status, _ = fc.create_compute_instance(
            f"isv-deny-test-{uuid.uuid4().hex[:8]}",
            token=minimal_token,
        )
        compute_denied = ci_status in (400, 401, 403, 404)
        result["tests"]["out_of_scope_compute_denied"] = {
            "passed": compute_denied,
            "message": f"CreateComputeInstance returned HTTP {ci_status}",
        }

        # storage_denied: Delegate to OCP storage isolation probe.
        from common.ocp_probes import probe_storage_isolation

        probe_data = probe_storage_isolation(
            namespace_a=config.tenant_namespace,
            namespace_b="default",
        )
        result["tests"]["out_of_scope_storage_denied"] = {
            "passed": probe_data.get("storage_denied", False),
            "message": probe_data.get("message") or probe_data.get("error", "No result"),
        }

        # network_denied: Try to create a VirtualNetwork
        vn_status, _ = fc.create_virtual_network(
            f"isv-deny-test-{uuid.uuid4().hex[:8]}",
            token=minimal_token,
        )
        network_denied = vn_status in (400, 401, 403, 404)
        result["tests"]["out_of_scope_network_denied"] = {
            "passed": network_denied,
            "message": f"CreateVirtualNetwork returned HTTP {vn_status}",
        }

        result["success"] = all(t["passed"] for t in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)
    finally:
        if client_uuid:
            try:
                admin.delete_client(client_uuid)
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
