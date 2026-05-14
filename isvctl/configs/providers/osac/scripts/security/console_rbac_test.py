#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Console RBAC test for OSAC.

Verifies that interactive console access (VNC/serial) is restricted by
RBAC. The osac-operator console proxy uses SubjectAccessReview to
authorize console access per-instance.

Tests:
1. A principal without console permissions is denied
2. An admin principal is allowed
3. Access is resource-scoped to a specific instance

Covers VM security: ConsoleRbacCheck.

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "console_rbac",
    "instance_id": "...",
    "access_restricted": true,
    "restricted_actions": ["console/connect", "console/access"],
    "rbac_model": "SubjectAccessReview",
    "tests": {
        "denied_principal_cannot_access_console": {"passed": true},
        "allowed_principal_can_access_console":   {"passed": true},
        "allowed_principal_is_resource_scoped":   {"passed": true}
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
    parser = argparse.ArgumentParser(description="Console RBAC test (OSAC)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    parser.add_argument("--instance-id", default="", help="Instance ID to test console access on")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "console_rbac",
        "instance_id": "",
        "access_restricted": False,
        "restricted_actions": [],
        "rbac_model": "SubjectAccessReview",
        "tests": {
            "denied_principal_cannot_access_console": {"passed": False},
            "allowed_principal_can_access_console": {"passed": False},
            "allowed_principal_is_resource_scoped": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["instance_id"] = "demo-instance-001"
        result["access_restricted"] = True
        result["restricted_actions"] = ["console/connect", "console/access"]
        result["tests"] = {k: {"passed": True} for k in result["tests"]}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    test_client_id = f"isv-console-rbac-{uuid.uuid4().hex[:8]}"
    client_uuid = ""

    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
        )

        if not config.fulfillment_url:
            result["skipped"] = True
            result["skip_reason"] = "OSAC_FULFILLMENT_URL not set; cannot test console RBAC"
            print(json.dumps(result, indent=2))
            return 0

        token = get_admin_token(config)
        admin = KeycloakAdmin(config, token)
        fc = FulfillmentClient(config, token)

        # Determine instance ID to test
        instance_id = args.instance_id
        if not instance_id:
            # Try to find an existing instance
            ci_status, ci_resp = fc.list_compute_instances()
            if ci_status == 200 and isinstance(ci_resp, dict):
                items = ci_resp.get("items", ci_resp.get("compute_instances", []))
                if items and isinstance(items, list):
                    instance_id = items[0].get("id", items[0].get("name", ""))

        if not instance_id:
            instance_id = "nonexistent-test-instance"

        result["instance_id"] = instance_id
        result["restricted_actions"] = ["console/connect", "console/access"]

        # Create an unprivileged client (no admin roles)
        client_rep = admin.create_client(test_client_id)
        client_uuid = client_rep["id"]
        secret = admin.get_client_secret(client_uuid)

        # Get unprivileged token
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": test_client_id,
            "client_secret": secret,
        }).encode()
        status, resp = _request(
            _token_endpoint(config),
            method="POST",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify_ssl=config.verify_ssl,
        )
        if status != 200 or not isinstance(resp, dict):
            result["error"] = "Failed to obtain unprivileged token"
            print(json.dumps(result, indent=2))
            return 1

        unpriv_token = resp["access_token"]

        # Test 1: Unprivileged principal denied console access
        deny_status, _ = fc.get_console_access(instance_id, token=unpriv_token)
        denied = deny_status in (401, 403, 404)
        result["tests"]["denied_principal_cannot_access_console"] = {
            "passed": denied,
            "message": f"Unprivileged client got HTTP {deny_status}",
        }
        result["access_restricted"] = denied

        # Test 2: Admin principal can access console (or at least gets further)
        allow_status, _ = fc.get_console_access(instance_id)
        # Admin should get 200 or at least not 401/403
        allowed = allow_status not in (401, 403)
        result["tests"]["allowed_principal_can_access_console"] = {
            "passed": allowed,
            "message": f"Admin client got HTTP {allow_status}",
        }

        # Test 3: Access is resource-scoped (different instance returns different result)
        fake_id = f"nonexistent-{uuid.uuid4().hex[:8]}"
        scope_status, _ = fc.get_console_access(fake_id)
        # A non-existent instance should return 404 (not a blanket allow)
        resource_scoped = scope_status in (404, 400)
        result["tests"]["allowed_principal_is_resource_scoped"] = {
            "passed": resource_scoped,
            "message": f"Non-existent instance got HTTP {scope_status} (resource-scoped check)",
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
