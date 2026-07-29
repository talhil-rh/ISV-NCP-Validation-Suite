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

"""Teardown for OSAC bare metal validation.

Best-effort cleanup:
1. DELETE the BareMetalInstance and poll until 404.
2. Delete the fulfillment-service Tenant record (via gRPC).
3. Delete the Kubernetes Tenant CRD.
4. Delete the storage-config Secret created by setup_tenant.py.

Cleanup failures are collected in ``cleanup_errors`` but do not fail the
step — teardown must be as robust as possible.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
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
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
DELETE_TIMEOUT = 300


def _poll_deleted(client: FulfillmentClient, bmi_id: str, timeout: int) -> bool:
    """Poll until GET returns 404. Returns True when confirmed deleted."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s, _ = client.get_bare_metal_instance(bmi_id)
        if s in (404, 410):
            return True
        time.sleep(5)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Bare metal teardown (OSAC)")
    parser.add_argument("--instance-id", default="", help="BareMetalInstance ID to delete")
    parser.add_argument("--tenant-name", default="")
    parser.add_argument("--tenant-namespace", default="")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "teardown",
    }

    if DEMO_MODE:
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    cleanup_errors: list[str] = []

    try:
        config = get_env_config(require_admin=False)

        # --- Delete the BareMetalInstance ---
        if args.instance_id and args.tenant_namespace:
            try:
                token, _ttl = create_sa_token(args.tenant_namespace, "default")
                client = FulfillmentClient(config, token)

                s, _ = client.delete_bare_metal_instance(args.instance_id)
                if s in (200, 202, 204, 404):
                    if not _poll_deleted(client, args.instance_id, DELETE_TIMEOUT):
                        cleanup_errors.append(
                            f"BareMetalInstance {args.instance_id} not confirmed deleted within {DELETE_TIMEOUT}s"
                        )
                else:
                    cleanup_errors.append(f"DELETE BareMetalInstance {args.instance_id} returned HTTP {s}")
            except Exception as e:
                cleanup_errors.append(f"delete BareMetalInstance: {e}")

        # --- Delete fulfillment Tenant (gRPC) ---
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

        # --- Delete Kubernetes Tenant CRD ---
        if args.tenant_name:
            try:
                TenantClient(config).delete(args.tenant_name)
            except Exception as e:
                cleanup_errors.append(f"delete tenant CRD: {e}")

        # --- Delete storage-config Secret ---
        if args.tenant_name:
            try:
                kubectl = shutil.which("kubectl") or shutil.which("oc") or "kubectl"
                subprocess.run(
                    [
                        kubectl,
                        "delete",
                        "secret",
                        f"vast-tenant-config-{args.tenant_name}",
                        "-n",
                        config.tenant_namespace,
                        "--ignore-not-found",
                    ],
                    capture_output=True,
                    timeout=15,
                )
            except Exception as e:
                cleanup_errors.append(f"delete storage secret: {e}")

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
