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

"""Create an ephemeral tenant for network tests.

Setup step that registers a fulfillment-service Tenant (via gRPC — this
resource is not exposed on the REST gateway) using a real onboarding flow:
this triggers IDP sync and the osac-operator auto-provisions a matching
Kubernetes Tenant CRD, labeled namespace, and OVN UserDefinedNetwork within
seconds. Fulfillment API calls then authenticate as the Kubernetes
ServiceAccount in that namespace: the fulfillment-service gRPC server
trusts the in-cluster Kubernetes API server as a JWT issuer and resolves
the tenant from the SA token's `system:serviceaccount:<namespace>:<name>`
subject.

Requires OSAC_ADMIN_CLIENT_ID/OSAC_ADMIN_CLIENT_SECRET to reference a
Keycloak client with fulfillment-service admin privileges (an "emergency
service account" per the gRPC server's `--emergency-service-accounts`
flag) — not the ephemeral, Keycloak-realm-management-scoped client that
`bootstrap_admin.py` creates for other OSAC domains. Also requires
OSAC_FULFILLMENT_GRPC_ADDRESS (host:port of the fulfillment gRPC server)
and the `grpcurl` CLI on PATH.
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
    TenantClient,
    get_admin_token,
    get_env_config,
    grpcurl_call,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
POLL_INTERVAL = 2
POLL_TIMEOUT = 60


def main() -> int:
    parser = argparse.ArgumentParser(description="Setup network test tenant (OSAC)")
    parser.add_argument("--region", required=True)
    parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "network",
        "test_name": "setup_tenant",
        "tenant_name": "",
        "tenant_namespace": "",
    }

    if DEMO_MODE:
        result["success"] = True
        result["tenant_name"] = "isv-net-tenant-demo"
        result["tenant_namespace"] = "isv-net-tenant-demo"
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config()
        if not config.fulfillment_grpc_address:
            raise RuntimeError("OSAC_FULFILLMENT_GRPC_ADDRESS is required")
        admin_token = get_admin_token(config)

        suffix = f"{int(time.time()) % 0xFFFF:04x}"
        tenant_name = f"isv-net-tenant-{suffix}"
        domain = f"{suffix}.isv-net-test.local"

        grpcurl_call(
            config.fulfillment_grpc_address,
            "osac.private.v1.Tenants/Create",
            {"object": {"metadata": {"name": tenant_name}, "spec": {"domains": [domain]}}},
            admin_token,
            verify_ssl=config.verify_ssl,
        )
        result["tenant_name"] = tenant_name

        # osac-operator auto-provisions a matching K8s Tenant CRD + labeled
        # namespace once the fulfillment Tenant syncs to the IDP.
        tc = TenantClient(config)
        deadline = time.time() + POLL_TIMEOUT
        namespace = ""
        while time.time() < deadline:
            try:
                tenant = tc.get(tenant_name)
                namespace = tenant.get("status", {}).get("namespace", "")
            except RuntimeError:
                namespace = ""
            if namespace:
                break
            time.sleep(POLL_INTERVAL)

        if not namespace:
            result["error"] = f"Tenant '{tenant_name}' namespace not provisioned within {POLL_TIMEOUT}s"
            print(json.dumps(result, indent=2))
            return 1

        result["tenant_namespace"] = namespace

        # WORKAROUND: Create the storage-config secret that the storage operator
        # checks for when provisioning compute instance volumes per tenant. Remove
        # this once the osac-operator auto-provisions tenant storage classes.
        secret_manifest = (
            f"apiVersion: v1\nkind: Secret\n"
            f"metadata:\n  name: vast-tenant-config-{tenant_name}\n"
            f"  namespace: {config.tenant_namespace}\n"
            f"  labels:\n    osac.openshift.io/tenant: {tenant_name}\n"
            f"stringData:\n  placeholder: 'true'\n"
        )
        kubectl = shutil.which("kubectl") or shutil.which("oc") or "kubectl"
        subprocess.run(
            [kubectl, "apply", "-f", "-"],
            input=secret_manifest,
            text=True,
            capture_output=True,
            timeout=15,
        )

        # Wait for the storage controller to detect the secret and populate
        # tenant.status.storageClasses — needed before compute instances can be provisioned.
        storage_deadline = time.time() + 60
        while time.time() < storage_deadline:
            probe = subprocess.run(
                [
                    kubectl,
                    "get",
                    "tenant",
                    tenant_name,
                    "-n",
                    config.tenant_namespace,
                    "-o",
                    "jsonpath={.status.storageClasses}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            sc = probe.stdout.strip()
            if sc and sc not in ("null", "[]", ""):
                break
            time.sleep(3)

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
