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

"""Launch a BareMetalInstance for OSAC validation (CNP01-05..08, CNP05-01, CNP08-01).

Setup step: generates an ephemeral Ed25519 SSH key pair, POSTs a
BareMetalInstance with ``auto_external_ip_attachment=True`` so the instance
is reachable post-provisioning, and polls until ``status.state == RUNNING``.

Emits ``instance_id``, ``state``, ``key_file``, and ``external_ip`` for
downstream test steps.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import FulfillmentClient, create_sa_token, get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
RUN_STRATEGY_ALWAYS = "BARE_METAL_INSTANCE_RUN_STRATEGY_ALWAYS"
POLL_TIMEOUT = 1800


def _get_external_host_id(bmi_id: str, operator_ns: str) -> str:
    """Return the BareMetalHost externalHostID for a BareMetalInstance, or empty string.

    The BMI CRD stores the assigned BMH as ``spec.externalHostID`` in the form
    ``<namespace>/<bmh-name>`` (e.g. ``host-inventory/virtual-bmh-caas-1``).
    Returns empty string on any failure so callers can treat it as non-fatal.
    """
    try:
        kubectl = shutil.which("kubectl") or shutil.which("oc")
        if not kubectl:
            return ""
        label = f"osac.openshift.io/baremetalinstance-uuid={bmi_id}"
        r = subprocess.run(
            [
                kubectl,
                "get",
                "baremetalinstance",
                "-n",
                operator_ns,
                f"-l={label}",
                "-o=jsonpath={.items[0].spec.externalHostID}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def generate_ssh_key(key_dir: str) -> tuple[str, str]:
    """Generate an Ed25519 SSH key pair in *key_dir*.

    Returns ``(private_key_path, public_key_content)``.
    """
    key_path = os.path.join(key_dir, "osac_bmi_key")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key_path],
        capture_output=True,
        timeout=30,
        check=True,
    )
    with open(f"{key_path}.pub") as fh:
        pub_key = fh.read().strip()
    return key_path, pub_key


def extract_external_ip(body: dict[str, Any]) -> str | None:
    """Return the external/public IP from a BMI status dict, or None."""
    status = body.get("status", {})
    for field in ("external_ip", "externalIp", "public_ip", "publicIp"):
        ip = status.get(field)
        if ip:
            return str(ip)
    for attachment in status.get("network_attachments", []):
        for field in ("external_ip", "public_ip"):
            ip = attachment.get(field)
            if ip:
                return str(ip)
    return None


def get_bmh_ip(bmi_id: str, operator_namespace: str = "osac-e2e-ci") -> str | None:
    """Look up the NIC IP from the BareMetalHost assigned to this BareMetalInstance.

    The BMF operator creates a BareMetalInstance CRD named ``bmi-<fulfillment-id>``
    whose ``spec.externalHostID`` is ``<namespace>/<bmh-name>``.  The BMH's
    ``status.hardware.nics`` list contains the discovered IP addresses.
    """
    try:
        import shutil

        kubectl = shutil.which("kubectl") or shutil.which("oc")
        if not kubectl:
            return None

        crd_name = f"bmi-{bmi_id}"
        r = subprocess.run(
            [
                kubectl,
                "get",
                "baremetalinstance",
                crd_name,
                "-n",
                operator_namespace,
                "-o",
                "jsonpath={.spec.externalHostID}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return None

        external_host_id = r.stdout.strip()  # e.g. "host-inventory/virtual-bmh-caas-2"
        parts = external_host_id.split("/", 1)
        if len(parts) != 2:
            return None
        bmh_namespace, bmh_name = parts

        r2 = subprocess.run(
            [
                kubectl,
                "get",
                "baremetalhost",
                bmh_name,
                "-n",
                bmh_namespace,
                "-o",
                "jsonpath={.status.hardware.nics[0].ip}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        ip = r2.stdout.strip()
        return ip if ip else None
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch BareMetalInstance (OSAC)")
    # --catalog-item removed: ID is auto-discovered via the fulfillment API,
    # or overridden with OSAC_CATALOG_ITEM env var.
    parser.add_argument("--tenant-namespace", default="", help="K8s namespace for SA token")
    parser.add_argument("--subnet", default="", help="Optional Subnet ID for network attachment")
    parser.add_argument("--region", default="")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "launch_instance",
        "instance_id": "",
        "state": "",
        "instance_type": os.environ.get("OSAC_CATALOG_ITEM", ""),
        "external_ip": "",
        "key_file": "",
        # public_ip / private_ip must be strings (not null) per the "instance" output schema
        "public_ip": "",
        "private_ip": "",
        # Stable identifier across reinstall: the BMH name assigned to this instance
        "bmh_id": "",
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "instance_id": "demo-bmi-001",
                "state": "running",
                "external_ip": "192.0.2.1",
                "key_file": "/tmp/demo-bmi.pem",
                "public_ip": "192.0.2.1",
                "private_ip": "",
                "bmh_id": "host-inventory/virtual-bmh-caas-demo",
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    # catalog_item is resolved at runtime if not explicitly provided
    if not args.tenant_namespace:
        result["error"] = "--tenant-namespace is required"
        print(json.dumps(result, indent=2))
        return 1

    # mkdtemp keeps the directory alive after the script exits so that
    # subsequent test steps can read the private key via the stored path.
    key_dir = tempfile.mkdtemp(prefix="osac-bmi-")
    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)

        # Resolve catalog item: use explicit arg/env value, else discover from API
        catalog_item_id = os.environ.get("OSAC_CATALOG_ITEM", "") or client.get_baremetal_catalog_item_id()
        result["instance_type"] = catalog_item_id

        # Generate SSH key pair for this run
        key_file, pub_key = generate_ssh_key(key_dir)
        result["key_file"] = key_file

        suffix = f"{int(time.time()) % 0xFFFF:04x}"
        bmi_name = f"isv-bm-{suffix}"

        body: dict[str, Any] = {
            "metadata": {
                "name": bmi_name,
                "labels": {"name": "osac-bm-validation", "created-by": "isv-validation"},
            },
            "spec": {
                "catalog_item": {"id": catalog_item_id},
                "ssh_public_key": pub_key,
                "auto_external_ip_attachment": True,
                "run_strategy": RUN_STRATEGY_ALWAYS,
            },
        }
        if args.subnet:
            body["spec"]["network_attachments"] = [{"subnet": {"id": args.subnet}}]

        status, resp = client.create_bare_metal_instance(body)
        if status not in (200, 201):
            result["error"] = f"Create BareMetalInstance failed (HTTP {status}): {resp}"
            print(json.dumps(result, indent=2))
            return 1

        bmi_id = resp["id"]
        result["instance_id"] = bmi_id

        # Poll until the instance is running
        final_body = client.wait_bare_metal_instance_state(bmi_id, "running", timeout=POLL_TIMEOUT)
        raw_state = final_body.get("status", {}).get("state", "")
        result["state"] = raw_state.lower().removeprefix("bare_metal_instance_state_")

        # Try fulfillment API status first, fall back to BMH NIC IP from K8s
        external_ip = extract_external_ip(final_body) or get_bmh_ip(bmi_id) or ""
        result["external_ip"] = external_ip
        result["public_ip"] = external_ip
        result["success"] = True

        # Look up the assigned BMH name — stable identifier for reinstall checks.
        # Non-fatal: leave bmh_id as "" if oc is not available or the CRD is not
        # yet visible (the externalHostID is set during inventory allocation which
        # completes before RUNNING, but oc may not be on PATH in all environments).
        result["bmh_id"] = _get_external_host_id(bmi_id, config.tenant_namespace)

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
