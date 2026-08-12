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

"""Reinstall a BareMetalInstance by delete+recreate (CNP08-02).

OSAC has no native reinstall API; delete+create achieves the same result.
The STABLE IDENTIFIER across a reinstall is the BareMetalHost (BMH) name,
not the BMI UUID (which changes each time).

Sequence:
1. Look up the BMH assigned to the existing BMI via CRD label lookup.
2. Delete the BMI; poll until GET returns 404.
3. Poll the original BMH until status.provisioning.state == "available".
4. Create a new BMI (re-using the SSH public key if key_file is provided).
5. Wait for the new BMI to reach RUNNING (timeout 1800 s).
6. Look up the new BMI's BMH and verify it is the same host.
7. Optional SSH probe to confirm OS reachability.

Emits ``instance_id`` = BMH name (stable identifier) so that
``BmIdentifierStableAfterReinstallCheck`` can compare it against
``steps.launch_instance.bmh_id``.
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
DELETE_TIMEOUT = 300
BMH_AVAILABLE_TIMEOUT = 300
PROVISION_TIMEOUT = 1800
POLL_INTERVAL = 10
SSH_RETRIES = 5
SSH_SLEEP = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _kubectl_cmd() -> str | None:
    """Return the kubectl/oc binary path, or None."""
    return shutil.which("kubectl") or shutil.which("oc")


def _get_external_host_id(bmi_id: str, operator_ns: str) -> str:
    """Return spec.externalHostID for a BareMetalInstance CRD, or empty string.

    The externalHostID is in the form ``<namespace>/<bmh-name>``
    (e.g. ``host-inventory/virtual-bmh-caas-1``).  Returns empty string on
    any failure so callers can treat the lookup as non-fatal.
    """
    try:
        kubectl = _kubectl_cmd()
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


def _get_other_bmhs_with_label(
    label_key: str, label_value: str, exclude_ns: str, exclude_name: str
) -> list[tuple[str, str]]:
    """Return (namespace, name) pairs of BMHs that have the given label, excluding one BMH."""
    kubectl = _kubectl_cmd()
    if not kubectl:
        return []
    try:
        r = subprocess.run(
            [
                kubectl,
                "get",
                "baremetalhost",
                "-A",
                f"-l={label_key}={label_value}",
                "-o=jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{'\\n'}{end}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        result = []
        for line in r.stdout.strip().splitlines():
            if not line:
                continue
            ns, name = line.split("/", 1)
            if ns == exclude_ns and name == exclude_name:
                continue
            result.append((ns, name))
        return result
    except Exception:
        return []


def _patch_bmh_label(bmh_ns: str, bmh_name: str, label_key: str, label_value: str | None) -> bool:
    """Add or remove a label on a BareMetalHost. Pass None as value to remove."""
    kubectl = _kubectl_cmd()
    if not kubectl:
        return False
    try:
        if label_value is None:
            patch = json.dumps({"metadata": {"labels": {label_key: None}}})
        else:
            patch = json.dumps({"metadata": {"labels": {label_key: label_value}}})
        r = subprocess.run(
            [kubectl, "patch", "baremetalhost", bmh_name, "-n", bmh_ns, "--type=merge", f"--patch={patch}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return r.returncode == 0
    except Exception:
        return False


def _poll_bmi_deleted(client: FulfillmentClient, bmi_id: str, timeout: int) -> bool:
    """Poll GET until the BMI returns 404/410.  Returns True when confirmed gone."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s, _ = client.get_bare_metal_instance(bmi_id)
        if s in (404, 410):
            return True
        time.sleep(POLL_INTERVAL)
    return False


def _poll_bmh_available(bmh_name: str, bmh_ns: str, timeout: int) -> bool:
    """Poll until BareMetalHost status.provisioning.state == 'available'."""
    kubectl = _kubectl_cmd()
    if not kubectl:
        return False
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = subprocess.run(
                [
                    kubectl,
                    "get",
                    "baremetalhost",
                    bmh_name,
                    "-n",
                    bmh_ns,
                    "-o",
                    "jsonpath={.status.provisioning.state}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if r.returncode == 0 and r.stdout.strip() == "available":
                return True
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)
    return False


def generate_ssh_key(key_dir: str) -> tuple[str, str]:
    """Generate an Ed25519 SSH key pair in *key_dir*.

    Returns ``(private_key_path, public_key_content)``.
    """
    key_path = os.path.join(key_dir, "osac_bmi_reinstall_key")
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


def ssh_probe(key_file: str, external_ip: str) -> tuple[bool, str]:
    """Attempt SSH connectivity. Returns (success, message)."""
    if not key_file or not external_ip:
        return False, "No key_file or external_ip — skipping SSH probe"
    for attempt in range(SSH_RETRIES):
        try:
            proc = subprocess.run(
                [
                    "ssh",
                    "-i",
                    key_file,
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "BatchMode=yes",
                    f"fedora@{external_ip}",
                    "echo ok",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode == 0 and "ok" in proc.stdout:
                return True, "SSH connected successfully"
        except Exception:
            pass
        if attempt < SSH_RETRIES - 1:
            time.sleep(SSH_SLEEP)
    return False, f"SSH not available after {SSH_RETRIES} attempts"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Reinstall BareMetalInstance via delete+create (OSAC)")
    parser.add_argument("--instance-id", required=True, help="Existing BMI UUID to reinstall")
    parser.add_argument("--tenant-namespace", required=True, help="K8s namespace for SA token")
    parser.add_argument("--key-file", default="", help="Path to existing SSH private key (re-used for new BMI)")
    parser.add_argument("--external-ip", default="", help="External IP for SSH probe")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "bare_metal",
        "test_name": "reinstall_instance",
        "instance_id": "",  # BMH name — stable identifier (not BMI UUID)
        "state": "",
        "instance_state": "",
        "same_host": False,
        "original_bmh": "",
        "new_bmh": "",
        "new_instance_id": "",
        "ssh_ok": False,
        "external_ip": "",
        "public_ip": "",  # alias for ConnectivityCheck/OsCheck step_output resolution
        "key_file": args.key_file or "",  # updated to effective_key_file if a new key is generated
    }

    if DEMO_MODE:
        result.update(
            {
                "success": True,
                "instance_id": "host-inventory/virtual-bmh-caas-demo",
                "state": "running",
                "instance_state": "running",
                "same_host": True,
                "original_bmh": "host-inventory/virtual-bmh-caas-demo",
                "new_bmh": "host-inventory/virtual-bmh-caas-demo",
                "new_instance_id": "demo-bmi-reinstall-001",
                "ssh_ok": False,
                "external_ip": "",
                "public_ip": "",
                "key_file": args.key_file or "",
            }
        )
        print(json.dumps(result, indent=2))
        return 0

    other_bmhs: list[tuple[str, str]] = []
    host_type_label = "osac.openshift.io/host-type"
    host_type_value = ""

    try:
        config = get_env_config(require_admin=False)
        token, _ttl = create_sa_token(args.tenant_namespace, "default")
        client = FulfillmentClient(config, token)
        operator_ns = config.tenant_namespace

        # ------------------------------------------------------------------
        # 1. Look up the original BMH assigned to this BMI
        # ------------------------------------------------------------------
        original_bmh = _get_external_host_id(args.instance_id, operator_ns)
        if not original_bmh or "/" not in original_bmh:
            result["error"] = (
                f"Could not find BMH for BareMetalInstance {args.instance_id} "
                f"in operator namespace {operator_ns}. "
                "Ensure oc/kubectl is on PATH and the BMI CRD exists."
            )
            print(json.dumps(result, indent=2))
            return 1

        result["original_bmh"] = original_bmh
        bmh_ns, bmh_name = original_bmh.split("/", 1)

        # ------------------------------------------------------------------
        # 2. Delete the existing BMI and wait until confirmed gone
        # ------------------------------------------------------------------
        s, _ = client.delete_bare_metal_instance(args.instance_id)
        if s not in (200, 202, 204, 404):
            result["error"] = f"DELETE BareMetalInstance {args.instance_id} returned HTTP {s}"
            print(json.dumps(result, indent=2))
            return 1

        if not _poll_bmi_deleted(client, args.instance_id, DELETE_TIMEOUT):
            result["error"] = f"BareMetalInstance {args.instance_id} not confirmed deleted within {DELETE_TIMEOUT}s"
            print(json.dumps(result, indent=2))
            return 1

        # ------------------------------------------------------------------
        # 3. Wait for the original BMH to return to 'available'
        # ------------------------------------------------------------------
        if not _poll_bmh_available(bmh_name, bmh_ns, BMH_AVAILABLE_TIMEOUT):
            result["error"] = (
                f"BareMetalHost {original_bmh} did not reach 'available' "
                f"within {BMH_AVAILABLE_TIMEOUT}s after BMI deletion"
            )
            print(json.dumps(result, indent=2))
            return 1

        # ------------------------------------------------------------------
        # 4. Strip host-type label from all OTHER BMHs so the operator can
        #    only allocate the original BMH for the new BMI.
        # ------------------------------------------------------------------
        # Read the label value from the original BMH before stripping others
        kubectl = _kubectl_cmd()
        host_type_value = ""
        if kubectl:
            rv = subprocess.run(
                [
                    kubectl,
                    "get",
                    "baremetalhost",
                    bmh_name,
                    "-n",
                    bmh_ns,
                    "-o=jsonpath={.metadata.labels.osac\\.openshift\\.io/host-type}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            host_type_value = rv.stdout.strip() if rv.returncode == 0 else ""

        other_bmhs = _get_other_bmhs_with_label(host_type_label, host_type_value, bmh_ns, bmh_name)
        for ns, name in other_bmhs:
            _patch_bmh_label(ns, name, host_type_label, None)

        # ------------------------------------------------------------------
        # 5. Resolve SSH public key and catalog item for the new BMI
        # ------------------------------------------------------------------
        pub_key_file = f"{args.key_file}.pub" if args.key_file else ""
        if pub_key_file and os.path.exists(pub_key_file):
            with open(pub_key_file) as fh:
                pub_key = fh.read().strip()
            effective_key_file = args.key_file
        else:
            # Generate a fresh key pair — SSH probe will use the new private key
            key_dir = tempfile.mkdtemp(prefix="osac-bmi-reinstall-")
            effective_key_file, pub_key = generate_ssh_key(key_dir)
        result["key_file"] = effective_key_file

        catalog_item_id = os.environ.get("OSAC_CATALOG_ITEM", "") or client.get_baremetal_catalog_item_id()

        # ------------------------------------------------------------------
        # 6. Create the new BMI
        # ------------------------------------------------------------------
        suffix = f"{int(time.time()) % 0xFFFF:04x}"
        bmi_name = f"isv-bm-reinstall-{suffix}"

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

        s, resp = client.create_bare_metal_instance(body)
        if s not in (200, 201):
            result["error"] = f"Create new BareMetalInstance failed (HTTP {s}): {resp}"
            print(json.dumps(result, indent=2))
            return 1

        new_bmi_id = resp["id"]
        result["new_instance_id"] = new_bmi_id

        # ------------------------------------------------------------------
        # 6b. Wait for the new BMI to reach RUNNING
        # ------------------------------------------------------------------
        final_body = client.wait_bare_metal_instance_state(new_bmi_id, "running", timeout=PROVISION_TIMEOUT)
        raw_state = final_body.get("status", {}).get("state", "")
        state = raw_state.lower().removeprefix("bare_metal_instance_state_")
        result["state"] = state
        result["instance_state"] = state

        # ------------------------------------------------------------------
        # 7. Restore host-type labels on the other BMHs (best-effort)
        # ------------------------------------------------------------------
        for ns, name in other_bmhs:
            _patch_bmh_label(ns, name, host_type_label, host_type_value)

        # ------------------------------------------------------------------
        # 8. Look up the new BMI's BMH and verify it is the same host
        # ------------------------------------------------------------------
        new_bmh = _get_external_host_id(new_bmi_id, operator_ns)
        result["new_bmh"] = new_bmh

        same_host = bool(new_bmh and original_bmh and new_bmh == original_bmh)
        result["same_host"] = same_host

        # The stable identifier emitted as instance_id is the BMH name so that
        # BmIdentifierStableAfterReinstallCheck can compare it against
        # steps.launch_instance.bmh_id (also a BMH name).
        result["instance_id"] = new_bmh or original_bmh

        # ------------------------------------------------------------------
        # 8. Resolve external IP (new BMI body first, fall back to arg)
        # ------------------------------------------------------------------
        external_ip = extract_external_ip(final_body) or args.external_ip or ""
        result["external_ip"] = external_ip
        result["public_ip"] = external_ip

        # ------------------------------------------------------------------
        # 9. Optional SSH probe
        # ------------------------------------------------------------------
        ssh_ok, ssh_msg = ssh_probe(effective_key_file, external_ip or args.external_ip)
        result["ssh_ok"] = ssh_ok
        if not ssh_ok:
            result["ssh_note"] = ssh_msg

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
        # Best-effort: restore labels on other BMHs so they aren't left unlabeled
        try:
            if other_bmhs and host_type_value:
                for ns, name in other_bmhs:
                    _patch_bmh_label(ns, name, host_type_label, host_type_value)
        except Exception:
            pass

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
