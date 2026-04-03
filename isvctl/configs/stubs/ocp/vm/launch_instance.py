#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Ensure an OpenShift Virtualization (KubeVirt) VM is created from a manifest, running, and SSH-ready.

This stub matches the shared VM suite JSON contract used by AWS ``launch_instance``:
``instance_id``, ``vpc_id`` (namespace), ``state``, ``key_file``, ``private_ip``
(from the first VMI interface IP), etc. It does **not** provision EC2.

Flow:

1. **Required:** ``oc``/``kubectl apply -f <manifest>`` (``--manifest`` or ``OCP_VM_MANIFEST``).
   The file must be a full ``VirtualMachine`` (or multi-doc list) whose ``spec`` defines
   the guest (``runStrategy`` / ``running``, ``template``, ``domain``, devices, volumes, …).
2. If the VMI is not already ``Running``, call ``virtctl start`` when the VM is halted or
   otherwise stopped (``runStrategy: Halted``, ``running: false``, ``Manual`` + ``Stopped``, etc.);
   ignore API errors that say the VM is already running. If the controller is already starting
   the guest (e.g. ``Always`` / ``running: true``), skip ``virtctl start`` and only wait.
3. Wait for VMI ``Running``, create a ``NodePort`` Service exposing guest SSH,
   then verify SSH through ``<node-ip>:<nodeport>``.  The Service persists after
   this script exits so isvtest validations can connect directly.

Usage:
    python launch_instance.py --vpc-id my-ns --instance-id my-vm --key-file ~/.ssh/key \\
        --manifest /path/to/virtualmachine.yaml

Environment:
    OCP_VM_MANIFEST: Path to the manifest if ``--manifest`` is not passed (must be non-empty).
    SSH_PORT: Default remote pod port for sshd when ``--ssh-port`` is omitted (usually ``22``).

Output JSON (subset):
{
    "success": true,
    "platform": "vm",
    "instance_id": "my-vm",
    "vpc_id": "my-ns",
    "state": "running",
    "private_ip": "10.128.1.2",
    "public_ip": "192.168.1.10",
    "ssh_port": 31234,
    "key_file": "/path/to/key",
    "key_name": "local",
    "ssh_user": "redhat",
    "ssh_host": "192.168.1.10",
    "ssh_ready": true
}
"""

from __future__ import annotations

from pathlib import Path
import sys

_OCP_STUB_ROOT = Path(__file__).resolve().parent.parent
if str(_OCP_STUB_ROOT) not in sys.path:
    sys.path.insert(0, str(_OCP_STUB_ROOT))

import argparse
import json
import os
from typing import Any

from common.cli import resolve_k8s_cli, resolve_ssh_port, run_cmd
from common.kubevirt_vm import KubeVirtVM, wait_for_guest_ssh


def _virtctl_start_reports_already_running(exc: BaseException) -> bool:
    """True if virtctl/API rejected start because the VM is already running (idempotent)."""
    return "already running" in str(exc).lower()


def _vm_needs_virtctl_start(vm: dict[str, Any]) -> bool:
    """Return whether ``virtctl start`` should run from ``VirtualMachine`` spec/status."""
    spec = vm.get("spec") or {}
    status = vm.get("status") or {}
    printable = (status.get("printableStatus") or "").strip()

    if printable == "Running":
        return False

    run_strategy = spec.get("runStrategy")
    running = spec.get("running")

    if run_strategy == "Halted":
        return True
    if running is False:
        return True
    if run_strategy == "Manual":
        return printable == "Stopped"

    if run_strategy in ("Always", "RerunOnFailure"):
        return printable == "Stopped"

    if running is True:
        return printable == "Stopped"

    if printable == "Stopped":
        return True
    return False


def apply_manifest(cli: str, namespace: str, manifest_path: str) -> None:
    """Run ``kubectl/oc apply -f`` for a ``VirtualMachine`` (or multi-doc) manifest."""
    path = Path(manifest_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"VM manifest not found: {path}")
    proc = run_cmd([cli, "apply", "-f", str(path), "-n", namespace], timeout=300)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise RuntimeError(f"{cli} apply failed: {err}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Launch (ensure running) an OpenShift Virtualization VM for the shared VM test suite",
    )
    parser.add_argument(
        "--vpc-id",
        required=True,
        help="Namespace for the VirtualMachine / VMI (same as shared ``vpc_id``)",
    )
    parser.add_argument(
        "--instance-id",
        required=True,
        help="VirtualMachine name (VMI name when running)",
    )
    parser.add_argument("--key-file", required=True, help="Path to SSH private key (for suite contract)")
    parser.add_argument("--ssh-user", default="ubuntu", help="SSH username for guest check")
    parser.add_argument(
        "--ssh-port",
        type=int,
        default=None,
        metavar="PORT",
        help="Guest sshd port (default 22 / SSH_PORT env)",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        metavar="PATH",
        help=(
            "Path to VirtualMachine YAML to ``kubectl/oc apply -f`` (required unless OCP_VM_MANIFEST is set)"
        ),
    )
    args = parser.parse_args()

    if args.ssh_port is not None and not (1 <= args.ssh_port <= 65535):
        print("launch_instance: --ssh-port must be between 1 and 65535", file=sys.stderr)
        return 2

    manifest = (args.manifest or os.environ.get("OCP_VM_MANIFEST") or "").strip()
    if not manifest:
        print(
            "launch_instance: a manifest file is required (--manifest PATH or OCP_VM_MANIFEST)",
            file=sys.stderr,
        )
        return 2

    ssh_port = resolve_ssh_port(args.ssh_port)
    vm = KubeVirtVM(args.vpc_id, args.instance_id, ssh_port=ssh_port)

    key_path = str(Path(args.key_file).expanduser())
    key_name = Path(key_path).stem or "local"

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "instance_id": args.instance_id,
        "vpc_id": args.vpc_id,
        "key_file": key_path,
        "key_name": key_name,
        "ssh_user": args.ssh_user,
        "ssh_ready": False,
        "launch_initiated": False,
    }

    try:
        cli = resolve_k8s_cli()
        print(f"Applying VM manifest {manifest!r} in namespace {args.vpc_id!r}...", file=sys.stderr)
        apply_manifest(cli, args.vpc_id, manifest)

        print(f"Reading VirtualMachine {args.instance_id!r}...", file=sys.stderr)
        vm_json = vm.read_virtual_machine()
        vmi_probe = vm.read_vmi_optional()
        phase_probe = KubeVirtVM.vmi_phase(vmi_probe)

        if phase_probe == "Running":
            print("VMI already Running; skipping virtctl start.", file=sys.stderr)
            result["launch_initiated"] = False
        elif _vm_needs_virtctl_start(vm_json):
            print(
                f"Starting VM with virtctl (VM printableStatus="
                f"{(vm_json.get('status') or {}).get('printableStatus')!r}, VMI phase={phase_probe!r})...",
                file=sys.stderr,
            )
            try:
                vm.start()
                result["launch_initiated"] = True
            except RuntimeError as e:
                if _virtctl_start_reports_already_running(e):
                    print(
                        "  virtctl start: VM already running per API; continuing to wait for VMI...",
                        file=sys.stderr,
                    )
                    result["launch_initiated"] = False
                else:
                    raise
        else:
            print(
                "VirtualMachine requests run via controller; skipping virtctl start "
                f"(printableStatus={(vm_json.get('status') or {}).get('printableStatus')!r}).",
                file=sys.stderr,
            )
            result["launch_initiated"] = False

        print("Waiting for VMI Running...", file=sys.stderr)
        vmi = vm.wait_running()
        result["state"] = "running"

        guest_ip = KubeVirtVM.guest_ip_from_vmi(vmi)
        result["private_ip"] = guest_ip

        sshd_port = 22 if ssh_port is None else ssh_port

        # Create a NodePort Service so SSH is reachable from outside the
        # cluster.  All subsequent SSH (the readiness check below *and*
        # isvtest validations after this script exits) goes through the
        # NodePort -- no oc port-forward needed.
        print("Creating NodePort Service for SSH access...", file=sys.stderr)
        svc_info = vm.create_ssh_nodeport_service(remote_port=sshd_port)
        node_ip = svc_info["node_ip"]
        node_port = svc_info["node_port"]
        result["public_ip"] = node_ip
        result["ssh_port"] = node_port
        result["ssh_host"] = node_ip
        print(f"  SSH via NodePort: {node_ip}:{node_port}", file=sys.stderr)

        print("Waiting for guest SSH via NodePort...", file=sys.stderr)
        ssh_ready, ssh_diag = wait_for_guest_ssh(
            vm.ssh_bin, node_ip, args.ssh_user, key_path, port=node_port,
        )

        result["ssh_ready"] = ssh_ready
        if not ssh_ready:
            result["error"] = "SSH not ready after launch"
            if ssh_diag:
                result["ssh_error"] = ssh_diag[:2000]
            print("WARNING: guest SSH did not become ready", file=sys.stderr)
            print(json.dumps(result, indent=2))
            return 1

        result["success"] = True
        print("Launch completed successfully.", file=sys.stderr)

    except FileNotFoundError as e:
        result["error"] = str(e)
        print(f"ERROR: {e}", file=sys.stderr)
    except (RuntimeError, json.JSONDecodeError, OSError) as e:
        result["error"] = str(e)
        print(f"ERROR: {e}", file=sys.stderr)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
