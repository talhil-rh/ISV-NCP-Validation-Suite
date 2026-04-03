#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Start a stopped OpenShift Virtualization VM and verify SSH.

Uses ``virtctl start`` on the ``VirtualMachine`` (same name as the VMI).
State and addresses come from ``oc``/``kubectl`` on the
``VirtualMachineInstance``. Use the same kubeconfig you use for ``virtctl``.

For shared VM YAML, ``--vpc-id`` is the namespace. After the VMI is
``Running``, guest SSH is verified through the NodePort Service created
by ``launch_instance`` (``<node-ip>:<nodeport>``).

Usage:
    python start_instance.py --vpc-id my-ns --instance-id my-vm --key-file /path/to/key

Environment:
    SSH_PORT: Guest sshd port when ``--ssh-port`` is not passed (default 22).

Output JSON:
{
    "success": true,
    "platform": "vm",
    "instance_id": "my-vm",
    "state": "running",
    "public_ip": "192.168.1.10",
    "ssh_port": 31234,
    "private_ip": "10.128.1.2",
    "ssh_host": "192.168.1.10",
    "key_file": "/path/to/key",
    "ssh_user": "ubuntu",
    "start_initiated": true,
    "ssh_ready": true
}
"""

from pathlib import Path
import sys

_OCP_STUB_ROOT = Path(__file__).resolve().parent.parent
if str(_OCP_STUB_ROOT) not in sys.path:
    sys.path.insert(0, str(_OCP_STUB_ROOT))

import argparse
import json
from typing import Any

from common.cli import resolve_ssh_port
from common.kubevirt_vm import KubeVirtVM


def main() -> int:
    parser = argparse.ArgumentParser(description="Start a stopped OpenShift Virtualization VM (virtctl) and verify SSH")
    parser.add_argument(
        "--vpc-id",
        required=True,
        help="Namespace containing the VirtualMachine / VMI",
    )
    parser.add_argument(
        "--instance-id",
        required=True,
        help="VirtualMachine name (same as VMI name when running)",
    )
    parser.add_argument("--key-file", required=True, help="Path to SSH private key")
    parser.add_argument("--ssh-user", default="ubuntu", help="SSH username")
    parser.add_argument(
        "--ssh-port",
        type=int,
        default=None,
        metavar="PORT",
        help="Guest sshd port (default 22 / SSH_PORT env)",
    )
    args = parser.parse_args()
    if args.ssh_port is not None and not (1 <= args.ssh_port <= 65535):
        print("start_instance: --ssh-port must be between 1 and 65535", file=sys.stderr)
        return 2

    ssh_port = resolve_ssh_port(args.ssh_port)
    vm = KubeVirtVM(args.vpc_id, args.instance_id, ssh_port=ssh_port)

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "instance_id": args.instance_id,
        "key_file": args.key_file,
        "ssh_user": args.ssh_user,
        "start_initiated": False,
        "ssh_ready": False,
    }

    try:
        vm.read_virtual_machine()

        print("Verifying VM is stopped before start...", file=sys.stderr)
        vmi_before = vm.read_vmi_optional()
        phase_before = KubeVirtVM.vmi_phase(vmi_before)
        if phase_before == "Running":
            result["error"] = f"VMI is {phase_before}, expected stopped (no running VMI)"
            result["state"] = "running"
            print(json.dumps(result, indent=2))
            return 1
        if phase_before is not None and phase_before not in ("Succeeded", "Failed"):
            print(f"  VMI phase before start: {phase_before}", file=sys.stderr)

        print(f"Starting VM {args.instance_id} with virtctl...", file=sys.stderr)
        vm.start()
        result["start_initiated"] = True
        print("  virtctl start succeeded", file=sys.stderr)

        print("Waiting for VMI to reach Running...", file=sys.stderr)
        vmi = vm.wait_running()
        result["state"] = "running"

        guest_ip = KubeVirtVM.guest_ip_from_vmi(vmi)
        result["private_ip"] = guest_ip

        info = vm.ensure_ssh_nodeport()
        result["public_ip"] = info["node_ip"]
        result["ssh_port"] = info["node_port"]
        result["ssh_host"] = info["node_ip"]

        print(
            f"Waiting for guest SSH via NodePort ({info['node_ip']}:{info['node_port']})...",
            file=sys.stderr,
        )
        ssh_ready, ssh_diag = vm.wait_guest_ssh(args.key_file, args.ssh_user)
        result["ssh_ready"] = ssh_ready

        if not ssh_ready:
            result["error"] = "SSH not ready after start"
            if ssh_diag:
                result["ssh_error"] = ssh_diag[:2000]
            print("WARNING: ssh did not become ready after start", file=sys.stderr)
            print(json.dumps(result, indent=2))
            return 1

        result["success"] = True
        print("Start completed successfully!", file=sys.stderr)

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
