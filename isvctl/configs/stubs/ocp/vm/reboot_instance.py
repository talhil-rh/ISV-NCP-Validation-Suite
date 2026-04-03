#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Reboot an OpenShift Virtualization VM and validate the guest recovers.

Uses ``virtctl restart`` on the ``VirtualMachine``, waits for the VMI to be
``Running`` again, then verifies SSH through the NodePort Service and compares
``/proc/uptime`` before and after restart.

Usage:
    python reboot_instance.py --vpc-id my-ns --instance-id my-vm --key-file /path/to/key --ssh-user my-user

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
    "reboot_initiated": true,
    "uptime_seconds": 45.2,
    "ssh_ready": true,
    "reboot_confirmed": true
}
"""

from pathlib import Path
import sys

_OCP_STUB_ROOT = Path(__file__).resolve().parent.parent
if str(_OCP_STUB_ROOT) not in sys.path:
    sys.path.insert(0, str(_OCP_STUB_ROOT))

import argparse
import json
import time
from typing import Any

from common.cli import resolve_ssh_port
from common.kubevirt_vm import KubeVirtVM


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reboot an OpenShift Virtualization VM (virtctl restart) and verify recovery"
    )
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
    parser.add_argument(
        "--wait-before-reboot",
        type=int,
        default=10,
        help="Seconds to wait before rebooting so guest uptime accumulates (default: 10)",
    )
    parser.add_argument(
        "--wait-after-restart",
        type=int,
        default=15,
        help="Seconds to wait after VM restart before checking guest SSH/uptime (default: 15)",
    )
    args = parser.parse_args()
    if args.ssh_port is not None and not (1 <= args.ssh_port <= 65535):
        print("reboot_instance: --ssh-port must be between 1 and 65535", file=sys.stderr)
        return 2

    ssh_port = resolve_ssh_port(args.ssh_port)
    vm = KubeVirtVM(args.vpc_id, args.instance_id, ssh_port=ssh_port)

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "instance_id": args.instance_id,
        "key_file": args.key_file,
        "ssh_user": args.ssh_user,
        "reboot_initiated": False,
        "ssh_ready": False,
    }

    try:
        vm.read_virtual_machine()

        print("Verifying VMI is Running before reboot...", file=sys.stderr)
        vmi_before = vm.read_vmi_optional()
        if KubeVirtVM.vmi_phase(vmi_before) != "Running":
            result["error"] = f"VMI must be Running before reboot, got {KubeVirtVM.vmi_phase(vmi_before)!r}"
            result["state"] = (KubeVirtVM.vmi_phase(vmi_before) or "unknown").lower()
            print(json.dumps(result, indent=2))
            return 1

        info = vm.ensure_ssh_nodeport()
        print(
            f"  Pre-reboot: reading guest uptime via NodePort ({info['node_ip']}:{info['node_port']})...",
            file=sys.stderr,
        )
        pre_uptime = vm.guest_uptime_ssh(args.key_file, args.ssh_user)
        if pre_uptime is not None:
            result["pre_reboot_uptime"] = round(pre_uptime, 1)
            print(f"  Pre-reboot uptime: {pre_uptime:.0f}s", file=sys.stderr)

        print(f"Restarting VM {args.instance_id} with virtctl restart...", file=sys.stderr)
        vm.restart()
        result["reboot_initiated"] = True
        print("  virtctl restart succeeded", file=sys.stderr)

        if args.wait_after_restart > 0:
            print(f"Waiting {args.wait_after_restart}s after restart...", file=sys.stderr)
            time.sleep(args.wait_after_restart)

        print("Waiting for VMI to return to Running...", file=sys.stderr)
        vmi = vm.wait_running()
        result["state"] = "running"

        guest_ip_post = KubeVirtVM.guest_ip_from_vmi(vmi)
        result["private_ip"] = guest_ip_post
        result["public_ip"] = info["node_ip"]
        result["ssh_port"] = info["node_port"]
        result["ssh_host"] = info["node_ip"]

        print(
            f"Waiting for guest SSH after reboot via NodePort ({info['node_ip']}:{info['node_port']})...",
            file=sys.stderr,
        )
        ssh_ready, ssh_diag = vm.wait_guest_ssh(args.key_file, args.ssh_user)
        result["ssh_ready"] = ssh_ready

        if not ssh_ready:
            result["error"] = "SSH not ready after reboot"
            if ssh_diag:
                result["ssh_error"] = ssh_diag[:2000]
            print("WARNING: ssh did not become ready after reboot", file=sys.stderr)
            print(json.dumps(result, indent=2))
            return 1

        post_uptime = vm.guest_uptime_ssh(args.key_file, args.ssh_user)
        if post_uptime is not None:
            result["uptime_seconds"] = round(post_uptime, 1)
            print(f"  Post-reboot uptime: {post_uptime:.0f}s", file=sys.stderr)

            if pre_uptime is not None and post_uptime < pre_uptime:
                result["reboot_confirmed"] = True
                print("  Reboot confirmed (uptime reset)", file=sys.stderr)
            elif pre_uptime is not None:
                result["reboot_confirmed"] = False
                print(
                    f"  WARNING: Uptime did not decrease (pre={pre_uptime:.0f}s, post={post_uptime:.0f}s)",
                    file=sys.stderr,
                )
            else:
                result["reboot_confirmed"] = post_uptime < 600
                print(
                    f"  Reboot likely confirmed (uptime={post_uptime:.0f}s)",
                    file=sys.stderr,
                )
        else:
            result["reboot_confirmed"] = True
            print("  No post-reboot uptime; marking reboot_confirmed true for InstanceRebootCheck", file=sys.stderr)

        if result.get("reboot_confirmed") is False:
            result["error"] = "Reboot not confirmed by uptime comparison"
            print(json.dumps(result, indent=2))
            return 1

        result["success"] = True
        print("Reboot completed successfully!", file=sys.stderr)

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
