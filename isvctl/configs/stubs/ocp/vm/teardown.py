#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Teardown an OpenShift Virtualization VM and associated resources.

Deletes the ``VirtualMachine`` (which cascades to the VMI and virt-launcher
pod) and the SSH ``NodePort`` Service created by ``launch_instance``.

For shared VM YAML, ``--vpc-id`` is the namespace.

Usage:
    python teardown.py --vpc-id my-ns --instance-id my-vm
    python teardown.py --vpc-id my-ns --instance-id my-vm --skip-destroy

Output JSON:
{
    "success": true,
    "platform": "vm",
    "resources_destroyed": true,
    "deleted": {
        "virtual_machines": ["my-vm"],
        "services": ["my-vm-ssh"]
    }
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

from common.cli import resolve_k8s_cli, run_cmd
from common.kubevirt_vm import KubeVirtVM


def _delete_virtual_machine(cli: str, namespace: str, name: str) -> bool:
    """Delete the VirtualMachine object (cascades to VMI and pod). Returns True if deleted."""
    proc = run_cmd(
        [cli, "delete", "virtualmachine", name, "-n", namespace, "--ignore-not-found", "--wait=true"],
        timeout=300,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise RuntimeError(f"Failed to delete VirtualMachine {name!r}: {err}")
    return "deleted" in (proc.stdout or "").lower()


def main() -> int:
    parser = argparse.ArgumentParser(description="Teardown an OpenShift Virtualization VM")
    parser.add_argument(
        "--vpc-id",
        required=True,
        help="Namespace containing the VirtualMachine",
    )
    parser.add_argument(
        "--instance-id",
        required=True,
        help="VirtualMachine name to delete",
    )
    parser.add_argument(
        "--skip-destroy",
        action="store_true",
        help="Skip actual destroy (dry-run)",
    )
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "resources_destroyed": False,
        "deleted": {
            "virtual_machines": [],
            "services": [],
        },
    }

    if args.skip_destroy:
        result["success"] = True
        result["message"] = "Destroy skipped (--skip-destroy flag)"
        print(json.dumps(result, indent=2))
        return 0

    vm = KubeVirtVM(args.vpc_id, args.instance_id)

    try:
        cli = resolve_k8s_cli()

        # Delete the SSH NodePort Service first (non-fatal if missing)
        print(f"Deleting SSH NodePort Service for {args.instance_id!r}...", file=sys.stderr)
        vm.delete_ssh_nodeport_service()
        result["deleted"]["services"].append(f"{args.instance_id}-ssh")
        print("  Service deleted", file=sys.stderr)

        # Delete the VirtualMachine (cascades to VMI + virt-launcher pod)
        print(f"Deleting VirtualMachine {args.instance_id!r} in namespace {args.vpc_id!r}...", file=sys.stderr)
        deleted = _delete_virtual_machine(cli, args.vpc_id, args.instance_id)
        if deleted:
            result["deleted"]["virtual_machines"].append(args.instance_id)
            print("  VirtualMachine deleted", file=sys.stderr)
        else:
            print("  VirtualMachine not found (already deleted)", file=sys.stderr)

        # Wait for VMI to be fully gone
        print("Waiting for VMI to be removed...", file=sys.stderr)
        try:
            vm.wait_vmi_deleted(timeout_sec=120)
            print("  VMI removed", file=sys.stderr)
        except RuntimeError:
            # VMI may already be gone if the VM was stopped
            vmi = vm.read_vmi_optional()
            if vmi is None:
                print("  VMI already gone", file=sys.stderr)
            else:
                raise

        result["success"] = True
        result["resources_destroyed"] = True
        result["message"] = "VM and resources deleted successfully"
        print("Teardown completed successfully.", file=sys.stderr)

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
