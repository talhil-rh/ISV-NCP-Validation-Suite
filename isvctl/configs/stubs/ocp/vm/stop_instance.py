#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Stop an OpenShift Virtualization VM and wait until the VMI is gone.

Uses ``virtctl stop`` on the ``VirtualMachine``. Readiness is determined with
``oc``/``kubectl`` (no running ``VirtualMachineInstance``). Use the same
kubeconfig as ``virtctl``.

For shared VM YAML, ``--vpc-id`` is the namespace.

Usage:
    python stop_instance.py --vpc-id my-ns --instance-id my-vm

Output JSON:
{
    "success": true,
    "platform": "vm",
    "instance_id": "my-vm",
    "state": "stopped",
    "stop_initiated": true
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

from common.kubevirt_vm import KubeVirtVM


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stop an OpenShift Virtualization VM (virtctl) and wait until the VMI is gone"
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
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "instance_id": args.instance_id,
        "stop_initiated": False,
    }

    vm = KubeVirtVM(args.vpc_id, args.instance_id)

    try:
        vm.read_virtual_machine()

        print("Checking instance state before stop...", file=sys.stderr)
        vmi_before = vm.read_vmi_optional()
        phase_before = KubeVirtVM.vmi_phase(vmi_before)

        if vmi_before is None or phase_before is None:
            result["state"] = "stopped"
            result["stop_initiated"] = True
            result["success"] = True
            print(f"  VM {args.instance_id} already has no VMI (no-op)", file=sys.stderr)
            print(json.dumps(result, indent=2))
            return 0

        if phase_before != "Running":
            result["error"] = f"VMI is {phase_before}, expected Running"
            result["state"] = phase_before.lower() if phase_before else "unknown"
            print(json.dumps(result, indent=2))
            return 1

        print(f"Stopping VM {args.instance_id} with virtctl...", file=sys.stderr)
        vm.stop()
        result["stop_initiated"] = True
        print("  virtctl stop succeeded", file=sys.stderr)

        print("Waiting for VMI to be removed...", file=sys.stderr)
        vm.wait_vmi_deleted()
        print("  VMI removed", file=sys.stderr)

        result["state"] = "stopped"
        result["success"] = True
        print("Stop completed successfully!", file=sys.stderr)

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
