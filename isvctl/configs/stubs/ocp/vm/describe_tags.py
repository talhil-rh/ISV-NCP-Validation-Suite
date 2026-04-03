#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Build EC2-style tags from a VirtualMachineInstance for ``InstanceTagCheck``.

Fetches the VMI via the Kubernetes API, reads ``metadata.name`` into tag
``Name``, and sets ``CreatedBy`` to ``isvtest`` (suite attribution).

Use the same kubeconfig/context as ``virtctl`` / ``oc``. For shared VM YAML,
``--vpc-id`` is the namespace (match ``list_instances`` / launch output).

Usage:
    python describe_tags.py --vpc-id my-namespace --instance-id my-vm

Output JSON:
{
    "success": true,
    "platform": "vm",
    "instance_id": "my-vm",
    "tags": {
        "Name": "my-vm",
        "CreatedBy": "isvtest"
    },
    "tag_count": 2
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


def get_vmi_json(cli: str, namespace: str, name: str) -> dict[str, Any]:
    """Fetch a single VirtualMachineInstance as parsed JSON."""
    cmd = [
        cli,
        "get",
        "virtualmachineinstance",
        name,
        "-n",
        namespace,
        "-o",
        "json",
    ]
    proc = run_cmd(cmd, timeout=120)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        if "NotFound" in err or "not found" in err.lower():
            raise RuntimeError(f"VirtualMachineInstance {name!r} not found in namespace {namespace!r}")
        raise RuntimeError(f"{cli} get virtualmachineinstance failed: {err}")
    return json.loads(proc.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description="Describe VMI metadata as tags (OpenShift Virtualization / KubeVirt)")
    parser.add_argument(
        "--vpc-id",
        required=True,
        help="Namespace containing the VMI (same as list_instances / shared vm.yaml)",
    )
    parser.add_argument(
        "--instance-id",
        required=True,
        help="VMI name (same as instance_id from launch / list steps)",
    )
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "instance_id": args.instance_id,
        "tags": {},
        "tag_count": 0,
    }

    try:
        cli = resolve_k8s_cli()
        data = get_vmi_json(cli, args.vpc_id, args.instance_id)
        meta = data.get("metadata") or {}
        vmi_name = meta.get("name")
        if not vmi_name or not isinstance(vmi_name, str):
            raise RuntimeError("VMI metadata.name is missing or invalid")
        result["tags"] = {
            "Name": vmi_name,
            "CreatedBy": "isvtest",
        }
        result["tag_count"] = len(result["tags"])
        result["success"] = True

    except FileNotFoundError as e:
        result["error"] = str(e)
    except (RuntimeError, json.JSONDecodeError, OSError) as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
