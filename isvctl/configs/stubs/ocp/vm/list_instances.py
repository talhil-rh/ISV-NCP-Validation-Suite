#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""List OpenShift Virtualization VM instances (VMIs) in a namespace.

Uses the Kubernetes API (``oc`` or ``kubectl``) to list
``VirtualMachineInstance`` objects—the same resources ``virtctl list vmi``
shows. Configure kubeconfig as you would for ``virtctl``.

For compatibility with the shared VM test config, ``--vpc-id`` is the
namespace to list (your ``launch_instance`` step should set ``vpc_id`` to
that namespace).

Usage:
    python list_instances.py --vpc-id my-namespace
    python list_instances.py --vpc-id my-namespace --instance-id my-vm

Environment:
    OC or KUBECTL: Executable to use (default: first of oc, kubectl on PATH).

Output JSON:
{
    "success": true,
    "platform": "vm",
    "instances": [
        {
            "instance_id": "my-vm",
            "instance_type": "u1.medium",
            "state": "running",
            "public_ip": null,
            "private_ip": "10.128.0.5",
            "vpc_id": "my-namespace"
        }
    ],
    "count": 1,
    "found_target": true,
    "target_instance": "my-vm"
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


def map_vmi_phase(phase: str | None) -> str:
    """Map KubeVirt VMI phase to lowercase states used by VM validations."""
    if not phase:
        return "pending"
    normalized = {
        "Pending": "pending",
        "Scheduling": "pending",
        "Scheduled": "pending",
        "Running": "running",
        "Succeeded": "stopped",
        "Failed": "terminated",
    }
    return normalized.get(phase, phase.lower())


def infer_instance_type(domain: dict[str, Any]) -> str:
    """Best-effort instance size string from VMI domain spec."""
    machine = domain.get("machine") or {}
    mtype = machine.get("type")
    if isinstance(mtype, str) and mtype:
        return mtype
    cpu = domain.get("cpu") or {}
    cores = cpu.get("cores")
    sockets = cpu.get("sockets")
    threads = cpu.get("threads")
    mem_guest = (domain.get("memory") or {}).get("guest")
    parts: list[str] = []
    if cores is not None:
        label = f"{cores}vCPU"
        if sockets:
            label = f"{sockets}x{label}"
        if threads:
            label = f"{label}/{threads}t"
        parts.append(label)
    if isinstance(mem_guest, str) and mem_guest:
        parts.append(mem_guest)
    return "/".join(parts) if parts else "unknown"


def extract_ips(interfaces: list[dict[str, Any]] | None) -> tuple[str | None, str | None]:
    """Return (public_ip, private_ip) from VMI status.interfaces."""
    if not interfaces:
        return None, None
    private_ip: str | None = None
    public_ip: str | None = None
    for iface in interfaces:
        ip = iface.get("ipAddress")
        if not isinstance(ip, str) or not ip:
            continue
        # Pod / cluster IPs are typically private; secondary interfaces may differ.
        if ip.startswith(("10.", "172.", "192.168.", "fc", "fd")):
            if private_ip is None:
                private_ip = ip
        else:
            if public_ip is None:
                public_ip = ip
    if private_ip is None:
        # First IP as private if none matched RFC1918-style heuristic
        first = interfaces[0].get("ipAddress")
        private_ip = first if isinstance(first, str) else None
    return public_ip, private_ip


def get_vmi_list_json(cli: str, namespace: str) -> dict[str, Any]:
    """Fetch VirtualMachineInstance list as parsed JSON."""
    cmd = [
        cli,
        "get",
        "virtualmachineinstance",
        "-n",
        namespace,
        "-o",
        "json",
    ]
    proc = run_cmd(cmd, timeout=120)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise RuntimeError(f"{cli} get virtualmachineinstance failed: {err}")
    return json.loads(proc.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description="List OpenShift Virtualization VMIs in a namespace (KubeVirt API)")
    parser.add_argument(
        "--vpc-id",
        required=True,
        help="Namespace containing VMIs (same key as AWS VPC for shared vm.yaml)",
    )
    parser.add_argument(
        "--instance-id",
        help="Target VMI name to verify exists in the list",
    )
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "instances": [],
    }

    try:
        cli = resolve_k8s_cli()
        data = get_vmi_list_json(cli, args.vpc_id)
        items = data.get("items") or []

        for item in items:
            meta = item.get("metadata") or {}
            name = meta.get("name")
            if not name:
                continue
            status = item.get("status") or {}
            phase = status.get("phase")
            spec = item.get("spec") or {}
            domain = spec.get("domain") or {}
            raw_ifaces = status.get("interfaces")
            ifaces = raw_ifaces if isinstance(raw_ifaces, list) else None
            public_ip, private_ip = extract_ips(ifaces)

            result["instances"].append(
                {
                    "instance_id": name,
                    "instance_type": infer_instance_type(domain),
                    "state": map_vmi_phase(phase if isinstance(phase, str) else None),
                    "public_ip": public_ip,
                    "private_ip": private_ip,
                    "vpc_id": args.vpc_id,
                }
            )

        result["count"] = len(result["instances"])

        if args.instance_id:
            result["target_instance"] = args.instance_id
            result["found_target"] = any(i["instance_id"] == args.instance_id for i in result["instances"])

        result["success"] = True

    except (FileNotFoundError, RuntimeError, json.JSONDecodeError, OSError) as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
