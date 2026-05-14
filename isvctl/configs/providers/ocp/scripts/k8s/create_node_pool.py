#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""OCP Node Pool (MachineSet) Create / Update.

Clones an existing MachineSet as a template, applies the specified
replicas, labels, and taints, and emits a ``node_pool`` JSON payload for
``K8sNodePoolCheck``.  Because ``oc apply`` is idempotent, this script
handles both the initial create and subsequent updates (e.g. scale via a
new ``OCP_NODE_POOL_REPLICAS``).

Environment variables (all optional):
  NODE_POOL_ACTION               Banner verb: "Creating" | "Updating"
  OCP_NODE_POOL_NAME             Pool name suffix (default "isv-test-pool")
  OCP_NODE_POOL_REPLICAS         Desired replica count (default 1)
  OCP_NODE_POOL_LABELS_JSON      JSON object of extra node labels
  OCP_NODE_POOL_TAINTS_JSON      JSON array of node taints
  OCP_NODE_POOL_NODE_TYPE        Informational "cpu" | "gpu" (default "cpu")
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

NAMESPACE = "openshift-machine-api"
TRACKING_LABEL_KEY = "isv.ncp.validation/node-pool"


def _kubectl() -> str:
    env = os.environ.get("KUBECTL", "").strip()
    return env if env else "oc"


def _run(cmd: str, *, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)


def _run_json(cmd: str) -> dict | list | None:
    r = _run(cmd)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def _infra_id(kc: str) -> str:
    r = _run(f"{kc} get infrastructure cluster -o jsonpath='{{.status.infrastructureName}}'")
    val = r.stdout.strip().strip("'")
    if val:
        return val
    # Fallback: derive from existing MachineSet name
    r = _run(f"{kc} get machineset -n {NAMESPACE} -o jsonpath='{{.items[0].metadata.name}}'")
    name = r.stdout.strip().strip("'")
    if name:
        # Convention: <infra-id>-worker-<az>
        parts = name.split("-worker")
        if parts:
            return parts[0]
    return ""


def _template_machineset(kc: str) -> dict | None:
    data = _run_json(f"{kc} get machineset -n {NAMESPACE} -o json")
    if not data or not data.get("items"):
        return None
    return data["items"][0]


def _clone_machineset(
    template: dict,
    name: str,
    pool: str,
    replicas: int,
    labels: dict,
    taints: list,
) -> dict:
    """Build a new MachineSet manifest from *template*."""
    ms = json.loads(json.dumps(template))  # deep copy

    # Clean metadata
    meta = ms["metadata"]
    meta["name"] = name
    for key in ("uid", "resourceVersion", "creationTimestamp", "generation", "managedFields"):
        meta.pop(key, None)
    ms.pop("status", None)

    ms["spec"]["replicas"] = replicas

    # Selector and template labels must match the new name
    ms["spec"]["selector"]["matchLabels"]["machine.openshift.io/cluster-api-machineset"] = name
    ms["spec"]["template"]["metadata"]["labels"]["machine.openshift.io/cluster-api-machineset"] = name

    # Node labels (go on the actual Node object)
    node_meta = ms["spec"]["template"]["spec"].setdefault("metadata", {})
    node_labels = node_meta.setdefault("labels", {})
    node_labels[TRACKING_LABEL_KEY] = pool
    node_labels.update(labels)

    # Taints (go on the actual Node object)
    if taints:
        ms["spec"]["template"]["spec"]["taints"] = taints

    return ms


def main() -> int:
    kc = _kubectl()
    pool_name = os.environ.get("OCP_NODE_POOL_NAME", "isv-test-pool")
    replicas = int(os.environ.get("OCP_NODE_POOL_REPLICAS", "1"))
    labels_json = os.environ.get("OCP_NODE_POOL_LABELS_JSON", "{}")
    taints_json = os.environ.get("OCP_NODE_POOL_TAINTS_JSON", "[]")
    node_type = os.environ.get("OCP_NODE_POOL_NODE_TYPE", "cpu").lower()
    action = os.environ.get("NODE_POOL_ACTION", "Creating")

    try:
        labels: dict = json.loads(labels_json)
    except json.JSONDecodeError:
        print(f"Error: OCP_NODE_POOL_LABELS_JSON is not valid JSON: {labels_json}", file=sys.stderr)
        return 1
    try:
        taints: list = json.loads(taints_json)
    except json.JSONDecodeError:
        print(f"Error: OCP_NODE_POOL_TAINTS_JSON is not valid JSON: {taints_json}", file=sys.stderr)
        return 1
    if node_type not in ("cpu", "gpu"):
        print(f"Error: OCP_NODE_POOL_NODE_TYPE must be 'cpu' or 'gpu', got '{node_type}'", file=sys.stderr)
        return 1

    infra = _infra_id(kc)
    if not infra:
        print("No infrastructure ID detected (SNO cluster); skipping node pool creation.", file=sys.stderr)
        return 0

    ms_name = f"{infra}-{pool_name}"

    template = _template_machineset(kc)
    if not template:
        print("No MachineSets found (SNO cluster); skipping node pool creation.", file=sys.stderr)
        return 0

    print(f"\n{'='*40}", file=sys.stderr)
    print(f"  {action} OCP test node pool", file=sys.stderr)
    print(f"{'='*40}", file=sys.stderr)
    print(f"  pool name:  {pool_name}", file=sys.stderr)
    print(f"  machineset: {ms_name}", file=sys.stderr)
    print(f"  replicas:   {replicas}", file=sys.stderr)
    print(f"  node type:  {node_type}", file=sys.stderr)
    print(f"  template:   {template['metadata']['name']}\n", file=sys.stderr)

    manifest = _clone_machineset(template, ms_name, pool_name, replicas, labels, taints)
    proc = subprocess.run(
        f"{kc} apply -n {NAMESPACE} -f -",
        shell=True, input=json.dumps(manifest), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(f"Error applying MachineSet: {proc.stderr}", file=sys.stderr)
        return 1
    print(proc.stderr, end="", file=sys.stderr)

    # Wait for ready replicas
    print(f"Waiting for MachineSet {ms_name} to reach {replicas} ready replicas...", file=sys.stderr)
    timeout, elapsed, ready = 600, 0, 0
    while elapsed < timeout:
        r = _run(f"{kc} get machineset {ms_name} -n {NAMESPACE} -o jsonpath='{{.status.readyReplicas}}'")
        val = r.stdout.strip().strip("'")
        ready = int(val) if val and val.isdigit() else 0
        if ready >= replicas:
            print(f"MachineSet ready: {ready}/{replicas}", file=sys.stderr)
            break
        print(f"  Waiting... {ready}/{replicas} ready ({elapsed}s/{timeout}s)", file=sys.stderr)
        time.sleep(15)
        elapsed += 15
    else:
        print(
            f"Warning: MachineSet {ms_name} has {ready}/{replicas} ready after {timeout}s; "
            "K8sNodePoolCheck will wait further with its own timeout.",
            file=sys.stderr,
        )

    # Emit node_pool JSON payload
    result = {
        "success": True,
        "platform": "kubernetes",
        "node_pool_name": pool_name,
        "label_selector": f"{TRACKING_LABEL_KEY}={pool_name}",
        "expected_replicas": replicas,
        "expected_labels_json": json.dumps(labels, separators=(",", ":")),
        "expected_taints_json": json.dumps(taints, separators=(",", ":")),
        "expected_instance_types_json": "[]",
        "node_type": node_type,
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
