# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""OCP-native probes for security checks that the fulfillment API cannot reach.

These functions use ``oc`` / ``kubectl`` to query kube-apiserver audit logs
and K8s namespace-scoped storage isolation. They're called directly by OSAC
security test scripts — no subprocess needed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _oc() -> str:
    path = shutil.which("oc")
    return path or ""


def _kubectl() -> str:
    path = shutil.which("kubectl") or shutil.which("oc")
    if not path:
        raise RuntimeError("Neither kubectl nor oc found on PATH")
    return path


# ---------------------------------------------------------------------------
# Audit log probe
# ---------------------------------------------------------------------------

def probe_audit_log(namespace: str = "osac-e2e-ci") -> dict[str, Any]:
    """Create a probe ConfigMap and find it in the kube-apiserver audit log.

    Returns a dict with ``source_ips``, ``user_agent``, ``username``,
    ``verb``, ``request_uri``, ``timestamp``, ``namespace``, and
    ``success``.
    """
    result: dict[str, Any] = {
        "success": False,
        "source_ips": [],
        "user_agent": "",
        "username": "",
        "verb": "",
        "request_uri": "",
        "timestamp": "",
        "namespace": namespace,
    }

    if os.environ.get("ISVCTL_DEMO_MODE") == "1":
        result["success"] = True
        result["source_ips"] = ["10.0.0.1"]
        result["user_agent"] = "kubectl/v1.0.0 (linux/amd64)"
        result["username"] = "system:admin"
        result["verb"] = "create"
        result["request_uri"] = f"/api/v1/namespaces/{namespace}/configmaps"
        result["timestamp"] = "2026-01-01T00:00:00Z"
        return result

    oc = _oc()
    if not oc:
        result["error"] = "oc not found on PATH"
        return result

    kctl = _kubectl()
    probe_name = f"isv-audit-probe-{uuid.uuid4().hex[:8]}"

    try:
        create_cmd = [kctl, "create", "configmap", probe_name,
                      "--from-literal=probe=audit-test", "-n", namespace, "-o", "json"]
        create_result = subprocess.run(create_cmd, capture_output=True, text=True, timeout=30)
        if create_result.returncode != 0:
            result["error"] = f"Could not create probe ConfigMap: {create_result.stderr.strip()}"
            return result

        time.sleep(3)

        log_files = _get_audit_log_files(oc)
        audit_entry = None
        for log_file in log_files:
            audit_entry = _search_audit_log(oc, log_file, probe_name, namespace)
            if audit_entry:
                break

        if audit_entry:
            result["success"] = True
            result["source_ips"] = audit_entry.get("sourceIPs", [])
            result["user_agent"] = audit_entry.get("userAgent", "")
            result["username"] = audit_entry.get("user", {}).get("username", "")
            result["verb"] = audit_entry.get("verb", "")
            result["request_uri"] = audit_entry.get("requestURI", "")
            result["timestamp"] = (
                audit_entry.get("requestReceivedTimestamp")
                or audit_entry.get("stageTimestamp", "")
            )
            result["namespace"] = audit_entry.get("objectRef", {}).get("namespace", namespace)
        else:
            result["error"] = f"Probe '{probe_name}' not found in {len(log_files)} audit log(s)"
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        subprocess.run(
            [kctl, "delete", "configmap", probe_name, "-n", namespace, "--ignore-not-found"],
            capture_output=True, text=True, timeout=10,
        )

    return result


def _get_audit_log_files(oc: str) -> list[str]:
    cmd = [oc, "adm", "node-logs", "--role=master", "--path=kube-apiserver/"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return []
    lines = result.stdout.strip().split("\n")
    files: list[str] = []
    if any("audit.log" in ln for ln in lines):
        files.append("audit.log")
    rotated = [ln.split()[-1] for ln in lines if "audit-" in ln and ln.endswith(".log")]
    if rotated:
        files.append(rotated[-1])
    return files


def _search_audit_log(oc: str, log_file: str, resource_name: str, namespace: str) -> dict[str, Any] | None:
    list_cmd = [oc, "adm", "node-logs", "--role=master", "--path=kube-apiserver/"]
    list_result = subprocess.run(list_cmd, capture_output=True, text=True, timeout=30)
    if list_result.returncode != 0:
        return None
    node_name = ""
    for line in list_result.stdout.strip().split("\n"):
        if log_file in line:
            node_name = line.split()[0]
            break
    if not node_name:
        return None

    oc_proc = subprocess.Popen(
        [oc, "adm", "node-logs", node_name, f"--path=kube-apiserver/{log_file}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    grep_proc = subprocess.Popen(
        ["grep", resource_name],
        stdin=oc_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    oc_proc.stdout.close()
    try:
        grep_out, _ = grep_proc.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        grep_proc.kill()
        oc_proc.kill()
        return None
    finally:
        oc_proc.wait()

    if grep_proc.returncode != 0 or not grep_out:
        return None

    for line in reversed(grep_out.decode().strip().split("\n")):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        obj_ref = entry.get("objectRef", {})
        if (obj_ref.get("name") == resource_name
                and obj_ref.get("namespace") == namespace
                and entry.get("verb") == "create"):
            return entry
    return None


# ---------------------------------------------------------------------------
# Storage isolation probe
# ---------------------------------------------------------------------------

def probe_storage_isolation(
    namespace_a: str, namespace_b: str, storage_class: str = ""
) -> dict[str, Any]:
    """Verify PVCs in namespace_a are not accessible from namespace_b.

    Returns a dict with ``storage_isolated``, ``storage_denied``,
    ``message``, and ``success``.
    """
    result: dict[str, Any] = {
        "success": False,
        "storage_isolated": False,
        "storage_denied": False,
        "namespace_a": namespace_a,
        "namespace_b": namespace_b,
        "message": "",
    }

    if os.environ.get("ISVCTL_DEMO_MODE") == "1":
        result["success"] = True
        result["storage_isolated"] = True
        result["storage_denied"] = True
        result["message"] = "PVC in namespace A not visible from namespace B"
        return result

    kctl = _kubectl()
    pvc_name = f"isv-storage-probe-{uuid.uuid4().hex[:8]}"

    try:
        for ns in (namespace_a, namespace_b):
            check = subprocess.run(
                [kctl, "get", "namespace", ns],
                capture_output=True, text=True, timeout=10,
            )
            if check.returncode != 0:
                result["error"] = f"Namespace '{ns}' not found"
                return result

        pvc_spec: dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": pvc_name, "namespace": namespace_a},
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": {"requests": {"storage": "1Mi"}},
            },
        }
        if storage_class:
            pvc_spec["spec"]["storageClassName"] = storage_class

        create = subprocess.run(
            [kctl, "apply", "-f", "-", "-o", "json"],
            input=json.dumps(pvc_spec),
            capture_output=True, text=True, timeout=30,
        )
        if create.returncode != 0:
            result["error"] = f"Could not create PVC in {namespace_a}: {create.stderr.strip()}"
            return result

        list_cross = subprocess.run(
            [kctl, "get", "pvc", pvc_name, "-n", namespace_a,
             "--as", f"system:serviceaccount:{namespace_b}:default",
             "-o", "json"],
            capture_output=True, text=True, timeout=10,
        )
        cross_ns_denied = list_cross.returncode != 0

        list_same = subprocess.run(
            [kctl, "get", "pvc", pvc_name, "-n", namespace_a, "-o", "json"],
            capture_output=True, text=True, timeout=10,
        )
        same_ns_visible = list_same.returncode == 0

        if cross_ns_denied and same_ns_visible:
            result["storage_isolated"] = True
            result["storage_denied"] = True
            result["message"] = (
                f"PVC '{pvc_name}' in {namespace_a} visible to owner, "
                f"denied to {namespace_b}:default SA"
            )
        elif not cross_ns_denied:
            result["message"] = (
                f"PVC '{pvc_name}' in {namespace_a} is accessible from "
                f"{namespace_b}:default SA — isolation failure"
            )
        else:
            result["message"] = (
                f"PVC '{pvc_name}' not visible to owner either — inconclusive "
                f"(owner rc={list_same.returncode}, cross-ns rc={list_cross.returncode})"
            )

        result["success"] = result["storage_isolated"]
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        subprocess.run(
            [kctl, "delete", "pvc", pvc_name, "-n", namespace_a, "--ignore-not-found"],
            capture_output=True, text=True, timeout=10,
        )

    return result
