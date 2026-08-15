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

"""NFS root-squash toggle test for OSAC.

Validates root_squash can be enabled and disabled at runtime on the NFS
server, and that the setting takes effect: root writes from a client pod
are squashed to anonymous UID when enabled, and retained as UID 0 when
disabled.

Covers HSS13-01.

Output JSON:
{
    "success": true,
    "platform": "storage",
    "test_name": "root_squash",
    "tests": {
        "enable_root_squash":  {"passed": true, "message": "..."},
        "root_squashed":       {"passed": true, "message": "..."},
        "disable_root_squash": {"passed": true, "message": "..."},
        "root_unsquashed":     {"passed": true, "message": "..."}
    }
}
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
KUBECTL = os.environ.get("KUBECTL", "kubectl")

NFS_SERVER_NS = os.environ.get("NFS_SERVER_NS", "nfs-system")
NFS_SERVER_DEPLOY = os.environ.get("NFS_SERVER_DEPLOY", "deployment/nfs-server")
NFS_EXPORT_PATH = os.environ.get("NFS_EXPORT_PATH", "/exports")
NFS_SERVER_SVC = os.environ.get("NFS_SERVER_SVC", "nfs-server.nfs-system.svc.cluster.local")
NFS_SVC_NAME = os.environ.get("NFS_SVC_NAME", "nfs-server")
TEST_NS = "isvtest-rootsquash"
POD_TIMEOUT = 120


def run_kubectl(*args: str, stdin: str | None = None, timeout: int = 60) -> tuple[int, str, str]:
    cmd = KUBECTL.split() + list(args)
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", f"kubectl timed out after {timeout}s"
    except Exception as exc:
        return 1, "", str(exc)


def ensure_namespace() -> bool:
    rc, ns_yaml, _ = run_kubectl("create", "namespace", TEST_NS, "--dry-run=client", "-o", "yaml")
    if rc != 0:
        return False
    rc, _, _ = run_kubectl("apply", "-f", "-", stdin=ns_yaml)
    if rc != 0:
        return False
    # Grant anyuid SCC so pods can run as root — use 'oc' directly since
    # 'kubectl adm policy' is an OCP-only subcommand
    subprocess.run(
        ["oc", "adm", "policy", "add-scc-to-user", "anyuid",
         "-z", "default", "-n", TEST_NS],
        capture_output=True, text=True, timeout=30,
    )
    return True


def cleanup_namespace() -> None:
    run_kubectl("delete", "namespace", TEST_NS, "--ignore-not-found", "--wait=false", timeout=30)


def nfs_exec(*cmd_parts: str, timeout: int = 30) -> tuple[int, str, str]:
    return run_kubectl(
        "exec", "-n", NFS_SERVER_NS, NFS_SERVER_DEPLOY, "--", *cmd_parts,
        timeout=timeout,
    )


def toggle_root_squash(enable: bool) -> tuple[bool, str]:
    squash_opt = "root_squash" if enable else "no_root_squash"
    # Unexport and re-export just the target path to avoid touching other entries
    unexport_cmd = f"exportfs -u '*:{NFS_EXPORT_PATH}'"
    reexport_cmd = f"exportfs -o rw,fsid=0,insecure,{squash_opt} '*:{NFS_EXPORT_PATH}'"
    rc, _, err = nfs_exec("sh", "-c", f"{unexport_cmd} && {reexport_cmd}")
    if rc != 0:
        return False, f"exportfs toggle failed: {err}"
    rc, out, _ = nfs_exec("exportfs", "-v")
    if rc != 0:
        return False, "exportfs -v failed"
    # Verify the target export line contains the expected option
    for line in out.splitlines():
        if NFS_EXPORT_PATH in line:
            if squash_opt in line:
                return True, f"{NFS_EXPORT_PATH} now exported with {squash_opt}"
    return False, f"{NFS_EXPORT_PATH} export not found with '{squash_opt}' after toggle"


def resolve_nfs_server() -> str:
    """Resolve NFS server to ClusterIP — node DNS can't resolve svc.cluster.local."""
    rc, ip, _ = run_kubectl(
        "get", "svc", NFS_SVC_NAME, "-n", NFS_SERVER_NS,
        "-o", "jsonpath={.spec.clusterIP}",
    )
    if rc == 0 and ip:
        return ip
    return NFS_SERVER_SVC


def write_file_as_root(filename: str, nfs_server_ip: str) -> tuple[bool, str]:
    """Create a pod that mounts NFS directly and writes a file as UID 0."""
    pod_name = f"rootsquash-{uuid.uuid4().hex[:8]}"
    manifest = json.dumps({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": TEST_NS},
        "spec": {
            "restartPolicy": "Never",
            "securityContext": {"runAsUser": 0, "fsGroup": 0},
            "containers": [{
                "name": "writer",
                "image": "busybox:1.36",
                "command": ["sh", "-c", f"touch /mnt/{filename} && echo done"],
                "volumeMounts": [{"name": "nfs", "mountPath": "/mnt"}],
                "securityContext": {"runAsUser": 0},
            }],
            "volumes": [{
                "name": "nfs",
                "nfs": {"server": nfs_server_ip, "path": NFS_EXPORT_PATH},
            }],
        },
    })

    rc, _, err = run_kubectl("apply", "-f", "-", stdin=manifest)
    if rc != 0:
        return False, f"pod apply failed: {err}"

    # Wait for pod to complete
    deadline = time.time() + POD_TIMEOUT
    while time.time() < deadline:
        rc, phase, _ = run_kubectl(
            "get", "pod", pod_name, "-n", TEST_NS,
            "-o", "jsonpath={.status.phase}",
        )
        if phase in ("Succeeded", "Failed"):
            break
        time.sleep(3)
    else:
        _, events, _ = run_kubectl(
            "get", "events", "-n", TEST_NS,
            "--field-selector", f"involvedObject.name={pod_name}",
            "--sort-by=.lastTimestamp", timeout=10,
        )
        _, phase_dbg, _ = run_kubectl(
            "get", "pod", pod_name, "-n", TEST_NS,
            "-o", "jsonpath={.status.phase} {.status.conditions}", timeout=10,
        )
        run_kubectl("delete", "pod", pod_name, "-n", TEST_NS, "--force", timeout=15)
        diag = f"pod timed out (phase={phase_dbg})"
        if events:
            last_lines = "\n".join(events.strip().splitlines()[-3:])
            diag += f"\nevents:\n{last_lines}"
        return False, diag

    # Get logs
    _, logs, _ = run_kubectl("logs", pod_name, "-n", TEST_NS)

    # Cleanup pod
    run_kubectl("delete", "pod", pod_name, "-n", TEST_NS, "--force", timeout=15)

    if phase == "Failed":
        return False, f"pod failed: {logs}"
    return True, logs


def check_file_uid(filename: str) -> tuple[bool, int, str]:
    filepath = f"{NFS_EXPORT_PATH}/{filename}"
    rc, out, err = nfs_exec("stat", "-c", "%u", filepath)
    if rc != 0:
        return False, -1, f"stat failed: {err}"
    try:
        uid = int(out)
    except ValueError:
        return False, -1, f"unexpected stat output: {out}"
    return True, uid, ""


def cleanup_test_files(*filenames: str) -> None:
    for f in filenames:
        nfs_exec("rm", "-f", f"{NFS_EXPORT_PATH}/{f}")


def main() -> int:
    result: dict = {
        "success": False,
        "platform": "storage",
        "test_name": "root_squash",
        "tests": {
            "enable_root_squash": {"passed": False, "message": ""},
            "root_squashed": {"passed": False, "message": ""},
            "disable_root_squash": {"passed": False, "message": ""},
            "root_unsquashed": {"passed": False, "message": ""},
        },
    }

    if DEMO_MODE:
        for key in result["tests"]:
            result["tests"][key] = {"passed": True, "message": f"demo: {key} ok"}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    squash_file = f"rootsquash-test-{uuid.uuid4().hex[:8]}"
    unsquash_file = f"rootsquash-test-{uuid.uuid4().hex[:8]}"

    try:
        ensure_namespace()
        nfs_ip = resolve_nfs_server()

        # --- 1. Enable root_squash ---
        ok, msg = toggle_root_squash(enable=True)
        result["tests"]["enable_root_squash"] = {"passed": ok, "message": msg}
        if not ok:
            print(json.dumps(result, indent=2))
            return 0

        # --- 2. Verify root is squashed ---
        ok, msg = write_file_as_root(squash_file, nfs_ip)
        if not ok:
            result["tests"]["root_squashed"] = {"passed": False, "message": msg}
        else:
            ok, uid, err = check_file_uid(squash_file)
            if not ok:
                result["tests"]["root_squashed"] = {"passed": False, "message": err}
            elif uid == 0:
                result["tests"]["root_squashed"] = {
                    "passed": False,
                    "message": f"file UID is 0 (root) — root_squash not in effect",
                }
            else:
                result["tests"]["root_squashed"] = {
                    "passed": True,
                    "message": f"file UID is {uid} (squashed from root)",
                }

        # --- 3. Disable root_squash ---
        ok, msg = toggle_root_squash(enable=False)
        result["tests"]["disable_root_squash"] = {"passed": ok, "message": msg}
        if not ok:
            print(json.dumps(result, indent=2))
            return 0

        # --- 4. Verify root is NOT squashed ---
        ok, msg = write_file_as_root(unsquash_file, nfs_ip)
        if not ok:
            result["tests"]["root_unsquashed"] = {"passed": False, "message": msg}
        else:
            ok, uid, err = check_file_uid(unsquash_file)
            if not ok:
                result["tests"]["root_unsquashed"] = {"passed": False, "message": err}
            elif uid != 0:
                result["tests"]["root_unsquashed"] = {
                    "passed": False,
                    "message": f"file UID is {uid} — expected 0 (root) with no_root_squash",
                }
            else:
                result["tests"]["root_unsquashed"] = {
                    "passed": True,
                    "message": "file UID is 0 (root retained with no_root_squash)",
                }

        result["success"] = all(t["passed"] for t in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)
        result["error_type"] = type(e).__name__
    finally:
        cleanup_test_files(squash_file, unsquash_file)
        cleanup_namespace()

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
