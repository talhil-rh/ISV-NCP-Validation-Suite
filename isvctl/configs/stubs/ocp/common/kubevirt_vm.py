# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""KubeVirt / OpenShift Virtualization VM operations shared by OCP stub scripts.

Guest SSH is exposed via a ``NodePort`` Service created by
:meth:`KubeVirtVM.create_ssh_nodeport_service`.  The Service targets the
virt-launcher pod by label, so it keeps working across stop/start/restart
cycles.  External callers (stubs and isvtest validations) connect to
``<node-ip>:<nodeport>`` -- no ``oc port-forward`` required.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

from .cli import build_ssh_argv, resolve_k8s_cli, resolve_ssh_cli, resolve_virtctl, run_cmd

VMI_RUNNING_WAIT_SEC = 600
VMI_POLL_INTERVAL_SEC = 10
VMI_GONE_WAIT_SEC = 600


class KubeVirtVM:
    """One ``VirtualMachine`` / ``VirtualMachineInstance`` pair in a namespace.

    Resolves ``oc``/``kubectl``, ``virtctl``, and the OpenSSH ``ssh`` client on
    first use.  Guest SSH goes through a ``NodePort`` Service created by
    :meth:`create_ssh_nodeport_service` (or lazily by :meth:`ensure_ssh_nodeport`).
    :attr:`ssh_port` is the **guest-side** sshd port (default ``22``).
    """

    def __init__(
        self,
        namespace: str,
        name: str,
        *,
        ssh_port: int | None = 22,
    ) -> None:
        """Args:
            namespace: Kubernetes namespace (shared VM YAML ``vpc_id``).
            name: VirtualMachine name (same as VMI name when running).
            ssh_port: Guest sshd port (default ``22``); used as ``targetPort``
                for the NodePort Service.
        """
        self.namespace = namespace
        self.name = name
        self.ssh_port = ssh_port
        self._k8s_cli: str | None = None
        self._virtctl_bin: str | None = None
        self._ssh_bin: str | None = None
        self._nodeport_info: dict[str, Any] | None = None

    @property
    def k8s_cli(self) -> str:
        if self._k8s_cli is None:
            self._k8s_cli = resolve_k8s_cli()
        return self._k8s_cli

    @property
    def virtctl_bin(self) -> str:
        if self._virtctl_bin is None:
            self._virtctl_bin = resolve_virtctl()
        return self._virtctl_bin

    @property
    def ssh_bin(self) -> str:
        """OpenSSH client (``SSH`` env can override the executable)."""
        if self._ssh_bin is None:
            self._ssh_bin = resolve_ssh_cli()
        return self._ssh_bin

    def virt_launcher_pod_name(self) -> str:
        """Name of the Running virt-launcher pod for this VMI."""
        cli = self.k8s_cli
        label = f"kubevirt.io/vm={self.name}"
        proc = run_cmd(
            [
                cli,
                "get",
                "pods",
                "-n",
                self.namespace,
                "-l",
                label,
                "-o",
                "json",
            ],
            timeout=120,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise RuntimeError(f"{cli} get pods failed ({label}): {err}")
        data = json.loads(proc.stdout)
        items = data.get("items") or []
        running = [
            p
            for p in items
            if isinstance(p, dict) and (p.get("status") or {}).get("phase") == "Running"
        ]
        if running:
            meta = running[0].get("metadata") or {}
            pod_name = meta.get("name")
            if isinstance(pod_name, str) and pod_name:
                return pod_name
        raise RuntimeError(
            f"No Running virt-launcher pod for VMI {self.name!r} in namespace {self.namespace!r} "
            f"(label {label})",
        )

    def read_virtual_machine(self, *, timeout: int = 120) -> dict[str, Any]:
        """Fetch the ``VirtualMachine`` object; raises if missing or API error."""
        cli = self.k8s_cli
        proc = run_cmd(
            [cli, "get", "virtualmachine", self.name, "-n", self.namespace, "-o", "json"],
            timeout=timeout,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            if "NotFound" in err or "not found" in err.lower():
                raise RuntimeError(f"VirtualMachine {self.name!r} not found in namespace {self.namespace!r}")
            raise RuntimeError(f"{cli} get virtualmachine failed: {err}")
        return json.loads(proc.stdout)

    def read_vmi_optional(self, *, timeout: int = 120) -> dict[str, Any] | None:
        """Return ``VirtualMachineInstance`` JSON, or ``None`` if it does not exist."""
        cli = self.k8s_cli
        proc = run_cmd(
            [cli, "get", "virtualmachineinstance", self.name, "-n", self.namespace, "-o", "json"],
            timeout=timeout,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            if "NotFound" in err or "not found" in err.lower():
                return None
            raise RuntimeError(f"{cli} get virtualmachineinstance failed: {err}")
        return json.loads(proc.stdout)

    @staticmethod
    def vmi_phase(vmi: dict[str, Any] | None) -> str | None:
        """Return VMI ``status.phase``, or ``None`` if there is no VMI."""
        if not vmi:
            return None
        status = vmi.get("status") or {}
        phase = status.get("phase")
        return phase if isinstance(phase, str) else None

    @staticmethod
    def first_interface_ip(interfaces: list[dict[str, Any]] | None) -> str | None:
        """First non-empty ``ipAddress`` on VMI ``status.interfaces``."""
        if not interfaces:
            return None
        for iface in interfaces:
            ip = iface.get("ipAddress")
            if isinstance(ip, str) and ip:
                return ip
        return None

    @staticmethod
    def guest_ip_from_vmi(vmi: dict[str, Any] | None) -> str | None:
        """First interface IP from a VMI object (``status.interfaces``)."""
        if not vmi:
            return None
        status = vmi.get("status") or {}
        raw = status.get("interfaces")
        ifaces = raw if isinstance(raw, list) else None
        return KubeVirtVM.first_interface_ip(ifaces)

    def ensure_ssh_nodeport(self) -> dict[str, Any]:
        """Create (or re-read) the SSH NodePort Service and return cached info.

        Returns ``{"node_ip": "<ip>", "node_port": <int>}``.
        Idempotent: ``kubectl apply`` updates in place if the Service exists.
        """
        if self._nodeport_info is not None:
            return self._nodeport_info
        remote = 22 if self.ssh_port is None else self.ssh_port
        self._nodeport_info = self.create_ssh_nodeport_service(remote_port=remote)
        return self._nodeport_info

    def wait_guest_ssh(
        self,
        key_file: str,
        user: str,
        *,
        max_attempts: int = 30,
        interval: int = 10,
    ) -> tuple[bool, str]:
        """Poll until ``ssh`` can run ``true`` on the guest via NodePort."""
        info = self.ensure_ssh_nodeport()
        return wait_for_guest_ssh(
            self.ssh_bin,
            info["node_ip"],
            user,
            key_file,
            port=info["node_port"],
            max_attempts=max_attempts,
            interval=interval,
        )

    def guest_uptime_ssh(
        self,
        key_file: str,
        user: str,
    ) -> float | None:
        """Read ``/proc/uptime`` first field on the guest via NodePort SSH."""
        info = self.ensure_ssh_nodeport()
        return get_uptime_via_ssh(
            self.ssh_bin,
            info["node_ip"],
            user,
            key_file,
            port=info["node_port"],
        )

    def wait_running(
        self,
        *,
        timeout_sec: int = VMI_RUNNING_WAIT_SEC,
        poll_sec: int = VMI_POLL_INTERVAL_SEC,
    ) -> dict[str, Any]:
        """Poll until VMI phase is ``Running`` or timeout / terminal failure."""
        deadline = time.monotonic() + timeout_sec
        last_phase: str | None = None
        while time.monotonic() < deadline:
            vmi = self.read_vmi_optional()
            phase = self.vmi_phase(vmi)
            last_phase = phase
            if phase == "Running" and vmi is not None:
                return vmi
            if phase in ("Failed", "Unknown") and vmi is not None:
                raise RuntimeError(f"VMI entered phase {phase!r} while waiting for Running")
            print(
                f"  Waiting for VMI Running... (phase={phase!r})",
                file=sys.stderr,
            )
            time.sleep(poll_sec)
        raise RuntimeError(
            f"Timeout waiting for VMI {self.name!r} to reach Running (last phase={last_phase!r})",
        )

    def wait_vmi_deleted(
        self,
        *,
        timeout_sec: int = VMI_GONE_WAIT_SEC,
        poll_sec: int = VMI_POLL_INTERVAL_SEC,
    ) -> None:
        """Poll until the VMI object is gone."""
        deadline = time.monotonic() + timeout_sec
        last_phase: str | None = None
        while time.monotonic() < deadline:
            vmi = self.read_vmi_optional()
            if vmi is None:
                return
            last_phase = self.vmi_phase(vmi)
            print(
                f"  Waiting for VMI to terminate... (phase={last_phase!r})",
                file=sys.stderr,
            )
            time.sleep(poll_sec)
        raise RuntimeError(
            f"Timeout waiting for VMI {self.name!r} to be removed (last phase={last_phase!r})",
        )

    def start(self, *, timeout: int = 120) -> None:
        """Run ``virtctl start``; raises ``RuntimeError`` on failure."""
        proc = run_cmd(
            [self.virtctl_bin, "start", self.name, "-n", self.namespace],
            timeout=timeout,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise RuntimeError(f"virtctl start failed: {err}")

    def stop(self, *, timeout: int = 120) -> None:
        """Run ``virtctl stop``; raises ``RuntimeError`` on failure."""
        proc = run_cmd(
            [self.virtctl_bin, "stop", self.name, "-n", self.namespace],
            timeout=timeout,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise RuntimeError(f"virtctl stop failed: {err}")

    def restart(self, *, timeout: int = 120) -> None:
        """Run ``virtctl restart``; raises ``RuntimeError`` on failure."""
        proc = run_cmd(
            [self.virtctl_bin, "restart", self.name, "-n", self.namespace],
            timeout=timeout,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise RuntimeError(f"virtctl restart failed: {err}")

    def create_ssh_nodeport_service(self, remote_port: int = 22, *, timeout: int = 120) -> dict[str, Any]:
        """Create a ``NodePort`` Service exposing guest SSH for external access.

        The Service targets the virt-launcher pod via the ``vm.kubevirt.io/name``
        label selector, which KubeVirt sets on the launcher pod automatically.

        Returns ``{"node_ip": "<ip>", "node_port": <int>}`` on success.  The
        caller can hand these to validations as ``public_ip`` / ``ssh_port`` so
        that SSH-based checks connect directly without ``oc port-forward``.
        """
        svc_name = f"{self.name}-ssh"
        cli = self.k8s_cli

        svc_manifest = json.dumps({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": svc_name,
                "namespace": self.namespace,
                "labels": {"app.kubernetes.io/managed-by": "isvctl"},
            },
            "spec": {
                "type": "NodePort",
                "selector": {"vm.kubevirt.io/name": self.name},
                "ports": [{
                    "name": "ssh",
                    "protocol": "TCP",
                    "port": remote_port,
                    "targetPort": remote_port,
                }],
            },
        })

        proc = run_cmd(
            [cli, "apply", "-f", "-", "-n", self.namespace],
            timeout=timeout,
            stdin_data=svc_manifest,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise RuntimeError(f"Failed to create SSH NodePort Service: {err}")

        # Read back the Service to get the assigned NodePort
        proc = run_cmd(
            [cli, "get", "service", svc_name, "-n", self.namespace, "-o", "json"],
            timeout=timeout,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"Failed to read SSH NodePort Service: {err}")

        svc = json.loads(proc.stdout)
        ports = (svc.get("spec") or {}).get("ports") or []
        node_port: int | None = None
        for p in ports:
            if p.get("name") == "ssh" or p.get("port") == remote_port:
                node_port = p.get("nodePort")
                break
        if not node_port:
            raise RuntimeError(f"Service {svc_name!r} has no nodePort assigned")

        node_ip = self._get_node_ip(timeout=timeout)
        return {"node_ip": node_ip, "node_port": node_port}

    def delete_ssh_nodeport_service(self, *, timeout: int = 60) -> None:
        """Delete the SSH NodePort Service (idempotent)."""
        svc_name = f"{self.name}-ssh"
        cli = self.k8s_cli
        proc = run_cmd(
            [cli, "delete", "service", svc_name, "-n", self.namespace, "--ignore-not-found"],
            timeout=timeout,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            print(f"Warning: failed to delete Service {svc_name}: {err}", file=sys.stderr)

    def _get_node_ip(self, *, timeout: int = 120) -> str:
        """Return the host IP of the node running the virt-launcher pod."""
        cli = self.k8s_cli
        pod = self.virt_launcher_pod_name()
        proc = run_cmd(
            [cli, "get", "pod", pod, "-n", self.namespace, "-o", "jsonpath={.status.hostIP}"],
            timeout=timeout,
        )
        if proc.returncode != 0 or not (proc.stdout or "").strip():
            raise RuntimeError(
                f"Cannot determine node IP for pod {pod!r}: "
                f"{(proc.stderr or proc.stdout or '').strip()}"
            )
        return proc.stdout.strip()

    def serial_console(self, *, timeout_sec: int) -> subprocess.CompletedProcess[str]:
        """Run ``virtctl console`` with a wall-clock timeout.

        May raise ``subprocess.TimeoutExpired`` (same as ``subprocess.run``).
        """
        argv = [
            self.virtctl_bin,
            "-n",
            self.namespace,
            "console",
            self.name,
        ]
        return run_cmd(argv, timeout=max(5, timeout_sec))


def wait_for_guest_ssh(
    ssh_bin: str,
    host: str,
    user: str,
    key_file: str,
    *,
    port: int | None = None,
    before_attempt: Callable[[], int | None] | None = None,
    max_attempts: int = 30,
    interval: int = 10,
) -> tuple[bool, str]:
    """Wait until ``ssh`` can run ``true`` on the guest.

    If ``before_attempt`` is set, it is called at the start of each attempt and
    must return the TCP port for ``ssh -p``.  When set, ``port`` is ignored.
    """
    target = f"{user}@{host}"
    last_err = ""
    for attempt in range(1, max_attempts + 1):
        eff_port: int | None = before_attempt() if before_attempt is not None else port
        port_note = f" port {eff_port}" if eff_port is not None else ""
        try:
            argv = build_ssh_argv(ssh_bin, key_file, user, host, ["true"], port=eff_port)
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode == 0:
                print(f"  ssh ready after attempt {attempt} ({target}{port_note})", file=sys.stderr)
                return True, ""
            combined = (proc.stderr or proc.stdout or "").strip()
            last_err = combined or f"exit code {proc.returncode}"
            if attempt == 1 or attempt % 5 == 0:
                print(f"  ssh attempt {attempt} failed: {last_err[:500]}", file=sys.stderr)
        except subprocess.TimeoutExpired:
            last_err = "ssh subprocess timed out (120s)"
            print(f"  {last_err} (attempt {attempt})", file=sys.stderr)
        except OSError as e:
            last_err = str(e)
            print(f"  ssh OSError: {last_err}", file=sys.stderr)

        print(f"  Waiting for ssh... (attempt {attempt}/{max_attempts})", file=sys.stderr)
        time.sleep(interval)

    return False, last_err


def get_uptime_via_ssh(
    ssh_bin: str,
    host: str,
    user: str,
    key_file: str,
    *,
    port: int | None = None,
) -> float | None:
    """Read the first field of ``/proc/uptime`` on the guest via OpenSSH."""
    argv = build_ssh_argv(ssh_bin, key_file, user, host, ["cat", "/proc/uptime"], port=port)
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        return None
    parts = proc.stdout.strip().split()
    if not parts:
        return None
    try:
        return float(parts[0])
    except ValueError:
        return None
