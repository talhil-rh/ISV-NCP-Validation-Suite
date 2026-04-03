# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Resolve ``oc``/``kubectl``/``virtctl``/``ssh`` and run subprocess helpers for OCP stubs."""

import argparse
import os
import shutil
import subprocess


def resolve_k8s_cli() -> str:
    """Return ``oc`` or ``kubectl`` for Kubernetes API calls.

    Returns:
        Executable name or path from ``OC`` / ``KUBECTL``, else first of
        ``oc``, ``kubectl`` on ``PATH``.

    Raises:
        FileNotFoundError: If no suitable CLI is available.
    """
    for env_var in ("OC", "KUBECTL"):
        override = os.environ.get(env_var)
        if override and shutil.which(override):
            return override
    for cmd in ("oc", "kubectl"):
        if shutil.which(cmd):
            return cmd
    raise FileNotFoundError(
        "No 'oc' or 'kubectl' on PATH (or OC/KUBECTL). "
        "Install OpenShift/Kubernetes CLI and use the same kubeconfig as virtctl."
    )


def resolve_virtctl() -> str:
    """Return ``virtctl`` binary path or name.

    Raises:
        FileNotFoundError: If ``virtctl`` is not available.
    """
    override = os.environ.get("VIRTCTL")
    if override and shutil.which(override):
        return override
    if shutil.which("virtctl"):
        return "virtctl"
    raise FileNotFoundError(
        "virtctl not on PATH. Install the KubeVirt client or set VIRTCTL to the binary path."
    )


def resolve_ssh_cli() -> str:
    """Return OpenSSH ``ssh`` binary path or name.

    ``SSH`` environment variable overrides the executable when set and found on ``PATH``.

    Raises:
        FileNotFoundError: If ``ssh`` is not available.
    """
    override = os.environ.get("SSH")
    if override and shutil.which(override):
        return override
    if shutil.which("ssh"):
        return "ssh"
    raise FileNotFoundError("No 'ssh' on PATH. Install OpenSSH client or set SSH to the binary path.")


def resolve_ssh_port(cli_port: int | None) -> int | None:
    """Return TCP port where sshd listens: ``cli_port`` if set, else valid ``SSH_PORT`` env, else ``None``.

    Use for OpenSSH ``-p`` (``None`` omits ``-p``, defaulting to 22).
    Also used as ``targetPort`` when creating the NodePort Service.
    Invalid ``SSH_PORT`` values are ignored.
    """
    if cli_port is not None:
        return cli_port
    raw = (os.environ.get("SSH_PORT") or "").strip()
    if not raw:
        return None
    try:
        p = int(raw, 10)
    except ValueError:
        return None
    if 1 <= p <= 65535:
        return p
    return None


def parse_cli_bool_string(value: str) -> bool:
    """Parse true/false for argparse ``type=`` (e.g. ``--flag true`` from templated configs).

    Raises:
        argparse.ArgumentTypeError: If ``value`` is not a recognized boolean string.
    """
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off", ""):
        return False
    msg = f"expected a boolean string, got {value!r}"
    raise argparse.ArgumentTypeError(msg)


def build_ssh_argv(
    ssh_bin: str,
    key_file: str,
    user: str,
    host: str,
    remote_cmd: list[str],
    *,
    port: int | None = None,
) -> list[str]:
    """Build argv for non-interactive ``ssh`` (strict host key off, batch, connect timeout)."""
    argv: list[str] = [ssh_bin]
    if port is not None:
        argv.extend(["-p", str(port)])
    argv.extend(
        [
            "-i",
            key_file,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            f"{user}@{host}",
        ],
    )
    argv.extend(remote_cmd)
    return argv


def run_cmd(
    argv: list[str],
    *,
    timeout: int = 120,
    stdin_data: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command and return the completed process.

    Args:
        argv: Command and arguments.
        timeout: Maximum wall-clock seconds.
        stdin_data: Optional string to feed to the process on stdin
            (e.g. a JSON manifest for ``kubectl apply -f -``).
    """
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        input=stdin_data,
    )
