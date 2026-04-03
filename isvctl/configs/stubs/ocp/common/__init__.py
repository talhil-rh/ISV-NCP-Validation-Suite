# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Shared helpers for OpenShift Virtualization stub scripts."""

from .cli import (
    build_ssh_argv,
    parse_cli_bool_string,
    resolve_k8s_cli,
    resolve_ssh_cli,
    resolve_ssh_port,
    resolve_virtctl,
    run_cmd,
)
from .kubevirt_vm import (
    KubeVirtVM,
    get_uptime_via_ssh,
    wait_for_guest_ssh,
)

__all__ = [
    "KubeVirtVM",
    "build_ssh_argv",
    "parse_cli_bool_string",
    "get_uptime_via_ssh",
    "resolve_k8s_cli",
    "resolve_ssh_cli",
    "resolve_ssh_port",
    "resolve_virtctl",
    "run_cmd",
    "wait_for_guest_ssh",
]
