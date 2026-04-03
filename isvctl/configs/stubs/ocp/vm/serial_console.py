#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Check serial console access for an OpenShift Virtualization VM via ``virtctl``.

Runs ``virtctl console`` against the running VMI for a bounded time, captures
any output, and prints JSON compatible with ``SerialConsoleCheck``.

Usage:
    python serial_console.py --vpc-id my-ns --instance-id my-vm

Environment:
    OC, KUBECTL, VIRTCTL: optional overrides (same as other OCP VM stubs).
"""

from pathlib import Path
import sys

_OCP_STUB_ROOT = Path(__file__).resolve().parent.parent
if str(_OCP_STUB_ROOT) not in sys.path:
    sys.path.insert(0, str(_OCP_STUB_ROOT))

import argparse
import json
import subprocess
from typing import Any

from common.kubevirt_vm import KubeVirtVM


def _slurp_timeout_chunk(chunk: str | bytes | None) -> str:
    """Normalize ``TimeoutExpired`` stdout/stderr to ``str`` for concatenation."""
    if chunk is None:
        return ""
    if isinstance(chunk, str):
        return chunk
    return chunk.decode(errors="replace")


def hard_console_failure(text: str) -> bool:
    """Heuristic: combined output indicates console is not usable."""
    s = text.lower()
    needles = (
        "not found",
        "forbidden",
        "unauthorized",
        "connection refused",
        "no such resource",
        "unknown command",
        "does not exist",
    )
    return any(n in s for n in needles)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Serial console check via virtctl (OpenShift Virtualization / KubeVirt)"
    )
    parser.add_argument(
        "--vpc-id",
        required=True,
        help="Namespace containing the VirtualMachine / VMI",
    )
    parser.add_argument(
        "--instance-id",
        required=True,
        help="VirtualMachine / VMI name",
    )
    parser.add_argument(
        "--console-timeout",
        type=int,
        default=25,
        help="Seconds to keep virtctl console open while capturing output (default: 25)",
    )
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "vm",
        "instance_id": args.instance_id,
        "console_available": False,
        "serial_access_enabled": False,
        "output_length": 0,
    }
    combined_text = ""

    vm = KubeVirtVM(args.vpc_id, args.instance_id)

    try:
        vm.read_virtual_machine(timeout=60)
        vmi = vm.read_vmi_optional(timeout=60)
        if KubeVirtVM.vmi_phase(vmi) != "Running":
            result["error"] = f"VMI must be Running for serial console, got {KubeVirtVM.vmi_phase(vmi)!r}"
            print(json.dumps(result, indent=2))
            return 1

        result["serial_access_enabled"] = True

        timeout_sec = max(5, args.console_timeout)
        print(f"Running virtctl console (timeout={timeout_sec}s)...", file=sys.stderr)

        try:
            proc = vm.serial_console(timeout_sec=timeout_sec)
            combined_text = (proc.stdout or "") + (proc.stderr or "")
            result["output_length"] = len(combined_text)
            result["console_available"] = bool(combined_text.strip())

            if proc.returncode != 0:
                if hard_console_failure(combined_text):
                    result["serial_access_enabled"] = False
                    result["error"] = combined_text.strip()[:2000]
                    result["success"] = False
                else:
                    result["success"] = result["console_available"] or result["serial_access_enabled"]
            else:
                result["success"] = result["console_available"] or result["serial_access_enabled"]

        except subprocess.TimeoutExpired as e:
            combined_text = _slurp_timeout_chunk(e.stdout) + _slurp_timeout_chunk(e.stderr)
            result["output_length"] = len(combined_text)
            result["console_available"] = bool(combined_text.strip())
            result["serial_access_enabled"] = True
            result["success"] = True
            print(
                f"  Console read stopped at timeout ({result['output_length']} chars)",
                file=sys.stderr,
            )

        if result["output_length"] > 0:
            result["output_snippet"] = combined_text[-500:] if len(combined_text) > 500 else combined_text

    except FileNotFoundError as e:
        result["error"] = str(e)
        result["serial_access_enabled"] = False
        print(f"ERROR: {e}", file=sys.stderr)
    except (RuntimeError, json.JSONDecodeError, OSError) as e:
        result["error"] = str(e)
        result["serial_access_enabled"] = False
        print(f"ERROR: {e}", file=sys.stderr)

    if not result["success"] and not result.get("error") and not result["serial_access_enabled"]:
        result["error"] = "virtctl console did not establish access"

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
