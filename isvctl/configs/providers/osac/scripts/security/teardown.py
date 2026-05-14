#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Security test teardown for OSAC.

Cleans up any residual resources created during the security test phase.
Individual test scripts perform their own best-effort cleanup, so this
teardown handles any resources that survived.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import Any

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def _kubectl() -> str:
    path = shutil.which("kubectl") or shutil.which("oc")
    if not path:
        raise RuntimeError("Neither kubectl nor oc found on PATH")
    return path


def _cleanup_tenants(namespace: str) -> list[str]:
    """Delete any leftover ISV test tenants."""
    errors: list[str] = []
    try:
        cmd = [_kubectl(), "get", "tenants.osac.openshift.io", "-n", namespace,
               "-o", "jsonpath={.items[*].metadata.name}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            for name in result.stdout.strip().split():
                if name.startswith("isv-"):
                    try:
                        subprocess.run(
                            [_kubectl(), "delete", "tenants.osac.openshift.io", name,
                             "-n", namespace, "--ignore-not-found"],
                            capture_output=True, text=True, timeout=30,
                        )
                    except Exception as e:
                        errors.append(f"tenant {name}: {e}")
    except Exception as e:
        errors.append(f"tenant listing: {e}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Security test teardown (OSAC)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--namespace", default="osac-e2e-ci")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": True,
        "platform": "security",
        "test_name": "teardown",
    }

    if DEMO_MODE:
        print(json.dumps(result, indent=2))
        return 0

    cleanup_errors: list[str] = []

    tenant_errors = _cleanup_tenants(args.namespace)
    cleanup_errors.extend(tenant_errors)

    if cleanup_errors:
        result["cleanup_errors"] = cleanup_errors

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
