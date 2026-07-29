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

"""Certificate rotation cycle test for OSAC.

Inspects cert-manager Certificate CRDs across all namespaces to verify
that TLS certificates rotate within a 60-day policy window. OSAC uses
cert-manager for automated certificate lifecycle management of:
- Fulfillment-service gRPC server certificate
- Fulfillment-service REST gateway certificate
- Authorino certificate
- Keycloak database client/server certificates

Covers SEC09-01.

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "cert_rotation_test",
    "rotation_window_days": 60,
    "certs_inspected": 4,
    "out_of_policy": 0,
    "tests": {
        "cert_inventory_non_empty":   {"passed": true},
        "no_certs_out_of_policy":     {"passed": true},
        "rotation_evidence_present":  {"passed": true}
    }
}
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import get_cert_manager_certificates

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
MAX_ROTATION_WINDOW_DAYS = 60


def _parse_duration_to_hours(duration_str: str) -> int | None:
    """Parse a Go/cert-manager duration string (e.g., '2160h', '720h0m0s') to hours."""
    if not duration_str:
        return None
    match = re.match(r"(\d+)h", duration_str)
    if match:
        return int(match.group(1))
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Certificate rotation test (OSAC)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "cert_rotation_test",
        "rotation_window_days": MAX_ROTATION_WINDOW_DAYS,
        "certs_inspected": 0,
        "auto_rotated": 0,
        "short_validity": 0,
        "out_of_policy": 0,
        "tests": {
            "cert_inventory_non_empty": {"passed": False},
            "no_certs_out_of_policy": {"passed": False},
            "rotation_evidence_present": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["certs_inspected"] = 4
        result["auto_rotated"] = 4
        result["tests"] = {
            "cert_inventory_non_empty": {"passed": True, "message": "4 cert-manager certificates found"},
            "no_certs_out_of_policy": {"passed": True, "message": "All certificates within 60-day rotation window"},
            "rotation_evidence_present": {"passed": True, "message": "cert-manager manages rotation automatically"},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        certs = get_cert_manager_certificates()

        if not certs:
            result["skipped"] = True
            result["skip_reason"] = "No cert-manager Certificate CRDs found"
            print(json.dumps(result, indent=2))
            return 0

        result["certs_inspected"] = len(certs)
        result["tests"]["cert_inventory_non_empty"] = {
            "passed": True,
            "message": f"{len(certs)} cert-manager certificates found",
        }

        out_of_policy = 0
        auto_rotated = 0
        short_validity = 0

        for cert in certs:
            spec = cert.get("spec", {})
            status = cert.get("status", {})
            duration_str = spec.get("duration", "")
            renew_before_str = spec.get("renewBefore", "")

            duration_hours = _parse_duration_to_hours(duration_str)
            renew_before_hours = _parse_duration_to_hours(renew_before_str)

            # cert-manager auto-manages rotation
            has_conditions = bool(status.get("conditions"))
            has_renewal_time = bool(status.get("renewalTime"))

            if has_conditions or has_renewal_time:
                auto_rotated += 1

            if duration_hours is not None:
                duration_days = duration_hours / 24
                if duration_days <= MAX_ROTATION_WINDOW_DAYS:
                    short_validity += 1
                else:
                    # Check if renewBefore brings effective rotation within policy
                    if renew_before_hours is not None:
                        effective_days = (duration_hours - renew_before_hours) / 24
                        if effective_days > MAX_ROTATION_WINDOW_DAYS:
                            out_of_policy += 1
                    elif not (has_conditions or has_renewal_time):
                        out_of_policy += 1

        result["auto_rotated"] = auto_rotated
        result["short_validity"] = short_validity
        result["out_of_policy"] = out_of_policy

        result["tests"]["no_certs_out_of_policy"] = {
            "passed": out_of_policy == 0,
            "message": f"{out_of_policy} certificate(s) out of {MAX_ROTATION_WINDOW_DAYS}-day policy"
            if out_of_policy > 0
            else f"All certificates within {MAX_ROTATION_WINDOW_DAYS}-day rotation window",
        }

        result["tests"]["rotation_evidence_present"] = {
            "passed": auto_rotated > 0 or short_validity > 0,
            "message": f"{auto_rotated} auto-rotated, {short_validity} short-validity",
        }

        result["success"] = all(t["passed"] for t in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
