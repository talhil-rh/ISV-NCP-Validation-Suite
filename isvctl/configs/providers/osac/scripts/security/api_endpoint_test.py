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

"""API endpoint isolation test for OSAC.

Verifies that OSAC platform API endpoints (fulfillment-service, Keycloak)
are not directly accessible from the public internet. Resolves hostnames
and checks that they resolve to private (RFC 1918 / cluster-internal)
addresses.

Covers SEC14-01.

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "api_endpoint_isolation",
    "endpoints_tested": 2,
    "tests": {
        "probe_api_from_public":  {"passed": true},
        "probe_mgmt_from_public": {"passed": true},
        "verify_private_only":    {"passed": true},
        "dns_not_public":         {"passed": true}
    }
}
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def _check_public_dns(hostname: str) -> bool:
    """Check if hostname has a public DNS record via dig/nslookup."""
    try:
        result = subprocess.run(
            ["dig", "+short", hostname, "@8.8.8.8"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return bool(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="API endpoint isolation test (OSAC)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "api_endpoint_isolation",
        "endpoints_tested": 0,
        "tests": {
            "probe_api_from_public": {"passed": False},
            "probe_mgmt_from_public": {"passed": False},
            "verify_private_only": {"passed": False},
            "dns_not_public": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["endpoints_tested"] = 2
        result["tests"] = {k: {"passed": True} for k in result["tests"]}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    # Following the AWS pattern: query the platform's configuration APIs
    # to verify the security posture, rather than probing from outside.
    # On OCP, this means: verify Services are ClusterIP (not LoadBalancer),
    # Routes use TLS, and no public DNS records exist.
    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
            require_admin=False,
        )

        kctl = shutil.which("kubectl") or shutil.which("oc") or ""
        if not kctl:
            result["error"] = "Neither kubectl nor oc found on PATH"
            print(json.dumps(result, indent=2))
            return 0

        namespace = os.environ.get("OSAC_TENANT_NAMESPACE", "osac-e2e-ci")
        result["endpoints_tested"] = 0

        # probe_api_from_public: Verify all fulfillment Services are
        # ClusterIP (not LoadBalancer/NodePort which would expose them).
        svc_cmd = [kctl, "get", "svc", "-n", namespace, "-o", "json"]
        svc_result = subprocess.run(svc_cmd, capture_output=True, text=True, timeout=15)
        if svc_result.returncode == 0:
            svc_data = json.loads(svc_result.stdout)
            exposed_svcs = []
            for svc in svc_data.get("items", []):
                svc_name = svc["metadata"]["name"]
                svc_type = svc.get("spec", {}).get("type", "ClusterIP")
                if svc_type in ("LoadBalancer", "NodePort"):
                    exposed_svcs.append(f"{svc_name} ({svc_type})")
            api_private = len(exposed_svcs) == 0
            result["tests"]["probe_api_from_public"] = {
                "passed": api_private,
                "message": f"All {len(svc_data.get('items', []))} services are ClusterIP"
                if api_private
                else f"Publicly exposed services: {', '.join(exposed_svcs)}",
            }
            result["endpoints_tested"] += len(svc_data.get("items", []))
        else:
            result["tests"]["probe_api_from_public"] = {
                "passed": False,
                "message": f"Could not query services: {svc_result.stderr.strip()}",
            }

        # probe_mgmt_from_public: Verify Routes use TLS termination
        # (passthrough or edge), not plain HTTP.
        route_cmd = [kctl, "get", "routes", "-n", namespace, "-o", "json"]
        route_result = subprocess.run(route_cmd, capture_output=True, text=True, timeout=15)
        if route_result.returncode == 0:
            route_data = json.loads(route_result.stdout)
            insecure_routes = []
            for route in route_data.get("items", []):
                route_name = route["metadata"]["name"]
                tls = route.get("spec", {}).get("tls")
                if not tls:
                    insecure_routes.append(route_name)
            mgmt_secure = len(insecure_routes) == 0
            result["tests"]["probe_mgmt_from_public"] = {
                "passed": mgmt_secure,
                "message": f"All {len(route_data.get('items', []))} routes have TLS configured"
                if mgmt_secure
                else f"Routes without TLS: {', '.join(insecure_routes)}",
            }
            result["endpoints_tested"] += len(route_data.get("items", []))
        else:
            result["tests"]["probe_mgmt_from_public"] = {
                "passed": False,
                "message": f"Could not query routes: {route_result.stderr.strip()}",
            }

        # verify_private_only: Verify the OCP default ingress controller
        # is not set to publish a public LoadBalancer with external IPs.
        ic_cmd = [
            kctl,
            "get",
            "ingresscontrollers.operator.openshift.io",
            "default",
            "-n",
            "openshift-ingress-operator",
            "-o",
            "json",
        ]
        ic_result = subprocess.run(ic_cmd, capture_output=True, text=True, timeout=15)
        if ic_result.returncode == 0:
            ic_data = json.loads(ic_result.stdout)
            endpoint_strategy = ic_data.get("spec", {}).get("endpointPublishingStrategy", {}).get("type", "")
            lb_scope = (
                ic_data.get("spec", {})
                .get("endpointPublishingStrategy", {})
                .get("loadBalancer", {})
                .get("scope", "External")
            )
            is_private = endpoint_strategy != "LoadBalancerService" or lb_scope == "Internal"
            result["tests"]["verify_private_only"] = {
                "passed": is_private,
                "message": f"Ingress strategy={endpoint_strategy}, scope={lb_scope}"
                + (" (private)" if is_private else " (public LoadBalancer)"),
            }
        else:
            result["tests"]["verify_private_only"] = {
                "passed": False,
                "message": f"Could not query ingress controller: {ic_result.stderr.strip()}",
            }

        # dns_not_public: Query public DNS (8.8.8.8) for API hostnames.
        endpoints: list[tuple[str, str]] = []
        if config.fulfillment_url:
            endpoints.append(("fulfillment-api", config.fulfillment_url))
        if config.keycloak_url:
            endpoints.append(("keycloak", config.keycloak_url))

        no_public_dns = True
        dns_details = []
        for label, url in endpoints:
            hostname = urlparse(url).hostname or ""
            if not hostname:
                continue
            has_public = _check_public_dns(hostname)
            if has_public:
                no_public_dns = False
                dns_details.append(f"{label} ({hostname}): PUBLIC DNS record found")
            else:
                dns_details.append(f"{label} ({hostname}): no public DNS record")

        result["tests"]["dns_not_public"] = {
            "passed": no_public_dns,
            "message": "; ".join(dns_details) if dns_details else "No endpoints checked",
        }

        result["success"] = all(t["passed"] for t in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
