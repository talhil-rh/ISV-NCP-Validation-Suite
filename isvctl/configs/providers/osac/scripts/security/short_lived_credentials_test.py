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

"""Short-lived credentials test for OSAC.

Verifies that both node-side and workload-side credentials have finite,
bounded TTL:

* Node-side: Keycloak access token lifespan (realm configuration)
* Workload-side: Kubernetes ServiceAccount token TTL (kubectl create token)

Covers SEC02-01.

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "short_lived_credentials_test",
    "node_credential_ttl_seconds": 300,
    "workload_credential_ttl_seconds": 3600,
    "max_ttl_seconds": 43200,
    "tests": {
        "node_credential_has_expiry":       {"passed": true},
        "node_credential_ttl_within_bound": {"passed": true},
        "workload_credential_has_expiry":       {"passed": true},
        "workload_credential_ttl_within_bound": {"passed": true}
    }
}
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import (
    KeycloakAdmin,
    create_sa_token,
    get_admin_token,
    get_env_config,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
DEFAULT_MAX_TTL_SECONDS = 43200  # 12h


def main() -> int:
    parser = argparse.ArgumentParser(description="Short-lived credentials test (OSAC)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    parser.add_argument("--max-ttl-seconds", type=int, default=DEFAULT_MAX_TTL_SECONDS)
    parser.add_argument("--sa-namespace", default="osac-e2e-ci", help="Namespace for SA token test")
    parser.add_argument("--sa-name", default="default", help="ServiceAccount name for token test")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "short_lived_credentials_test",
        "node_credential_method": "",
        "workload_credential_method": "",
        "node_credential_ttl_seconds": 0,
        "workload_credential_ttl_seconds": 0,
        "max_ttl_seconds": args.max_ttl_seconds,
        "tests": {
            "node_credential_has_expiry": {"passed": False},
            "node_credential_ttl_within_bound": {"passed": False},
            "workload_credential_has_expiry": {"passed": False},
            "workload_credential_ttl_within_bound": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["node_credential_method"] = "keycloak-access-token"
        result["workload_credential_method"] = "k8s-sa-token"
        result["node_credential_ttl_seconds"] = 300
        result["workload_credential_ttl_seconds"] = 3600
        result["tests"] = {k: {"passed": True} for k in result["tests"]}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
        )
        token = get_admin_token(config)
        admin = KeycloakAdmin(config, token)

        # Node-side: Keycloak access token lifespan from realm settings
        try:
            realm_settings = admin.get_realm_settings()
            access_token_lifespan = realm_settings.get("accessTokenLifespan", 0)
        except RuntimeError:
            # Fallback: decode the admin token to get its TTL directly
            from common.osac_client import decode_jwt_payload

            payload = decode_jwt_payload(token)
            exp = payload.get("exp", 0)
            iat = payload.get("iat", 0)
            access_token_lifespan = exp - iat if exp and iat else 0

        result["node_credential_method"] = "keycloak-access-token"
        result["node_credential_ttl_seconds"] = access_token_lifespan

        if access_token_lifespan > 0:
            result["tests"]["node_credential_has_expiry"] = {
                "passed": True,
                "message": f"Access token lifespan: {access_token_lifespan}s",
            }
            within_bound = access_token_lifespan <= args.max_ttl_seconds
            result["tests"]["node_credential_ttl_within_bound"] = {
                "passed": within_bound,
                "message": f"{access_token_lifespan}s {'<=' if within_bound else '>'} {args.max_ttl_seconds}s bound",
            }
        else:
            result["tests"]["node_credential_has_expiry"] = {
                "passed": False,
                "message": "accessTokenLifespan not set or 0",
            }

        # Workload-side: K8s ServiceAccount token
        try:
            _, wl_ttl = create_sa_token(args.sa_namespace, args.sa_name, "3600s")
            result["workload_credential_method"] = "k8s-sa-token"
            result["workload_credential_ttl_seconds"] = wl_ttl

            result["tests"]["workload_credential_has_expiry"] = {
                "passed": wl_ttl > 0,
                "message": f"SA token TTL: {wl_ttl}s",
            }
            within_bound = wl_ttl <= args.max_ttl_seconds
            result["tests"]["workload_credential_ttl_within_bound"] = {
                "passed": within_bound,
                "message": f"{wl_ttl}s {'<=' if within_bound else '>'} {args.max_ttl_seconds}s bound",
            }
        except RuntimeError as e:
            result["tests"]["workload_credential_has_expiry"] = {
                "passed": False,
                "message": f"Could not create SA token: {e}",
            }

        result["success"] = all(t["passed"] for t in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
