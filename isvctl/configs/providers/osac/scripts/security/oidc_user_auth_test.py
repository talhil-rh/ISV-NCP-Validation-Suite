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

"""OIDC user authentication test for OSAC (Keycloak + Fulfillment Service).

Mints a valid Keycloak token, probes the fulfillment-service API, then
crafts tokens with bad signature, wrong issuer, wrong audience, expired,
and missing claims to verify rejection. Also validates OIDC discovery and
JWKS endpoints.

Covers SEC01-01.

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "oidc_user_auth_test",
    "issuer_url": "https://...",
    "audience": "...",
    "target_url": "https://...",
    "endpoints_tested": 1,
    "tests": {
        "valid_token_accepted":            {"passed": true},
        "bad_signature_rejected":          {"passed": true},
        "wrong_issuer_rejected":           {"passed": true},
        "wrong_audience_rejected":         {"passed": true},
        "expired_token_rejected":          {"passed": true},
        "missing_required_claim_rejected": {"passed": true},
        "discovery_and_jwks_reachable":    {"passed": true}
    }
}
"""

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import urllib.parse

from common.osac_client import (
    KeycloakAdmin,
    _request,
    _token_endpoint,
    craft_jwt,
    decode_jwt_payload,
    get_admin_token,
    get_env_config,
    get_jwks,
    get_oidc_discovery,
)

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def _probe_api(target_url: str, token: str, verify_ssl: bool) -> int:
    """Send a request to the target API with the given bearer token. Returns HTTP status."""
    status, _ = _request(
        target_url,
        headers={"Authorization": f"Bearer {token}"},
        verify_ssl=verify_ssl,
    )
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="OIDC user auth test (OSAC/Keycloak)")
    parser.add_argument("--region", default="osac-default")
    parser.add_argument("--admin-client-id", help="Bootstrapped admin client ID")
    parser.add_argument("--admin-client-secret", help="Bootstrapped admin client secret")
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "oidc_user_auth_test",
        "issuer_url": "",
        "audience": "",
        "target_url": "",
        "endpoints_tested": 0,
        "tests": {
            "valid_token_accepted": {"passed": False},
            "bad_signature_rejected": {"passed": False},
            "wrong_issuer_rejected": {"passed": False},
            "wrong_audience_rejected": {"passed": False},
            "expired_token_rejected": {"passed": False},
            "missing_required_claim_rejected": {"passed": False},
            "discovery_and_jwks_reachable": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["issuer_url"] = "https://keycloak.osac.example/realms/osac"
        result["audience"] = "fulfillment-service"
        result["target_url"] = "https://fulfillment-api.osac.example/api/fulfillment/v1/capabilities"
        result["endpoints_tested"] = 1
        result["tests"] = {k: {"passed": True} for k in result["tests"]}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    test_client_id = f"isv-oidc-test-{uuid.uuid4().hex[:8]}"
    client_uuid = ""

    try:
        config = get_env_config(
            admin_client_id=args.admin_client_id,
            admin_client_secret=args.admin_client_secret,
        )

        if not config.fulfillment_url:
            result["skipped"] = True
            result["skip_reason"] = "OSAC_FULFILLMENT_URL not set; cannot probe API endpoint"
            print(json.dumps(result, indent=2))
            return 0

        token = get_admin_token(config)
        admin = KeycloakAdmin(config, token)

        issuer_url = f"{config.keycloak_url}/realms/{config.keycloak_realm}"
        # Probe the fulfillment-service API — the real auth chain
        # (Authorino JWT validation → OPA policy → fulfillment-service).
        # The test client needs a tenant group so Authorino can resolve
        # a tenant and the request doesn't 500 on empty tenants.
        target_url = f"{config.fulfillment_url}/api/fulfillment/v1/virtual_networks"
        result["issuer_url"] = issuer_url
        result["target_url"] = target_url

        # 1. OIDC discovery + JWKS
        discovery = get_oidc_discovery(config)
        jwks_uri = discovery.get("jwks_uri", "")
        internal_issuer = discovery.get("issuer", "")
        if jwks_uri and internal_issuer and internal_issuer != issuer_url:
            jwks_uri = jwks_uri.replace(internal_issuer, issuer_url)
        jwks_ok = False
        if jwks_uri:
            try:
                get_jwks(jwks_uri, verify_ssl=config.verify_ssl)
                jwks_ok = True
            except RuntimeError:
                pass
        result["audience"] = discovery.get("token_endpoint", "fulfillment-service")
        result["tests"]["discovery_and_jwks_reachable"] = {
            "passed": jwks_ok,
            "message": f"Discovery OK, JWKS at {jwks_uri}" if jwks_ok else f"JWKS fetch failed ({jwks_uri})",
        }

        # 2. Create a temporary client with a tenant group, get a valid token
        client_rep = admin.create_client(test_client_id)
        client_uuid = client_rep["id"]
        secret = admin.get_client_secret(client_uuid)

        # Assign to isv-test-tenant group so JWT carries a groups claim
        # and the fulfillment-service can resolve a tenant.
        group = admin.get_group_by_name("isv-test-tenant")
        if group:
            sa_user = admin.get_service_account_user(client_uuid)
            admin.add_user_to_group(sa_user["id"], group["id"])

        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": test_client_id,
                "client_secret": secret,
            }
        ).encode()
        status, resp = _request(
            _token_endpoint(config),
            method="POST",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify_ssl=config.verify_ssl,
        )
        if status != 200 or not isinstance(resp, dict):
            result["error"] = "Failed to obtain JWT for OIDC test"
            print(json.dumps(result, indent=2))
            return 0

        valid_jwt = resp["access_token"]
        payload = decode_jwt_payload(valid_jwt)
        result["audience"] = payload.get("aud", payload.get("azp", ""))
        result["endpoints_tested"] = 1

        # 3. Valid token should be accepted by the fulfillment-service
        # auth chain (Authorino → OPA → app). Expect 200 (list
        # succeeds) or 403 (authn passed, authz denied by OPA).
        # 401 = token rejected. 500 = ambiguous server error.
        http_status = _probe_api(target_url, valid_jwt, config.verify_ssl)
        result["tests"]["valid_token_accepted"] = {
            "passed": http_status in (200, 403),
            "message": f"HTTP {http_status}" + (" (authn OK, authz denied by OPA)" if http_status == 403 else ""),
        }

        # 4. Bad signature
        bad_sig_jwt = craft_jwt(valid_jwt, corrupt_signature=True)
        http_status = _probe_api(target_url, bad_sig_jwt, config.verify_ssl)
        result["tests"]["bad_signature_rejected"] = {
            "passed": http_status in (401, 403),
            "message": f"HTTP {http_status}",
        }

        # 5. Wrong issuer
        wrong_iss_jwt = craft_jwt(valid_jwt, payload_overrides={"iss": "https://evil.example.com"})
        http_status = _probe_api(target_url, wrong_iss_jwt, config.verify_ssl)
        result["tests"]["wrong_issuer_rejected"] = {
            "passed": http_status in (401, 403),
            "message": f"HTTP {http_status}",
        }

        # 6. Wrong audience
        wrong_aud_jwt = craft_jwt(valid_jwt, payload_overrides={"aud": "wrong-audience"})
        http_status = _probe_api(target_url, wrong_aud_jwt, config.verify_ssl)
        result["tests"]["wrong_audience_rejected"] = {
            "passed": http_status in (401, 403),
            "message": f"HTTP {http_status}",
        }

        # 7. Expired token
        expired_jwt = craft_jwt(valid_jwt, payload_overrides={"exp": int(time.time()) - 3600})
        http_status = _probe_api(target_url, expired_jwt, config.verify_ssl)
        result["tests"]["expired_token_rejected"] = {
            "passed": http_status in (401, 403),
            "message": f"HTTP {http_status}",
        }

        # 8. Missing required claim (sub)
        no_sub_jwt = craft_jwt(valid_jwt, remove_claims=["sub"])
        http_status = _probe_api(target_url, no_sub_jwt, config.verify_ssl)
        result["tests"]["missing_required_claim_rejected"] = {
            "passed": http_status in (401, 403),
            "message": f"HTTP {http_status}",
        }

        result["success"] = all(t["passed"] for t in result["tests"].values())

    except Exception as e:
        result["error"] = str(e)
    finally:
        if client_uuid:
            try:
                admin.delete_client(client_uuid)
            except Exception:
                pass

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
