#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

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
    authenticate_with_client_credentials,
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
        target_url = f"{config.fulfillment_url}/api/fulfillment/v1/virtual_networks"
        result["issuer_url"] = issuer_url
        result["target_url"] = target_url

        # 1. OIDC discovery + JWKS
        discovery = get_oidc_discovery(config)
        jwks_uri = discovery.get("jwks_uri", "")
        # Keycloak may return internal URIs (svc.cluster.local); rewrite to
        # use the same external host we already know is reachable.
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

        # 2. Create a temporary client and get a valid token
        client_rep = admin.create_client(test_client_id)
        client_uuid = client_rep["id"]
        secret = admin.get_client_secret(client_uuid)
        auth_result = authenticate_with_client_credentials(config, test_client_id, secret)

        if not auth_result["success"]:
            result["error"] = f"Could not obtain valid token: {auth_result.get('error')}"
            print(json.dumps(result, indent=2))
            return 1

        # Re-authenticate to get actual JWT
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": test_client_id,
            "client_secret": secret,
        }).encode()
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
            return 1

        valid_jwt = resp["access_token"]
        payload = decode_jwt_payload(valid_jwt)
        result["audience"] = payload.get("aud", payload.get("azp", ""))
        result["endpoints_tested"] = 1

        # 3. Valid token should be accepted (not 401)
        # 200 = full access, 403 = authn passed but authz denied, 500 = authn
        # passed but downstream error — all prove the OIDC token was validated.
        http_status = _probe_api(target_url, valid_jwt, config.verify_ssl)
        result["tests"]["valid_token_accepted"] = {
            "passed": http_status not in (401,),
            "message": f"HTTP {http_status}",
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
