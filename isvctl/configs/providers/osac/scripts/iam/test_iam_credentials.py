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

"""Test IAM credential identity and resource access (IAM03-01).

Two probes:
  identity — exchange the access key client credentials for a Keycloak JWT
              (client_credentials grant). Proves the key is valid.
  access   — call the Keycloak userinfo endpoint with the minted token.
              Proves the token is accepted by a protected API resource.

Output JSON:
{
    "success": true,
    "platform": "iam",
    "account_id": "<access-key-id>",
    "tests": {
        "identity": {"passed": true, "message": "authenticated as <sub>"},
        "access":   {"passed": true, "message": "userinfo returned sub=<sub>"}
    }
}
"""

import argparse
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.osac_client import get_env_config

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"


def _ssl_ctx(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_form(url: str, fields: dict[str, str], verify: bool) -> tuple[int, Any]:
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(verify), timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, body.decode(errors="replace")


def _get_bearer(url: str, token: str, verify: bool) -> tuple[int, Any]:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(verify), timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, body.decode(errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--access-key-id", required=True)
    parser.add_argument("--secret-access-key", required=True)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "iam",
        "account_id": args.access_key_id,
        "tests": {
            "identity": {"passed": False, "message": ""},
            "access": {"passed": False, "message": ""},
        },
    }

    if DEMO_MODE:
        result["tests"]["identity"] = {"passed": True, "message": "authenticated as demo-sub"}
        result["tests"]["access"] = {"passed": True, "message": "userinfo returned sub=demo-sub"}
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        config = get_env_config(require_admin=False)
        base = f"{config.keycloak_url}/realms/{config.keycloak_realm}/protocol/openid-connect"
        verify = config.verify_ssl

        # ── Identity probe ────────────────────────────────────────────────────
        status, resp = _post_form(
            f"{base}/token",
            {
                "grant_type": "client_credentials",
                "client_id": args.access_key_id,
                "client_secret": args.secret_access_key,
            },
            verify,
        )

        if status != 200 or not isinstance(resp, dict) or "access_token" not in resp:
            error = resp.get("error_description", resp.get("error", str(resp))) if isinstance(resp, dict) else str(resp)
            result["tests"]["identity"]["message"] = f"token request failed (HTTP {status}): {error}"
            print(json.dumps(result, indent=2))
            return 1

        access_token = resp["access_token"]
        sub = resp.get("sub") or "<unknown>"
        result["tests"]["identity"] = {"passed": True, "message": f"authenticated as {sub}"}

        # ── Access probe ──────────────────────────────────────────────────────
        status, resp = _get_bearer(f"{base}/userinfo", access_token, verify)

        if status == 200 and isinstance(resp, dict):
            userinfo_sub = resp.get("sub", sub)
            result["tests"]["access"] = {"passed": True, "message": f"userinfo returned sub={userinfo_sub}"}
            result["success"] = True
        else:
            result["tests"]["access"]["message"] = f"userinfo endpoint returned HTTP {status}: {resp}"

    except Exception as exc:
        result["error"] = str(exc)

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
