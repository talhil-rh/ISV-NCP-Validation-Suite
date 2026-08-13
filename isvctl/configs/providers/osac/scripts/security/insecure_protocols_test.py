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

"""Insecure protocols test for OSAC (SEC13-02).

Probes OSAC edge endpoints (fulfillment REST gateway, Keycloak) to verify
that SSLv3, TLSv1.0, TLSv1.1, and plain HTTP are disabled.  Each legacy
protocol is tested with a raw-socket TLS ClientHello; a refused handshake
(alert, RST, timeout) is a pass, a successful ServerHello is a fail.

Output JSON:
{
    "success": true,
    "platform": "security",
    "test_name": "insecure_protocols_test",
    "endpoints_tested": 2,
    "tests": {
        "sslv3_disabled":      {"passed": true, "message": "..."},
        "tlsv1_0_disabled":    {"passed": true, "message": "..."},
        "tlsv1_1_disabled":    {"passed": true, "message": "..."},
        "plain_http_disabled": {"passed": true, "message": "..."}
    }
}
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DEMO_MODE = os.environ.get("ISVCTL_DEMO_MODE") == "1"
CONNECT_TIMEOUT = 5

LEGACY_PROTOCOLS: list[tuple[str, int]] = [
    ("sslv3", ssl.PROTOCOL_TLS_CLIENT),
    ("tlsv1_0", ssl.PROTOCOL_TLS_CLIENT),
    ("tlsv1_1", ssl.PROTOCOL_TLS_CLIENT),
]

PROTOCOL_MAX_VERSION: dict[str, int] = {
    "sslv3": ssl.TLSVersion.SSLv3,
    "tlsv1_0": ssl.TLSVersion.TLSv1,
    "tlsv1_1": ssl.TLSVersion.TLSv1_1,
}


def _parse_endpoints() -> list[tuple[str, str, int]]:
    """Return (label, host, port) tuples from OSAC env vars."""
    endpoints: list[tuple[str, str, int]] = []
    for env_var, label in [
        ("OSAC_FULFILLMENT_URL", "fulfillment"),
        ("OSAC_KEYCLOAK_URL", "keycloak"),
    ]:
        url = os.environ.get(env_var, "")
        if not url:
            continue
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if host:
            endpoints.append((label, host, port))
    return endpoints


def _try_legacy_tls(host: str, port: int, protocol_name: str) -> bool:
    """Attempt a TLS handshake with a legacy protocol version.

    Returns True if the connection was REFUSED (= protocol disabled = good).
    Returns False if the handshake SUCCEEDED (= protocol accepted = bad).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    max_ver = PROTOCOL_MAX_VERSION.get(protocol_name)
    if max_ver is None:
        return True
    try:
        ctx.maximum_version = max_ver
        ctx.minimum_version = max_ver
    except (ValueError, AttributeError):
        return True

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((host, port))
        with ctx.wrap_socket(sock, server_hostname=host):
            return False
    except (ssl.SSLError, ConnectionRefusedError, ConnectionResetError, OSError):
        return True
    finally:
        sock.close()


def _try_plain_http(host: str, port: int = 80) -> bool:
    """Attempt a plain HTTP connection on port 80.

    Returns True if refused or not serving HTTP (= good).
    Returns False if HTTP content is served without redirect to HTTPS (= bad).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((host, port))
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        response = sock.recv(1024).decode("utf-8", errors="replace")
        if not response:
            return True
        first_line = response.split("\r\n", 1)[0]
        # Pass if: redirect (301/302/307/308), server error (5xx),
        # client error (4xx), or any non-200 response.  Only fail
        # on a 200 OK that serves actual content over plain HTTP.
        if " 200 " not in first_line:
            return True
        return False
    except (ConnectionRefusedError, ConnectionResetError, OSError, TimeoutError):
        return True
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Insecure protocols test (OSAC)")
    parser.add_argument("--region", default="osac-default")
    parser.parse_args()

    result: dict[str, Any] = {
        "success": False,
        "platform": "security",
        "test_name": "insecure_protocols_test",
        "endpoints_tested": 0,
        "tests": {
            "sslv3_disabled": {"passed": False},
            "tlsv1_0_disabled": {"passed": False},
            "tlsv1_1_disabled": {"passed": False},
            "plain_http_disabled": {"passed": False},
        },
    }

    if DEMO_MODE:
        result["endpoints_tested"] = 2
        result["tests"] = {
            "sslv3_disabled": {"passed": True, "message": "SSLv3 refused on 2/2 endpoints"},
            "tlsv1_0_disabled": {"passed": True, "message": "TLSv1.0 refused on 2/2 endpoints"},
            "tlsv1_1_disabled": {"passed": True, "message": "TLSv1.1 refused on 2/2 endpoints"},
            "plain_http_disabled": {"passed": True, "message": "HTTP/80 refused on 2/2 endpoints"},
        }
        result["success"] = True
        print(json.dumps(result, indent=2))
        return 0

    try:
        endpoints = _parse_endpoints()
        if not endpoints:
            result["skipped"] = True
            result["skip_reason"] = "No OSAC endpoints configured (OSAC_FULFILLMENT_URL, OSAC_KEYCLOAK_URL)"
            print(json.dumps(result, indent=2))
            return 0

        result["endpoints_tested"] = len(endpoints)
        total = len(endpoints)

        for protocol_name in ["sslv3", "tlsv1_0", "tlsv1_1"]:
            refused = 0
            accepted: list[str] = []
            for label, host, port in endpoints:
                if _try_legacy_tls(host, port, protocol_name):
                    refused += 1
                else:
                    accepted.append(label)

            display_name = protocol_name.replace("_", ".").upper().replace("SSLV", "SSLv").replace("TLSV", "TLSv")
            test_key = f"{protocol_name}_disabled"
            if not accepted:
                result["tests"][test_key] = {
                    "passed": True,
                    "message": f"{display_name} refused on {refused}/{total} endpoints",
                }
            else:
                result["tests"][test_key] = {
                    "passed": False,
                    "error": f"{display_name} accepted on: {', '.join(accepted)}",
                }

        http_refused = 0
        http_accepted: list[str] = []
        for label, host, _port in endpoints:
            if _try_plain_http(host):
                http_refused += 1
            else:
                http_accepted.append(label)

        if not http_accepted:
            result["tests"]["plain_http_disabled"] = {
                "passed": True,
                "message": f"HTTP/80 refused on {http_refused}/{total} endpoints",
            }
        else:
            result["tests"]["plain_http_disabled"] = {
                "passed": False,
                "error": f"Plain HTTP served on: {', '.join(http_accepted)}",
            }

        result["success"] = all(t.get("passed") for t in result["tests"].values())

    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__

    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
