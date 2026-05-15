# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""OSAC shared client helpers — Keycloak admin + Fulfillment Service + Tenant CRD.

Uses only Python stdlib (``urllib.request``, ``subprocess``) so no
``requests`` dependency is needed on the target host.

Tenant lifecycle uses ``kubectl`` to manage ``osac.openshift.io/v1alpha1``
Tenant CRDs.  The fulfillment-service Organizations API (enhancement
proposal ``enhancements/organizations``) is not yet implemented; when it
lands the ``FulfillmentClient`` can be extended with org CRUD methods and
the tenant scripts switched over without touching validations.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class OsacConfig:
    """Holds validated environment configuration for OSAC scripts."""

    keycloak_url: str
    keycloak_realm: str
    admin_client_id: str
    admin_client_secret: str
    verify_ssl: bool
    fulfillment_url: str = ""
    tenant_namespace: str = "osac-e2e-ci"


def get_env_config(
    *,
    admin_client_id: str | None = None,
    admin_client_secret: str | None = None,
    require_admin: bool = True,
) -> OsacConfig:
    """Read and validate required OSAC environment variables.

    ``admin_client_id`` / ``admin_client_secret`` can be passed
    explicitly (from CLI args wired through the config YAML) to
    override the environment variables.  When ``require_admin`` is
    ``False`` the admin fields may be empty (used by bootstrap).

    Raises ``RuntimeError`` when a required variable is missing.
    """
    missing: list[str] = []
    for var in ("OSAC_KEYCLOAK_URL", "OSAC_KEYCLOAK_REALM"):
        if not os.environ.get(var):
            missing.append(var)

    cid = admin_client_id or os.environ.get("OSAC_ADMIN_CLIENT_ID", "")
    csecret = admin_client_secret or os.environ.get("OSAC_ADMIN_CLIENT_SECRET", "")
    if require_admin:
        if not cid:
            missing.append("OSAC_ADMIN_CLIENT_ID (or --admin-client-id)")
        if not csecret:
            missing.append("OSAC_ADMIN_CLIENT_SECRET (or --admin-client-secret)")

    if missing:
        raise RuntimeError(f"Missing required configuration: {', '.join(missing)}")

    verify_ssl = os.environ.get("OSAC_VERIFY_SSL", "true").lower() != "false"

    return OsacConfig(
        keycloak_url=os.environ["OSAC_KEYCLOAK_URL"].rstrip("/"),
        keycloak_realm=os.environ["OSAC_KEYCLOAK_REALM"],
        admin_client_id=cid,
        admin_client_secret=csecret,
        verify_ssl=verify_ssl,
        fulfillment_url=os.environ.get("OSAC_FULFILLMENT_URL", "").rstrip("/"),
        tenant_namespace=os.environ.get("OSAC_TENANT_NAMESPACE", "osac-e2e-ci"),
    )


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------


def _ssl_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    verify_ssl: bool = True,
) -> tuple[int, dict[str, Any] | str]:
    """Issue an HTTP request and return ``(status_code, body)``.

    ``body`` is parsed as JSON when possible, otherwise returned as a string.
    """
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)

    ctx = _ssl_context(verify_ssl)
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode() if exc.fp else ""
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------


def _token_endpoint(config: OsacConfig) -> str:
    return f"{config.keycloak_url}/realms/{config.keycloak_realm}/protocol/openid-connect/token"


def get_admin_token(config: OsacConfig) -> str:
    """Obtain a bearer token using the admin service-account client credentials."""
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": config.admin_client_id,
            "client_secret": config.admin_client_secret,
        }
    ).encode()

    status, resp = _request(
        _token_endpoint(config),
        method="POST",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        verify_ssl=config.verify_ssl,
    )
    if status != 200 or not isinstance(resp, dict) or "access_token" not in resp:
        raise RuntimeError(f"Failed to obtain admin token (HTTP {status}): {resp}")
    return resp["access_token"]


def authenticate_with_client_credentials(
    config: OsacConfig, client_id: str, client_secret: str
) -> dict[str, Any]:
    """Attempt ``client_credentials`` grant with *test* client creds.

    Returns ``{"success": True, "sub": "..."}`` on success,
    ``{"success": False, "error": "...", "error_code": "..."}`` on failure.
    """
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
    ).encode()

    status, resp = _request(
        _token_endpoint(config),
        method="POST",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        verify_ssl=config.verify_ssl,
    )

    if status == 200 and isinstance(resp, dict) and "access_token" in resp:
        sub = _decode_jwt_sub(resp["access_token"])
        return {"success": True, "sub": sub}

    error = ""
    error_code = ""
    if isinstance(resp, dict):
        error = resp.get("error_description", resp.get("error", str(resp)))
        error_code = resp.get("error", "")
    else:
        error = str(resp)
        error_code = f"http_{status}"
    return {"success": False, "error": error, "error_code": error_code}


def _decode_jwt_sub(token: str) -> str:
    """Extract the ``sub`` claim from a JWT access token (no verification)."""
    parts = token.split(".")
    if len(parts) < 2:
        return "unknown"
    # Base64url decode the payload
    payload_b64 = parts[1]
    # Add padding
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("sub", "unknown")
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Keycloak Admin
# ---------------------------------------------------------------------------


class KeycloakAdmin:
    """Minimal Keycloak Admin REST API wrapper."""

    def __init__(self, config: OsacConfig, token: str) -> None:
        self._config = config
        self._base = (
            f"{config.keycloak_url}/admin/realms/{config.keycloak_realm}"
        )
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self._verify = config.verify_ssl

    def create_client(self, client_id: str) -> dict[str, Any]:
        """Create a new Keycloak client with service accounts enabled.

        Returns the representation including the server-assigned ``id`` (UUID).
        """
        payload = json.dumps(
            {
                "clientId": client_id,
                "enabled": True,
                "serviceAccountsEnabled": True,
                "clientAuthenticatorType": "client-secret",
                "protocol": "openid-connect",
                "publicClient": False,
                "standardFlowEnabled": False,
            }
        ).encode()

        status, resp = _request(
            f"{self._base}/clients",
            method="POST",
            data=payload,
            headers=self._headers,
            verify_ssl=self._verify,
        )
        # Keycloak returns 201 with empty body; location header has UUID
        if status not in (200, 201):
            raise RuntimeError(f"Failed to create client '{client_id}' (HTTP {status}): {resp}")

        # Fetch the created client to get its UUID
        return self.get_client_by_client_id(client_id)

    def get_client_secret(self, client_uuid: str) -> str:
        """GET the client secret for a client identified by its internal UUID."""
        status, resp = _request(
            f"{self._base}/clients/{client_uuid}/client-secret",
            headers=self._headers,
            verify_ssl=self._verify,
        )
        if status != 200 or not isinstance(resp, dict):
            raise RuntimeError(f"Failed to get client secret (HTTP {status}): {resp}")
        return resp["value"]

    def get_client_by_client_id(self, client_id: str) -> dict[str, Any]:
        """Look up a client by its human-readable ``clientId``."""
        encoded = urllib.parse.quote(client_id, safe="")
        status, resp = _request(
            f"{self._base}/clients?clientId={encoded}",
            headers=self._headers,
            verify_ssl=self._verify,
        )
        if status != 200 or not isinstance(resp, list) or len(resp) == 0:
            raise RuntimeError(f"Client '{client_id}' not found (HTTP {status}): {resp}")
        return resp[0]

    def get_realm_authentication_flows(self) -> list[dict[str, Any]]:
        """GET authentication flows for the realm (MFA check)."""
        status, resp = _request(
            f"{self._base}/authentication/flows",
            headers=self._headers,
            verify_ssl=self._verify,
        )
        if status != 200 or not isinstance(resp, list):
            raise RuntimeError(f"Failed to get authentication flows (HTTP {status}): {resp}")
        return resp

    def get_realm_authentication_flow_executions(self, flow_alias: str) -> list[dict[str, Any]]:
        """GET executions for a specific authentication flow."""
        encoded = urllib.parse.quote(flow_alias, safe="")
        status, resp = _request(
            f"{self._base}/authentication/flows/{encoded}/executions",
            headers=self._headers,
            verify_ssl=self._verify,
        )
        if status != 200 or not isinstance(resp, list):
            raise RuntimeError(f"Failed to get flow executions for '{flow_alias}' (HTTP {status}): {resp}")
        return resp

    def get_realm_settings(self) -> dict[str, Any]:
        """GET realm representation (token lifespan, etc.)."""
        status, resp = _request(
            f"{self._base}",
            headers=self._headers,
            verify_ssl=self._verify,
        )
        if status != 200 or not isinstance(resp, dict):
            raise RuntimeError(f"Failed to get realm settings (HTTP {status}): {resp}")
        return resp

    def get_required_actions(self) -> list[dict[str, Any]]:
        """GET required actions configured in the realm."""
        status, resp = _request(
            f"{self._base}/authentication/required-actions",
            headers=self._headers,
            verify_ssl=self._verify,
        )
        if status != 200 or not isinstance(resp, list):
            raise RuntimeError(f"Failed to get required actions (HTTP {status}): {resp}")
        return resp

    def disable_client(self, client_uuid: str) -> None:
        """Disable a client by setting ``enabled: false``."""
        payload = json.dumps({"enabled": False}).encode()
        status, resp = _request(
            f"{self._base}/clients/{client_uuid}",
            method="PUT",
            data=payload,
            headers=self._headers,
            verify_ssl=self._verify,
        )
        if status not in (200, 204):
            raise RuntimeError(f"Failed to disable client (HTTP {status}): {resp}")

    def delete_client(self, client_uuid: str) -> None:
        """Delete a client by its internal UUID."""
        status, resp = _request(
            f"{self._base}/clients/{client_uuid}",
            method="DELETE",
            headers=self._headers,
            verify_ssl=self._verify,
        )
        if status not in (200, 204):
            raise RuntimeError(f"Failed to delete client (HTTP {status}): {resp}")


# ---------------------------------------------------------------------------
# Fulfillment Service
# ---------------------------------------------------------------------------


class FulfillmentClient:
    """Minimal OSAC Fulfillment Service REST API wrapper.

    Only ``get_capabilities`` is used today (for the health check).
    Organization / project CRUD will be added here once the
    ``enhancements/organizations`` proposal is implemented in the
    fulfillment service.
    """

    def __init__(self, config: OsacConfig, token: str) -> None:
        self._config = config
        self._base = config.fulfillment_url
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self._verify = config.verify_ssl

    def get_capabilities(self) -> dict[str, Any]:
        """GET ``/api/fulfillment/v1/capabilities`` (no auth required)."""
        status, resp = _request(
            f"{self._base}/api/fulfillment/v1/capabilities",
            verify_ssl=self._verify,
        )
        if status != 200:
            raise RuntimeError(f"Capabilities request failed (HTTP {status}): {resp}")
        return resp if isinstance(resp, dict) else {"raw": resp}

    def _api_request(
        self,
        path: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        headers_override: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any] | str]:
        """Issue an authenticated request to the fulfillment API."""
        hdrs = headers_override if headers_override else self._headers
        return _request(
            f"{self._base}{path}",
            method=method,
            data=data,
            headers=hdrs,
            verify_ssl=self._verify,
        )

    def list_virtual_networks(self, token: str | None = None) -> tuple[int, Any]:
        """List virtual networks. Returns ``(status, body)``."""
        hdrs = dict(self._headers)
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        return self._api_request("/api/fulfillment/v1/virtual_networks", headers_override=hdrs)

    def list_compute_instances(self, token: str | None = None) -> tuple[int, Any]:
        """List compute instances. Returns ``(status, body)``."""
        hdrs = dict(self._headers)
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        return self._api_request("/api/fulfillment/v1/compute_instances", headers_override=hdrs)

    def list_network_classes(self, token: str | None = None) -> tuple[int, Any]:
        """List network classes. Returns ``(status, body)``."""
        hdrs = dict(self._headers)
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        return self._api_request("/api/fulfillment/v1/network_classes", headers_override=hdrs)

    def create_virtual_network(
        self, name: str, token: str | None = None, network_class: str = ""
    ) -> tuple[int, Any]:
        """Attempt to create a virtual network. Returns ``(status, body)``.

        The REST gateway maps ``body: "object"`` so the HTTP body IS the
        VirtualNetwork message directly (metadata + spec), not wrapped in
        an ``object`` key.
        """
        hdrs = dict(self._headers)
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        spec: dict[str, Any] = {"ipv4_cidr": "10.200.0.0/16"}
        if network_class:
            spec["network_class"] = network_class
        payload = json.dumps({"metadata": {"name": name}, "spec": spec}).encode()
        return self._api_request(
            "/api/fulfillment/v1/virtual_networks",
            method="POST",
            data=payload,
            headers_override=hdrs,
        )

    def create_compute_instance(self, name: str, token: str | None = None) -> tuple[int, Any]:
        """Attempt to create a compute instance. Returns ``(status, body)``."""
        hdrs = dict(self._headers)
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        payload = json.dumps({"name": name}).encode()
        return self._api_request(
            "/api/fulfillment/v1/compute_instances",
            method="POST",
            data=payload,
            headers_override=hdrs,
        )

    def get_console_access(self, instance_id: str, token: str | None = None) -> tuple[int, Any]:
        """Probe console access for an instance. Returns ``(status, body)``."""
        hdrs = dict(self._headers)
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        encoded = urllib.parse.quote(instance_id, safe="")
        return self._api_request(
            f"/api/fulfillment/v1/compute_instances/{encoded}/console/access",
            headers_override=hdrs,
        )


# ---------------------------------------------------------------------------
# Tenant CRD (kubectl)
# ---------------------------------------------------------------------------


def _kubectl() -> str:
    """Return the kubectl binary path."""
    path = shutil.which("kubectl") or shutil.which("oc")
    if not path:
        raise RuntimeError("Neither kubectl nor oc found on PATH")
    return path


def _run_kubectl(args: list[str], config: OsacConfig) -> str:
    """Run a kubectl command and return its stdout.

    Raises ``RuntimeError`` on non-zero exit.
    """
    cmd = [_kubectl()] + args + ["-n", config.tenant_namespace]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(
            f"kubectl failed (rc={result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


class TenantClient:
    """Manage ``osac.openshift.io/v1alpha1`` Tenant CRDs via kubectl."""

    def __init__(self, config: OsacConfig) -> None:
        self._config = config

    def create(self, name: str) -> dict[str, Any]:
        """Create a Tenant CRD and return its metadata."""
        manifest = json.dumps(
            {
                "apiVersion": "osac.openshift.io/v1alpha1",
                "kind": "Tenant",
                "metadata": {
                    "name": name,
                    "namespace": self._config.tenant_namespace,
                    "labels": {"created-by": "isvtest"},
                },
                "spec": {},
            }
        )
        cmd = [
            _kubectl(),
            "apply",
            "-f",
            "-",
            "-n",
            self._config.tenant_namespace,
            "-o",
            "json",
        ]
        result = subprocess.run(
            cmd,
            input=manifest,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to create tenant '{name}': {result.stderr.strip()}"
            )
        return json.loads(result.stdout)

    def list(self) -> list[dict[str, Any]]:
        """List Tenant CRDs in the configured namespace."""
        out = _run_kubectl(
            ["get", "tenants.osac.openshift.io", "-o", "json"],
            self._config,
        )
        data = json.loads(out)
        return data.get("items", [])

    def get(self, name: str) -> dict[str, Any]:
        """Get a single Tenant CRD by name."""
        out = _run_kubectl(
            ["get", "tenants.osac.openshift.io", name, "-o", "json"],
            self._config,
        )
        return json.loads(out)

    def delete(self, name: str) -> None:
        """Delete a Tenant CRD by name."""
        try:
            _run_kubectl(
                ["delete", "tenants.osac.openshift.io", name, "--ignore-not-found"],
                self._config,
            )
        except RuntimeError:
            pass  # best-effort teardown


# ---------------------------------------------------------------------------
# Admin client bootstrap / cleanup
# ---------------------------------------------------------------------------


def _master_token(keycloak_url: str, verify_ssl: bool) -> str:
    """Get a master-realm admin token using resource-owner password grant.

    Reads ``OSAC_KEYCLOAK_ADMIN_USER`` (default ``admin``) and
    ``OSAC_KEYCLOAK_ADMIN_PASSWORD`` from the environment.
    """
    user = os.environ.get("OSAC_KEYCLOAK_ADMIN_USER", "admin")
    password = os.environ.get("OSAC_KEYCLOAK_ADMIN_PASSWORD", "")
    if not password:
        raise RuntimeError("OSAC_KEYCLOAK_ADMIN_PASSWORD is required for bootstrap")

    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": user,
            "password": password,
        }
    ).encode()

    status, resp = _request(
        f"{keycloak_url}/realms/master/protocol/openid-connect/token",
        method="POST",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        verify_ssl=verify_ssl,
    )
    if status != 200 or not isinstance(resp, dict) or "access_token" not in resp:
        raise RuntimeError(f"Master-realm login failed (HTTP {status}): {resp}")
    return resp["access_token"]


def bootstrap_admin_client(
    keycloak_url: str,
    realm: str,
    client_id: str,
    verify_ssl: bool,
) -> dict[str, str]:
    """Create an ephemeral admin client with ``manage-clients`` and ``view-realm`` roles.

    Uses master-realm credentials to:
      1. Create a service-account client in *realm*
      2. Assign ``manage-clients`` and ``view-realm`` from ``realm-management``
      3. Return ``{"client_id": ..., "client_secret": ..., "client_uuid": ...}``
    """
    token = _master_token(keycloak_url, verify_ssl)
    base = f"{keycloak_url}/admin/realms/{realm}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # 1. Create client
    payload = json.dumps(
        {
            "clientId": client_id,
            "enabled": True,
            "serviceAccountsEnabled": True,
            "clientAuthenticatorType": "client-secret",
            "protocol": "openid-connect",
            "publicClient": False,
            "standardFlowEnabled": False,
        }
    ).encode()
    status, _ = _request(
        f"{base}/clients",
        method="POST",
        data=payload,
        headers=headers,
        verify_ssl=verify_ssl,
    )
    if status not in (200, 201):
        raise RuntimeError(f"Failed to create admin client (HTTP {status})")

    # 2. Look up UUID
    encoded = urllib.parse.quote(client_id, safe="")
    status, clients = _request(
        f"{base}/clients?clientId={encoded}",
        headers=headers,
        verify_ssl=verify_ssl,
    )
    if not isinstance(clients, list) or len(clients) == 0:
        raise RuntimeError("Admin client not found after creation")
    client_uuid = clients[0]["id"]

    # 3. Get secret
    status, secret_resp = _request(
        f"{base}/clients/{client_uuid}/client-secret",
        headers=headers,
        verify_ssl=verify_ssl,
    )
    client_secret = secret_resp["value"] if isinstance(secret_resp, dict) else ""

    # 4. Get service-account user
    status, sa_user = _request(
        f"{base}/clients/{client_uuid}/service-account-user",
        headers=headers,
        verify_ssl=verify_ssl,
    )
    if not isinstance(sa_user, dict):
        raise RuntimeError("Could not find service-account user")
    sa_user_id = sa_user["id"]

    # 5. Find realm-management client UUID
    status, rm_clients = _request(
        f"{base}/clients?clientId=realm-management",
        headers=headers,
        verify_ssl=verify_ssl,
    )
    if not isinstance(rm_clients, list) or len(rm_clients) == 0:
        raise RuntimeError("realm-management client not found")
    rm_uuid = rm_clients[0]["id"]

    # 6. Get manage-clients and view-realm roles
    roles_to_assign: list[dict[str, Any]] = []
    for role_name in ("manage-clients", "view-realm"):
        status, role = _request(
            f"{base}/clients/{rm_uuid}/roles/{role_name}",
            headers=headers,
            verify_ssl=verify_ssl,
        )
        if isinstance(role, dict):
            roles_to_assign.append(role)
        elif role_name == "manage-clients":
            raise RuntimeError("manage-clients role not found")

    # 7. Assign roles
    status, _ = _request(
        f"{base}/users/{sa_user_id}/role-mappings/clients/{rm_uuid}",
        method="POST",
        data=json.dumps(roles_to_assign).encode(),
        headers=headers,
        verify_ssl=verify_ssl,
    )
    if status not in (200, 204):
        raise RuntimeError(f"Failed to assign realm-management roles (HTTP {status})")

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_uuid": client_uuid,
    }


def cleanup_admin_client(
    keycloak_url: str,
    realm: str,
    client_uuid: str,
    verify_ssl: bool,
) -> None:
    """Delete the ephemeral admin client using master-realm credentials."""
    token = _master_token(keycloak_url, verify_ssl)
    base = f"{keycloak_url}/admin/realms/{realm}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    status, _ = _request(
        f"{base}/clients/{client_uuid}",
        method="DELETE",
        headers=headers,
        verify_ssl=verify_ssl,
    )
    # 204 = success, 404 = already gone — both are fine
    if status not in (200, 204, 404):
        raise RuntimeError(f"Failed to delete admin client (HTTP {status})")


# ---------------------------------------------------------------------------
# OIDC discovery helpers
# ---------------------------------------------------------------------------


def get_oidc_discovery(config: OsacConfig) -> dict[str, Any]:
    """Fetch the OpenID Connect discovery document for the realm."""
    url = f"{config.keycloak_url}/realms/{config.keycloak_realm}/.well-known/openid-configuration"
    status, resp = _request(url, verify_ssl=config.verify_ssl)
    if status != 200 or not isinstance(resp, dict):
        raise RuntimeError(f"OIDC discovery failed (HTTP {status}): {resp}")
    return resp


def get_jwks(jwks_uri: str, verify_ssl: bool = True) -> dict[str, Any]:
    """Fetch the JWKS from the given URI."""
    status, resp = _request(jwks_uri, verify_ssl=verify_ssl)
    if status != 200 or not isinstance(resp, dict):
        raise RuntimeError(f"JWKS fetch failed (HTTP {status}): {resp}")
    return resp


# ---------------------------------------------------------------------------
# JWT manipulation (stdlib-only, for crafting test tokens)
# ---------------------------------------------------------------------------


def _b64url_decode(s: str) -> bytes:
    """Base64url decode without padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode the payload of a JWT without verification."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")
    return json.loads(_b64url_decode(parts[1]))


def craft_jwt(token: str, payload_overrides: dict[str, Any] | None = None,
              remove_claims: list[str] | None = None,
              corrupt_signature: bool = False) -> str:
    """Re-encode a JWT with modified payload or corrupted signature.

    Used for negative OIDC testing. The resulting token will have an
    invalid signature (expected — we're testing rejection).
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    header = parts[0]
    payload = json.loads(_b64url_decode(parts[1]))
    signature = parts[2]

    if payload_overrides:
        payload.update(payload_overrides)
    for claim in (remove_claims or []):
        payload.pop(claim, None)

    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    if corrupt_signature:
        sig_bytes = _b64url_decode(signature)
        corrupted = bytes(b ^ 0xFF for b in sig_bytes[:8]) + sig_bytes[8:]
        signature = _b64url_encode(corrupted)

    return f"{header}.{new_payload}.{signature}"


# ---------------------------------------------------------------------------
# Kubernetes helpers
# ---------------------------------------------------------------------------


def create_sa_token(namespace: str, sa_name: str, duration: str = "3600s") -> tuple[str, int]:
    """Create a short-lived ServiceAccount token via ``kubectl create token``.

    Returns ``(token_string, ttl_seconds)``.
    """
    kctl = _kubectl()
    cmd = [kctl, "create", "token", sa_name, "-n", namespace,
           f"--duration={duration}", "--output=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl create token failed: {result.stderr.strip()}")

    token_str = result.stdout.strip()
    try:
        token_data = json.loads(token_str)
        token_str = token_data.get("status", {}).get("token", token_str)
    except json.JSONDecodeError:
        pass

    payload = decode_jwt_payload(token_str)
    exp = payload.get("exp", 0)
    iat = payload.get("iat", 0)
    ttl = exp - iat if exp and iat else int(duration.rstrip("s"))
    return token_str, ttl


def get_cert_manager_certificates() -> list[dict[str, Any]]:
    """List cert-manager Certificate resources across all namespaces."""
    kctl = _kubectl()
    cmd = [kctl, "get", "certificates.cert-manager.io", "-A", "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return []
    data = json.loads(result.stdout)
    return data.get("items", [])
