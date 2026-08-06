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

"""Tests for instance/VM validations."""

from __future__ import annotations

from typing import Any

import pytest

from isvtest.validations.instance import (
    SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED,
    InstanceListCheck,
    InstancePowerCycleCheck,
    InstanceRebootCheck,
    InstanceStartCheck,
    InstanceStateCheck,
    InstanceStopCheck,
    InstanceTagCheck,
    SerialConsoleRetentionCheck,
    StableIdentifierCheck,
    VmComponentKeyAccessCheck,
    VmLaunchedWithSpecifiedKeyCheck,
)


def _reboot_output(**overrides: Any) -> dict[str, Any]:
    """Build a minimal passing reboot step_output; overrides replace keys."""
    base: dict[str, Any] = {
        "instance_id": "i-abc123",
        "reboot_initiated": True,
        "state": "running",
        "ssh_ready": True,
        "uptime_seconds": 45.2,
        "reboot_confirmed": True,
    }
    base.update(overrides)
    return base


def _retention_output(**overrides: Any) -> dict[str, Any]:
    """Build a minimal passing serial-console retention step_output."""
    base: dict[str, Any] = {
        "instance_id": "bm-abc123",
        "console_log_queryable": True,
        "retention_days_required": SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED,
        "retention_days_configured": SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED,
        "oldest_queryable_log_age_days": SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED,
        "query_result_count": 1,
        "retention_evidence": "test-log-archive:bm-abc123",
    }
    base.update(overrides)
    return base


class TestInstanceRebootCheck:
    """Tests for InstanceRebootCheck - the check must require an affirmative
    ``reboot_confirmed: True`` rather than treating absence as success."""

    def test_passes_with_affirmative_confirmation(self) -> None:
        """Happy path: reboot_confirmed=True passes."""
        v = InstanceRebootCheck(config={"step_output": _reboot_output()})
        result = v.execute()
        assert result["passed"] is True

    def test_fails_when_reboot_confirmed_absent(self) -> None:
        """Absent key must FAIL (was silently passing)."""
        out = _reboot_output()
        del out["reboot_confirmed"]
        v = InstanceRebootCheck(config={"step_output": out})
        result = v.execute()
        assert result["passed"] is False
        assert "not affirmatively confirmed" in result["error"]

    def test_fails_when_reboot_confirmed_none(self) -> None:
        """Explicit None must FAIL - same semantic as absent."""
        v = InstanceRebootCheck(config={"step_output": _reboot_output(reboot_confirmed=None)})
        result = v.execute()
        assert result["passed"] is False
        assert "not affirmatively confirmed" in result["error"]

    def test_fails_when_reboot_confirmed_false(self) -> None:
        """Existing behavior preserved: explicit False still fails."""
        v = InstanceRebootCheck(config={"step_output": _reboot_output(reboot_confirmed=False)})
        result = v.execute()
        assert result["passed"] is False

    def test_fails_when_reboot_initiated_false(self) -> None:
        """Upstream failure mode: reboot API call never succeeded."""
        v = InstanceRebootCheck(config={"step_output": _reboot_output(reboot_initiated=False)})
        result = v.execute()
        assert result["passed"] is False
        assert "Reboot was not initiated" in result["error"]

    def test_fails_when_state_not_running(self) -> None:
        """Instance must be running after reboot."""
        v = InstanceRebootCheck(config={"step_output": _reboot_output(state="stopped")})
        result = v.execute()
        assert result["passed"] is False
        assert "not running" in result["error"]

    def test_fails_when_ssh_not_ready(self) -> None:
        """SSH connectivity must be restored post-reboot."""
        v = InstanceRebootCheck(config={"step_output": _reboot_output(ssh_ready=False)})
        result = v.execute()
        assert result["passed"] is False
        assert "SSH not ready" in result["error"]

    def test_fails_when_uptime_exceeds_max(self) -> None:
        """Uptime > max_uptime means the instance wasn't really rebooted."""
        v = InstanceRebootCheck(config={"step_output": _reboot_output(uptime_seconds=3600), "max_uptime": 600})
        result = v.execute()
        assert result["passed"] is False
        assert "reboot may not have occurred" in result["error"]


class TestInstanceSpecifiedKeyCheck:
    """Tests for VM launch-with-specified-key validation."""

    def test_passes_when_instance_key_matches_requested_key(self) -> None:
        """Provider output proves the launched instance uses the requested key."""
        v = VmLaunchedWithSpecifiedKeyCheck(
            config={
                "step_output": {
                    "instance_id": "i-abc123",
                    "requested_key_name": "isv-test-key",
                    "key_name": "isv-test-key",
                }
            }
        )

        result = v.execute()

        assert result["passed"] is True
        assert "isv-test-key" in result["output"]

    def test_passes_with_instance_key_name_alias(self) -> None:
        """Providers may emit instance_key_name when key_name is reserved elsewhere."""
        v = VmLaunchedWithSpecifiedKeyCheck(
            config={
                "step_output": {
                    "instance_id": "i-abc123",
                    "requested_key_name": "custom-key",
                    "instance_key_name": "custom-key",
                }
            }
        )

        result = v.execute()

        assert result["passed"] is True

    def test_fails_when_requested_key_is_missing(self) -> None:
        """The provider must state which key it requested."""
        v = VmLaunchedWithSpecifiedKeyCheck(
            config={
                "step_output": {
                    "instance_id": "i-abc123",
                    "key_name": "isv-test-key",
                }
            }
        )

        result = v.execute()

        assert result["passed"] is False
        assert "No 'requested_key_name'" in result["error"]

    def test_fails_when_actual_key_is_missing(self) -> None:
        """The provider must report the key observed on the launched instance."""
        v = VmLaunchedWithSpecifiedKeyCheck(
            config={
                "step_output": {
                    "instance_id": "i-abc123",
                    "requested_key_name": "isv-test-key",
                }
            }
        )

        result = v.execute()

        assert result["passed"] is False
        assert "No launched instance key name" in result["error"]

    def test_fails_when_actual_key_differs_from_requested_key(self) -> None:
        """A launched instance with the wrong key fails the validation."""
        v = VmLaunchedWithSpecifiedKeyCheck(
            config={
                "step_output": {
                    "instance_id": "i-abc123",
                    "requested_key_name": "isv-test-key",
                    "key_name": "other-key",
                }
            }
        )

        result = v.execute()

        assert result["passed"] is False
        assert "expected key 'isv-test-key', got 'other-key'" in result["error"]


class TestComponentKeyAccessCheck:
    """Tests for AUTH03-01 specified-key SOL / network-device access."""

    def _output(self, **overrides: Any) -> dict[str, Any]:
        """Build a minimal passing component_key_access step_output."""
        base: dict[str, Any] = {
            "success": True,
            "platform": "vm",
            "instance_id": "i-abc123",
            "key_name": "isv-test-key",
            "tests": {
                "sol_access": {"passed": True},
                "network_device_access": {"passed": True},
            },
        }
        base.update(overrides)
        return base

    def test_passes_with_sol_and_network_access(self) -> None:
        """Happy path: both required component probes pass."""
        result = VmComponentKeyAccessCheck(config={"step_output": self._output()}).execute()

        assert result["passed"] is True
        assert "isv-test-key" in result["output"]

    def test_passes_with_provider_hidden_network_devices(self) -> None:
        """Network-device access may be provider-hidden when not tenant-visible."""
        result = VmComponentKeyAccessCheck(
            config={
                "step_output": self._output(
                    tests={
                        "sol_access": {"passed": True},
                        "network_device_access": {
                            "passed": True,
                            "provider_hidden": True,
                            "message": "no tenant network-device SSH",
                        },
                    }
                )
            }
        ).execute()

        assert result["passed"] is True
        assert "provider_hidden=network_device_access" in result["output"]

    def test_fails_when_key_name_missing(self) -> None:
        """The provider must report which key was used."""
        out = self._output()
        del out["key_name"]

        result = VmComponentKeyAccessCheck(config={"step_output": out}).execute()

        assert result["passed"] is False
        assert "key_name" in result["error"]

    def test_fails_when_sol_access_fails(self) -> None:
        """SOL access failure fails AUTH03."""
        result = VmComponentKeyAccessCheck(
            config={
                "step_output": self._output(
                    tests={
                        "sol_access": {"passed": False, "error": "serial disabled"},
                        "network_device_access": {"passed": True},
                    }
                )
            }
        ).execute()

        assert result["passed"] is False
        assert "sol_access" in result["error"]

    def test_skips_when_step_marked_skipped(self) -> None:
        """Whole-step skip (e.g. serial console disabled) is a pytest skip."""
        with pytest.raises(pytest.skip.Exception, match="serial console"):
            VmComponentKeyAccessCheck(
                config={
                    "step_output": self._output(
                        skipped=True,
                        skip_reason="EC2 serial console access is disabled for this account or region",
                    )
                }
            ).execute()


class TestSerialConsoleRetentionCheck:
    """Tests for one-month serial console retention evidence validation."""

    def test_passes_with_complete_retention_evidence(self) -> None:
        """Happy path: queryable logs satisfy the required retention window."""
        v = SerialConsoleRetentionCheck(
            config={
                "step_output": _retention_output(),
                "retention_days_required": SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED,
            }
        )
        result = v.execute()
        assert result["passed"] is True
        assert "bm-abc123" in result["output"]
        assert f"configured={SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED}d" in result["output"]
        assert "test-log-archive:bm-abc123" in result["output"]

    def test_fails_when_instance_id_is_missing(self) -> None:
        """The provider output must identify the node being checked."""
        out = _retention_output()
        del out["instance_id"]
        v = SerialConsoleRetentionCheck(config={"step_output": out})
        result = v.execute()
        assert result["passed"] is False
        assert "No 'instance_id'" in result["error"]

    def test_fails_when_console_logs_are_not_queryable(self) -> None:
        """A provider must prove historical logs can be queried."""
        v = SerialConsoleRetentionCheck(config={"step_output": _retention_output(console_log_queryable=False)})
        result = v.execute()
        assert result["passed"] is False
        assert "not queryable" in result["error"]

    def test_fails_when_configured_retention_is_below_required(self) -> None:
        """Configured retention must meet the required minimum."""
        v = SerialConsoleRetentionCheck(
            config={
                "step_output": _retention_output(retention_days_configured=14),
                "retention_days_required": SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED,
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert f"below required {SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED}" in result["error"]

    def test_fails_when_oldest_queryable_age_is_below_required(self) -> None:
        """The returned evidence must cover the full retention window."""
        v = SerialConsoleRetentionCheck(
            config={
                "step_output": _retention_output(oldest_queryable_log_age_days=7),
                "retention_days_required": SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED,
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "Oldest queryable serial console log" in result["error"]
        assert f"below required {SERIAL_CONSOLE_RETENTION_DAYS_REQUIRED}" in result["error"]

    def test_fails_when_query_returns_no_records(self) -> None:
        """A configured retention policy alone is insufficient without query results."""
        v = SerialConsoleRetentionCheck(config={"step_output": _retention_output(query_result_count=0)})
        result = v.execute()
        assert result["passed"] is False
        assert "returned no records" in result["error"]

    def test_fails_when_retention_evidence_is_missing(self) -> None:
        """Passing retention fields still require an evidence source."""
        out = _retention_output()
        del out["retention_evidence"]
        v = SerialConsoleRetentionCheck(config={"step_output": out})
        result = v.execute()
        assert result["passed"] is False
        assert "No 'retention_evidence'" in result["error"]


# ---------------------------------------------------------------------------
# OSAC bare metal lifecycle tests
# ---------------------------------------------------------------------------


class TestInstanceStateCheck:
    """Tests for InstanceStateCheck (launch and describe state)."""

    def test_passes_when_state_matches_expected(self) -> None:
        """Instance in expected state passes."""
        v = InstanceStateCheck(
            config={
                "step_output": {"instance_id": "bmi-abc", "state": "running"},
                "expected_state": "running",
            }
        )
        result = v.execute()
        assert result["passed"] is True
        assert "running" in result["output"]

    def test_fails_when_instance_id_missing(self) -> None:
        """No instance_id in output fails immediately."""
        v = InstanceStateCheck(config={"step_output": {"state": "running"}})
        result = v.execute()
        assert result["passed"] is False
        assert "instance_id" in result["error"]

    def test_fails_when_state_missing(self) -> None:
        """No state field in output fails."""
        v = InstanceStateCheck(config={"step_output": {"instance_id": "bmi-abc"}})
        result = v.execute()
        assert result["passed"] is False
        assert "state" in result["error"].lower()

    def test_fails_when_state_wrong(self) -> None:
        """Wrong state fails with descriptive message."""
        v = InstanceStateCheck(
            config={
                "step_output": {"instance_id": "bmi-abc", "state": "stopped"},
                "expected_state": "running",
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "stopped" in result["error"]
        assert "running" in result["error"]

    def test_custom_expected_state(self) -> None:
        """Non-default expected_state=stopped passes when instance is stopped."""
        v = InstanceStateCheck(
            config={
                "step_output": {"instance_id": "bmi-abc", "state": "stopped"},
                "expected_state": "stopped",
            }
        )
        result = v.execute()
        assert result["passed"] is True


class TestInstanceListCheck:
    """Tests for InstanceListCheck (list_instances step)."""

    def _passing_output(self, target: str = "bmi-001") -> dict[str, Any]:
        return {
            "instances": [
                {"instance_id": target, "state": "running", "vpc_id": "sub-abc"},
            ],
            "count": 1,
            "found_target": True,
            "target_instance": target,
        }

    def test_passes_with_valid_list_and_target_found(self) -> None:
        v = InstanceListCheck(config={"step_output": self._passing_output()})
        result = v.execute()
        assert result["passed"] is True
        assert "bmi-001" in result["output"]

    def test_fails_when_instances_key_missing(self) -> None:
        v = InstanceListCheck(config={"step_output": {}})
        result = v.execute()
        assert result["passed"] is False
        assert "instances" in result["error"]

    def test_fails_when_list_is_empty(self) -> None:
        v = InstanceListCheck(
            config={
                "step_output": {
                    "instances": [],
                    "count": 0,
                    "found_target": False,
                    "target_instance": "bmi-001",
                }
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "1 instance" in result["error"]

    def test_fails_when_target_not_found(self) -> None:
        out = self._passing_output()
        out["found_target"] = False
        v = InstanceListCheck(config={"step_output": out})
        result = v.execute()
        assert result["passed"] is False
        assert "bmi-001" in result["error"]

    def test_fails_when_instance_missing_required_field(self) -> None:
        """An instance entry without vpc_id fails the field check."""
        v = InstanceListCheck(
            config={
                "step_output": {
                    "instances": [{"instance_id": "bmi-001", "state": "running"}],
                    "count": 1,
                    "found_target": True,
                    "target_instance": "bmi-001",
                }
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "vpc_id" in result["error"]


class TestInstanceTagCheck:
    """Tests for InstanceTagCheck (verify_tags step)."""

    def test_passes_with_required_tags_present(self) -> None:
        v = InstanceTagCheck(
            config={
                "step_output": {
                    "instance_id": "bmi-001",
                    "tags": {"Name": "osac-bm-validation", "CreatedBy": "isv-validation"},
                    "tag_count": 2,
                },
                "required_keys": ["Name", "CreatedBy"],
            }
        )
        result = v.execute()
        assert result["passed"] is True
        assert "2 tag" in result["output"]

    def test_fails_when_tags_key_missing(self) -> None:
        v = InstanceTagCheck(config={"step_output": {"instance_id": "bmi-001"}, "required_keys": []})
        result = v.execute()
        assert result["passed"] is False
        assert "tags" in result["error"].lower()

    def test_fails_when_tags_empty(self) -> None:
        v = InstanceTagCheck(
            config={
                "step_output": {"instance_id": "bmi-001", "tags": {}, "tag_count": 0},
                "required_keys": [],
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "no tags" in result["error"].lower()

    def test_fails_when_required_key_missing(self) -> None:
        v = InstanceTagCheck(
            config={
                "step_output": {
                    "instance_id": "bmi-001",
                    "tags": {"Name": "test"},
                    "tag_count": 1,
                },
                "required_keys": ["Name", "CreatedBy"],
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "CreatedBy" in result["error"]

    def test_fails_when_instance_id_missing(self) -> None:
        v = InstanceTagCheck(config={"step_output": {}})
        result = v.execute()
        assert result["passed"] is False
        assert "instance_id" in result["error"]


class TestInstanceStopCheck:
    """Tests for InstanceStopCheck (stop_instance step)."""

    def test_passes_when_stopped(self) -> None:
        v = InstanceStopCheck(
            config={
                "step_output": {
                    "instance_id": "bmi-001",
                    "stop_initiated": True,
                    "state": "stopped",
                }
            }
        )
        result = v.execute()
        assert result["passed"] is True
        assert "stopped" in result["output"]

    def test_fails_when_instance_id_missing(self) -> None:
        v = InstanceStopCheck(config={"step_output": {"stop_initiated": True, "state": "stopped"}})
        result = v.execute()
        assert result["passed"] is False
        assert "instance_id" in result["error"]

    def test_fails_when_stop_not_initiated(self) -> None:
        v = InstanceStopCheck(
            config={
                "step_output": {
                    "instance_id": "bmi-001",
                    "stop_initiated": False,
                    "state": "stopped",
                }
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "not initiated" in result["error"].lower()

    def test_fails_when_state_not_stopped(self) -> None:
        v = InstanceStopCheck(
            config={
                "step_output": {
                    "instance_id": "bmi-001",
                    "stop_initiated": True,
                    "state": "running",
                }
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "running" in result["error"]


class TestInstanceStartCheck:
    """Tests for InstanceStartCheck (start_instance step)."""

    def _passing_output(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "instance_id": "bmi-001",
            "start_initiated": True,
            "state": "running",
            "ssh_ready": True,
        }
        base.update(overrides)
        return base

    def test_passes_when_running_and_ssh_ready(self) -> None:
        v = InstanceStartCheck(config={"step_output": self._passing_output()})
        result = v.execute()
        assert result["passed"] is True

    def test_fails_when_instance_id_missing(self) -> None:
        v = InstanceStartCheck(config={"step_output": {"start_initiated": True, "state": "running", "ssh_ready": True}})
        result = v.execute()
        assert result["passed"] is False
        assert "instance_id" in result["error"]

    def test_fails_when_start_not_initiated(self) -> None:
        v = InstanceStartCheck(config={"step_output": self._passing_output(start_initiated=False)})
        result = v.execute()
        assert result["passed"] is False
        assert "not initiated" in result["error"].lower()

    def test_fails_when_state_not_running(self) -> None:
        v = InstanceStartCheck(config={"step_output": self._passing_output(state="stopped")})
        result = v.execute()
        assert result["passed"] is False
        assert "stopped" in result["error"]

    def test_fails_when_ssh_not_ready(self) -> None:
        v = InstanceStartCheck(config={"step_output": self._passing_output(ssh_ready=False)})
        result = v.execute()
        assert result["passed"] is False
        assert "SSH not ready" in result["error"]


class TestInstancePowerCycleCheck:
    """Tests for InstancePowerCycleCheck (power_cycle_instance step)."""

    def _passing_output(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "instance_id": "bmi-001",
            "power_cycle_initiated": True,
            "power_was_off": True,
            "state": "running",
            "ssh_ready": True,
            "recovery_seconds": 180,
        }
        base.update(overrides)
        return base

    def test_passes_with_all_fields(self) -> None:
        v = InstancePowerCycleCheck(config={"step_output": self._passing_output()})
        result = v.execute()
        assert result["passed"] is True
        assert "power-cycle" in result["output"]

    def test_fails_when_instance_id_missing(self) -> None:
        out = self._passing_output()
        del out["instance_id"]
        v = InstancePowerCycleCheck(config={"step_output": out})
        result = v.execute()
        assert result["passed"] is False
        assert "instance_id" in result["error"]

    def test_fails_when_power_cycle_not_initiated(self) -> None:
        v = InstancePowerCycleCheck(config={"step_output": self._passing_output(power_cycle_initiated=False)})
        result = v.execute()
        assert result["passed"] is False
        assert "not initiated" in result["error"].lower()

    def test_fails_when_power_was_not_off(self) -> None:
        v = InstancePowerCycleCheck(config={"step_output": self._passing_output(power_was_off=False)})
        result = v.execute()
        assert result["passed"] is False
        assert "powered-off" in result["error"]

    def test_fails_when_state_not_running(self) -> None:
        v = InstancePowerCycleCheck(config={"step_output": self._passing_output(state="stopped")})
        result = v.execute()
        assert result["passed"] is False
        assert "stopped" in result["error"]

    def test_fails_when_ssh_not_ready(self) -> None:
        v = InstancePowerCycleCheck(config={"step_output": self._passing_output(ssh_ready=False)})
        result = v.execute()
        assert result["passed"] is False
        assert "SSH not ready" in result["error"]

    def test_fails_when_recovery_too_long(self) -> None:
        v = InstancePowerCycleCheck(
            config={
                "step_output": self._passing_output(recovery_seconds=1000),
                "max_recovery_time": 900,
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "1000" in result["error"]


class TestStableIdentifierCheck:
    """Tests for StableIdentifierCheck (start_checks / reboot_checks)."""

    def test_passes_when_ids_match(self) -> None:
        v = StableIdentifierCheck(
            config={
                "step_output": {"instance_id": "bmi-001"},
                "reference_id": "bmi-001",
            }
        )
        result = v.execute()
        assert result["passed"] is True
        assert "stable" in result["output"].lower()

    def test_fails_when_instance_id_missing(self) -> None:
        v = StableIdentifierCheck(config={"step_output": {}, "reference_id": "bmi-001"})
        result = v.execute()
        assert result["passed"] is False
        assert "instance_id" in result["error"]

    def test_fails_when_no_reference_id(self) -> None:
        v = StableIdentifierCheck(config={"step_output": {"instance_id": "bmi-001"}, "reference_id": ""})
        result = v.execute()
        assert result["passed"] is False
        assert "reference_id" in result["error"]

    def test_fails_when_ids_differ(self) -> None:
        v = StableIdentifierCheck(
            config={
                "step_output": {"instance_id": "bmi-999"},
                "reference_id": "bmi-001",
            }
        )
        result = v.execute()
        assert result["passed"] is False
        assert "bmi-999" in result["error"]
        assert "bmi-001" in result["error"]
