from __future__ import annotations

import base64
import hashlib
import inspect
import json
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class _ProvisionerFacade:
    """Expose the migrated helpers through the legacy test call sites."""

    def __init__(self, *modules: types.ModuleType) -> None:
        self._modules = modules

    def __getattr__(self, name: str) -> object:
        for module in self._modules:
            if hasattr(module, name):
                return getattr(module, name)
        raise AttributeError(name)


def _load_module() -> _ProvisionerFacade:
    yaml_stub = types.ModuleType("yaml")
    yaml_stub.safe_load = lambda *_args, **_kwargs: {}
    yaml_stub.safe_dump = lambda *_args, **_kwargs: ""
    yaml_stub.YAMLError = ValueError
    sys.modules.setdefault("yaml", yaml_stub)

    from windows_provisioner import cli, openssh, remote

    return _ProvisionerFacade(remote, openssh, cli)


mavi = _load_module()


def _clean_audit() -> dict[str, object]:
    return {
        "QueryErrors": [],
        "CertificateChecks": {
            "WinRmRootThumbprintProvided": True,
            "WinRmRootIdentityProvided": True,
            "WinRmLeafIdentityProvided": True,
            "BootstrapRootThumbprintProvided": True,
        },
        "WinRM": {
            "Exists": True,
            "Status": "Stopped",
            "Start": 4,
            "MaviListenerCount": 0,
            "ForeignListenerCount": 0,
            "FirewallRuleCount": 0,
            "PolicyValueCount": 0,
        },
        "OpenSSH": {
            "Exists": True,
            "Status": "Stopped",
            "Start": 4,
            "FirewallRuleCount": 0,
            "MaviKeyCount": 0,
            "MaviConfigBackupCount": 0,
        },
        "Certificates": {
            "WinRmRootPresent": False,
            "BootstrapRootPresent": False,
            "CurrentLeafPresent": False,
            "ManagedLeafCount": 0,
        },
    }


class CertificateAndMarkerTests(unittest.TestCase):
    def test_der_thumbprint_uses_windows_sha1_form(self) -> None:
        der = b"\x30\x03\x02\x01\x01"
        self.assertEqual(
            mavi._certificate_thumbprint_from_der(der),
            hashlib.sha1(der).hexdigest().upper(),
        )

    def test_https_marker_persists_leaf_lifetime_and_prune_count(self) -> None:
        payload = {
            "Thumbprint": "A" * 40,
            "RootThumbprint": "B" * 40,
            "CertificateSha256": "c" * 64,
            "NotAfterUtc": "2030-01-01T00:00:00+00:00",
            "RootNotAfterUtc": "2035-01-01T00:00:00+00:00",
            "PrunedServerCertificates": 3,
            "Fqdn": "pc01.example.test",
            "Port": 5986,
            "KerberosOnly": True,
            "Http5985Blocked": True,
        }
        marker = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        result = mavi._extract_winrm_https_install_result(f"Mavi_WINRM_HTTPS_B64={marker}")
        self.assertEqual(result["thumbprint"], "A" * 40)
        self.assertEqual(result["pruned_server_certificates"], 3)
        self.assertEqual(result["certificate_not_after"], "2030-01-01T00:00:00Z")

    def test_result_markers_must_be_unique(self) -> None:
        marker = base64.b64encode(
            json.dumps({"result": "expected"}).encode("utf-8")
        ).decode("ascii")
        output = f"Mavi_TEST_B64={marker}\nMavi_TEST_B64={marker}"

        with self.assertRaisesRegex(RuntimeError, "nicht eindeutig"):
            mavi._extract_json_marker(output, "Mavi_TEST_B64=")

    def test_bootstrap_probe_marker_binds_current_and_historical_roots(self) -> None:
        payload = {
            "CurrentRootThumbprint": "B" * 40,
            "PresentRootThumbprints": ["B" * 40, "C" * 40],
        }
        marker = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        result = mavi._extract_bootstrap_ca_probe_result(
            f"Mavi_BOOTSTRAP_CA_B64={marker}"
        )
        self.assertEqual(result["current_root_thumbprint"], "B" * 40)
        self.assertEqual(
            result["present_root_thumbprints"],
            ["B" * 40, "C" * 40],
        )

        payload["PresentRootThumbprints"] = ["C" * 40]
        invalid_marker = base64.b64encode(
            json.dumps(payload).encode("utf-8")
        ).decode("ascii")
        with self.assertRaisesRegex(RuntimeError, "aktuelle CA nicht"):
            mavi._extract_bootstrap_ca_probe_result(
                f"Mavi_BOOTSTRAP_CA_B64={invalid_marker}"
            )
        legacy_result = mavi._extract_bootstrap_ca_probe_result(
            f"Mavi_BOOTSTRAP_CA_B64={invalid_marker}",
            require_current_root=False,
        )
        self.assertEqual(legacy_result["present_root_thumbprints"], ["C" * 40])

        payload["PresentRootThumbprints"] = []
        empty_marker = base64.b64encode(
            json.dumps(payload).encode("utf-8")
        ).decode("ascii")
        with self.assertRaisesRegex(RuntimeError, "keine der exakt bekannten CAs"):
            mavi._extract_bootstrap_ca_probe_result(
                f"Mavi_BOOTSTRAP_CA_B64={empty_marker}",
                require_current_root=False,
            )

    def test_reset_marker_requires_the_new_exact_listener_result(self) -> None:
        payload = {
            "RemovedListeners": 1,
            "RemovedCertificates": 2,
            "RemovedFirewallRules": 3,
            "RemovedOpenSshFirewallRules": 1,
            "RemovedOpenSshKeys": 1,
            "RemovedOpenSshConfigBackups": 1,
            "RemovedBootstrapCertificates": 1,
            "BootstrapScopeVerified": True,
            "OpenSshDisableScheduled": True,
            "OpenSshStartupDisabled": True,
            "OpenSshStoppedVerified": True,
            "OpenSshState": "Stopped",
            "OpenSshStartMode": "Disabled",
            "WinRMState": "Stopped",
            "WinRMStartMode": "Disabled",
            "WinRmScopeVerified": True,
            "WinRmListenersCleared": True,
            "PreservedForeignWinRmListeners": 0,
            "WinRmRootThumbprint": "A" * 40,
            "BootstrapRootThumbprint": "B" * 40,
            "BootstrapRootThumbprints": ["B" * 40, "C" * 40],
        }
        marker = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        result = mavi._extract_winrm_reset_result(f"Mavi_REMOTE_RESET_B64={marker}")
        self.assertEqual(result["preserved_foreign_winrm_listeners"], 0)
        self.assertEqual(result["bootstrap_root_thumbprint"], "B" * 40)
        self.assertEqual(
            result["bootstrap_root_thumbprints"],
            ["B" * 40, "C" * 40],
        )
        self.assertEqual(result["removed_openssh_config_backups"], 1)
        self.assertTrue(result["winrm_scope_verified"])
        self.assertTrue(result["winrm_listeners_cleared"])
        self.assertTrue(result["bootstrap_scope_verified"])
        self.assertTrue(result["openssh_stopped_verified"])
        self.assertEqual(result["openssh_state"], "Stopped")
        self.assertEqual(result["openssh_start_mode"], "Disabled")

        payload["PreservedForeignWinRmListeners"] = 1
        contradictory_marker = base64.b64encode(
            json.dumps(payload).encode("utf-8")
        ).decode("ascii")
        with self.assertRaisesRegex(RuntimeError, "widerspricht sich"):
            mavi._extract_winrm_reset_result(
                f"Mavi_REMOTE_RESET_B64={contradictory_marker}"
            )


class StatusClassificationTests(unittest.TestCase):
    def test_live_clean_is_confirmed_when_a_versioned_proof_exists(self) -> None:
        result = mavi._classify_remote_management_audit(_clean_audit(), {"verified": True})
        self.assertEqual(result["code"], "confirmed_disabled")

    def test_clean_audit_keeps_observed_generic_winrm_policy_detail(self) -> None:
        audit = _clean_audit()
        audit["WinRM"] = dict(audit["WinRM"], PolicyValueCount=5)

        result = mavi._classify_remote_management_audit(audit, {"verified": True})

        self.assertEqual(result["code"], "confirmed_disabled")
        self.assertIn(
            "generische WinRM-Richtlinienwerte beobachtet (nicht angefasst)",
            result["details"],
        )

    def test_disabled_listener_provider_skip_requires_versioned_proof(self) -> None:
        audit = _clean_audit()
        audit["WinRM"] = dict(
            audit["WinRM"],
            ListenerCheckSkippedDisabled=True,
        )
        self.assertEqual(
            mavi._classify_remote_management_audit(audit, {"verified": True})["code"],
            "confirmed_disabled",
        )
        self.assertEqual(
            mavi._classify_remote_management_audit(audit, None)["code"],
            "unknown",
        )

    def test_unreachable_verified_host_stays_explicitly_recorded(self) -> None:
        result = mavi._classify_remote_management_audit(None, {"verified": True})
        self.assertEqual(result["code"], "disabled_unreachable")
        self.assertIn("Rückbau-Nachweis", result["label"])

    def test_legacy_inventory_record_is_never_clean_confirmed(self) -> None:
        result = mavi._classify_remote_management_audit(_clean_audit(), {"verified": False})
        self.assertEqual(result["code"], "legacy_not_confirmable")

    def test_active_and_partial_are_distinguished(self) -> None:
        active = _clean_audit()
        active["WinRM"] = dict(active["WinRM"], Status="Running", Start=2)
        self.assertEqual(
            mavi._classify_remote_management_audit(active, None)["code"],
            "active",
        )

        partial = _clean_audit()
        partial["OpenSSH"] = dict(partial["OpenSSH"], MaviKeyCount=1)
        self.assertEqual(
            mavi._classify_remote_management_audit(partial, None)["code"],
            "partial",
        )

        config_backup = _clean_audit()
        config_backup["OpenSSH"] = dict(
            config_backup["OpenSSH"], MaviConfigBackupCount=1
        )
        self.assertEqual(
            mavi._classify_remote_management_audit(config_backup, None)["code"],
            "partial",
        )

        unknown_listener = _clean_audit()
        unknown_listener["WinRM"] = dict(
            unknown_listener["WinRM"], ForeignListenerCount=1
        )
        listener_result = mavi._classify_remote_management_audit(
            unknown_listener,
            {"verified": True},
        )
        self.assertEqual(listener_result["code"], "partial")
        self.assertTrue(
            any(
                "nicht zuordenbare WinRM-Listener" in detail
                for detail in listener_result["details"]
            )
        )

    def test_inventory_migration_keeps_old_record_unknown(self) -> None:
        windows = {"vars": {"ansible_connection": "ssh"}}
        legacy = {
            "mavi_remote_management_disabled": {
                "version": 1,
                "winrm": True,
                "openssh": True,
            }
        }
        version_two = {
            "mavi_remote_management_disabled": {
                "version": 2,
                "winrm": True,
                "openssh": True,
                "remote_cleanup_verified": True,
                "winrm_scope_verified": True,
                "controller_cleanup_complete": True,
            }
        }
        current = {
            "mavi_remote_management_disabled": {
                "version": 3,
                "winrm": True,
                "openssh": True,
                "remote_cleanup_verified": True,
                "winrm_scope_verified": True,
                "winrm_listeners_cleared": True,
                "bootstrap_scope_verified": True,
                "openssh_stopped_verified": True,
                "controller_cleanup_complete": True,
            }
        }
        self.assertEqual(
            mavi._inventory_remote_management_status(windows, legacy)["code"],
            "legacy_disabled",
        )
        self.assertEqual(
            mavi._inventory_remote_management_status(windows, version_two)["code"],
            "legacy_disabled",
        )
        self.assertEqual(
            mavi._inventory_remote_management_status(windows, current)["code"],
            "disabled_recorded",
        )

        current["mavi_remote_management_disabled"]["winrm_scope_verified"] = False
        self.assertEqual(
            mavi._inventory_remote_management_status(windows, current)["code"],
            "legacy_disabled",
        )


class GeneratedPlayAndCliTests(unittest.TestCase):
    def test_verified_bootstrap_instance_scopes_openssh_artifacts(self) -> None:
        project = Path("project")
        instance_id = "test-instance-a1b2c3"
        host_data = {
            "mavi_bootstrap": {
                "version": 2,
                "remote_verified": True,
                "instance_id": instance_id,
            }
        }

        self.assertEqual(
            mavi._openssh_artifact_instance_id(project, host_data),
            instance_id,
        )
        self.assertEqual(
            mavi._openssh_firewall_rule_name(
                project,
                instance_id=instance_id,
            ),
            "Mavi-OpenSSH-test-instance-a1b2c3-Ansible-In-TCP",
        )
        self.assertEqual(
            mavi._openssh_config_backup_relative_path(
                project,
                instance_id=instance_id,
            ),
            (
                r"MaviProvisioner\bootstrap\test-instance-a1b2c3"
                r"\sshd_config.pre-mavi.bak"
            ),
        )

        invalid_states = (
            {"version": 1, "remote_verified": True, "instance_id": instance_id},
            {"version": 2, "remote_verified": False, "instance_id": instance_id},
            {"version": 2, "remote_verified": True, "instance_id": "../foreign"},
            {"version": 2, "remote_verified": True},
            {"version": 2, "remote_verified": False, "instance_id": ""},
        )
        for state in invalid_states:
            with self.subTest(state=state):
                with self.assertRaises(ValueError):
                    mavi._openssh_artifact_instance_id(
                        project,
                        {"mavi_bootstrap": state},
                    )

    def test_status_all_and_live_arguments_and_legacy_host_are_compatible(self) -> None:
        parser = mavi.build_parser()
        all_live = parser.parse_args(["ssh", "status", "--all", "--live"])
        self.assertTrue(all_live.all_hosts)
        self.assertTrue(all_live.live)
        old_form = parser.parse_args(["ssh", "status", "PC-01"])
        self.assertEqual(old_form.host, "PC-01")
        self.assertFalse(old_form.all_hosts)
        self.assertFalse(old_form.live)

    def test_full_reset_uses_controller_der_and_never_infers_certificate_scope(self) -> None:
        self.assertEqual(
            mavi._bootstrap_state_thumbprints(
                {"version": 1, "root_thumbprint": "b" * 40}
            ),
            ("B" * 40,),
        )

        source = inspect.getsource(mavi.cmd_ssh_winrm_reset)
        ssh_selection = source.index("cmd_ssh_use(")
        live_probe = source.index("play=_bootstrap_ca_probe_play")
        reset_play = source.index("play=_winrm_reset_play")
        self.assertLess(ssh_selection, live_probe)
        self.assertLess(live_probe, reset_play)
        self.assertIn("require_current_root=False", source)
        self.assertIn("_controller_bound_bootstrap_root_certificates", source)
        self.assertIn("_verified_bootstrap_root_thumbprints", source)
        self.assertIn("unbound_bootstrap_thumbprints", source)

        audit_source = inspect.getsource(mavi._host_known_ca_thumbprints)
        self.assertNotIn("_bootstrap_root_ca_thumbprint", audit_source)

        reset_script = mavi._winrm_reset_play(
            root_thumbprint="",
            bootstrap_root_certificates_der_base64=[
                base64.b64encode(b"controller-root").decode("ascii")
            ],
            disable_openssh=True,
        )[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]
        self.assertEqual(reset_script.count("$winRmScopeVerified = $true"), 1)
        self.assertIn("ein leerer Listener-Bestand reicht nicht aus", reset_script)
        self.assertNotIn(
            "Ein live nachgewiesener leerer Listener-Bestand",
            reset_script,
        )
        self.assertIn(
            "if ($disableOpenSsh -and (-not $winRmScopeVerified",
            reset_script,
        )

    def test_full_reset_without_exact_winrm_root_never_starts_remote_cleanup(self) -> None:
        args = types.SimpleNamespace(
            project=Path("project"),
            host="PC-01",
            key=None,
            port=None,
            disable_openssh=True,
            yes=True,
        )
        inventory = {"all": {}}
        windows = {"vars": {"ansible_connection": "ssh", "ansible_port": 22}}
        host_data = {
            "ansible_connection": "ssh",
            "ansible_port": 22,
            "ansible_ssh_private_key_file": "controller-key",
        }
        current_der = base64.b64encode(b"controller-root").decode("ascii")
        current_thumbprint = mavi._certificate_thumbprint_from_der(b"controller-root")

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.remote._host_inventory_entry",
                return_value=(inventory, windows, host_data),
            ),
            mock.patch(
                "windows_provisioner.openssh._controller_bound_bootstrap_root_certificates",
                return_value=(current_thumbprint, {current_thumbprint: current_der}),
            ),
            mock.patch(
                "windows_provisioner.openssh._public_key_prefix_for_private_key",
                return_value="ssh-ed25519 AAAATEST",
            ),
            mock.patch(
                "windows_provisioner.remote._winrm_pki_paths",
                return_value={"ca_cert": Path("ca.pem"), "ca_der": Path("ca.cer")},
            ),
            mock.patch(
                "windows_provisioner.openssh._winrm_reset_root_identity",
                return_value=("", ""),
            ),
            mock.patch("windows_provisioner.environment.eprint") as error_mock,
            mock.patch("windows_provisioner.remote._run_winrm_temporary_play") as run_mock,
        ):
            with self.assertRaises(SystemExit):
                mavi.cmd_ssh_winrm_reset(args)

        run_mock.assert_not_called()
        error_text = "\n".join(str(call.args[0]) for call in error_mock.call_args_list)
        self.assertIn("kein v3-Vollnachweis", error_text)

    def test_full_reset_without_exact_public_key_never_starts_remote_cleanup(self) -> None:
        args = types.SimpleNamespace(
            project=Path("project"),
            host="PC-01",
            key=None,
            port=None,
            disable_openssh=True,
            yes=True,
        )
        inventory = {"all": {}}
        windows = {"vars": {"ansible_connection": "ssh", "ansible_port": 22}}
        host_data = {
            "ansible_connection": "ssh",
            "ansible_port": 22,
            "ansible_ssh_private_key_file": "controller-key",
        }
        current_der = base64.b64encode(b"controller-root").decode("ascii")
        current_thumbprint = mavi._certificate_thumbprint_from_der(b"controller-root")

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.remote._host_inventory_entry",
                return_value=(inventory, windows, host_data),
            ),
            mock.patch(
                "windows_provisioner.openssh._controller_bound_bootstrap_root_certificates",
                return_value=(current_thumbprint, {current_thumbprint: current_der}),
            ),
            mock.patch(
                "windows_provisioner.openssh._public_key_prefix_for_private_key",
                return_value="",
            ),
            mock.patch("windows_provisioner.environment.eprint") as error_mock,
            mock.patch("windows_provisioner.remote._run_winrm_temporary_play") as run_mock,
        ):
            with self.assertRaises(SystemExit):
                mavi.cmd_ssh_winrm_reset(args)

        run_mock.assert_not_called()
        error_text = "\n".join(str(call.args[0]) for call in error_mock.call_args_list)
        self.assertIn("exakte Key-Identität", error_text)

    def test_existing_legacy_host_aliases_resolve_with_safe_artifact_tokens(self) -> None:
        for valid_host in ("PC", "PC-01", "PC_01", "PC.01", "WINDOWS"):
            with self.subTest(valid_host=valid_host):
                self.assertEqual(mavi._safe_host_token(valid_host), valid_host)

        legacy_hosts = ("PC-01_", "-PC01", "PC01.", ".PC", ".", "..", "---")
        legacy_tokens = {host: mavi._safe_host_token(host) for host in legacy_hosts}
        self.assertEqual(len(set(legacy_tokens.values())), len(legacy_hosts))
        for legacy_host, token in legacy_tokens.items():
            with self.subTest(legacy_host=legacy_host):
                self.assertTrue(token.startswith("@mavi-legacy-host-"))
                self.assertEqual(Path(token).name, token)
                self.assertNotIn(token, {".", ".."})
                with self.assertRaisesRegex(ValueError, "PC-Name"):
                    mavi._validate_new_host_alias(legacy_host)

                inventory = {
                    "all": {
                        "children": {
                            "windows": {
                                "vars": {"ansible_connection": "ssh"},
                                "hosts": {legacy_host: {"ansible_host": "192.0.2.10"}},
                            }
                        }
                    }
                }
                with mock.patch(
                    "windows_provisioner.execution.load_inventory",
                    return_value=inventory,
                ):
                    resolved_inventory, _windows, host_data = mavi._host_inventory_entry(
                        Path("project"), legacy_host
                    )
                self.assertIs(resolved_inventory, inventory)
                self.assertEqual(host_data["ansible_host"], "192.0.2.10")

        for invalid_host in ("PC/A", "PC?A", "PC:A", "PC A", "PÇ", ""):
            with self.subTest(invalid_host=invalid_host):
                with self.assertRaisesRegex(ValueError, "Inventory-Hostname"):
                    mavi._safe_host_token(invalid_host)

        self.assertEqual(
            mavi._host_artifact_tokens("-PC01", include_legacy=True),
            (mavi._safe_host_token("-PC01"), "PC01"),
        )
        self.assertEqual(
            mavi._host_artifact_tokens("PC01", include_legacy=True),
            ("PC01",),
        )

        entry_source = inspect.getsource(mavi._host_inventory_entry)
        self.assertLess(
            entry_source.index("_validate_inventory_host_alias(host)"),
            entry_source.index("load_inventory(project)"),
        )

        from windows_provisioner.execution import cmd_host_add

        add_source = inspect.getsource(cmd_host_add)
        self.assertIn("_validate_new_host_alias(name)", add_source)

        existing_inventory = {
            "all": {
                "children": {
                    "windows": {
                        "vars": {"ansible_connection": "ssh"},
                        "hosts": {"-PC01": {"ansible_host": "192.0.2.10"}},
                    }
                }
            }
        }
        add_args = types.SimpleNamespace(
            project=Path("project"),
            name="-PC01",
            ip="192.0.2.11",
            ansible_user=None,
            local_admin=None,
            connection="inherit",
            ssh_key=None,
            ssh_port=None,
        )
        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.environment.project_paths",
                return_value={"inventory": Path("inventory.yml")},
            ),
            mock.patch(
                "windows_provisioner.execution.load_inventory",
                return_value=existing_inventory,
            ),
            mock.patch("windows_provisioner.environment.atomic_write_yaml") as write_mock,
            mock.patch("builtins.print"),
        ):
            cmd_host_add(add_args)

        self.assertEqual(
            existing_inventory["all"]["children"]["windows"]["hosts"]["-PC01"][
                "ansible_host"
            ],
            "192.0.2.11",
        )
        write_mock.assert_called_once_with(Path("inventory.yml"), existing_inventory)

    def test_host_add_cannot_reactivate_a_fully_disabled_host(self) -> None:
        from windows_provisioner.execution import cmd_host_add

        host_data = {
            "ansible_host": "192.0.2.10",
            "ansible_connection": "mavi_disabled",
            "mavi_remote_management_disabled": {
                "version": 3,
                "openssh": True,
                "remote_cleanup_verified": True,
            },
        }
        inventory = {
            "all": {
                "children": {
                    "windows": {
                        "vars": {"ansible_connection": "ssh"},
                        "hosts": {"PC-01": host_data},
                    }
                }
            }
        }
        args = types.SimpleNamespace(
            project=Path("project"),
            name="PC-01",
            ip="192.0.2.99",
            ansible_user=None,
            local_admin=None,
            connection="ssh",
            ssh_key=None,
            ssh_port=None,
        )

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.environment.project_paths",
                return_value={"inventory": Path("inventory.yml")},
            ),
            mock.patch(
                "windows_provisioner.execution.load_inventory",
                return_value=inventory,
            ),
            mock.patch("windows_provisioner.environment.eprint"),
            mock.patch("windows_provisioner.environment.atomic_write_yaml") as write_mock,
            mock.patch("windows_provisioner.remote._apply_ssh_transport") as apply_mock,
        ):
            with self.assertRaises(SystemExit) as raised:
                cmd_host_add(args)

        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(host_data["ansible_host"], "192.0.2.10")
        self.assertEqual(host_data["ansible_connection"], "mavi_disabled")
        apply_mock.assert_not_called()
        write_mock.assert_not_called()

    def test_temporary_plays_prune_inventory_before_running_pattern_aliases(self) -> None:
        inventory = {
            "all": {
                "children": {
                    "windows": {
                        "vars": {"ansible_connection": "ssh"},
                        "hosts": {
                            "all": {"ansible_host": "192.0.2.10"},
                            "PC-02": {"ansible_host": "192.0.2.11"},
                        },
                    },
                    "linux": {"hosts": {"SERVER-01": {}}},
                }
            },
            "detached": {"hosts": {"SERVER-02": {}}},
        }

        mavi._retain_single_inventory_host(inventory, "all")

        windows = inventory["all"]["children"]["windows"]
        self.assertEqual(list(windows["hosts"]), ["all"])
        self.assertEqual(windows["vars"], {"ansible_connection": "ssh"})
        self.assertEqual(inventory["all"]["children"]["linux"]["hosts"], {})
        self.assertEqual(inventory["detached"]["hosts"], {})
        runner_source = inspect.getsource(mavi._run_winrm_temporary_play)
        self.assertIn("_temporary_single_host_inventory", runner_source)
        self.assertNotIn('"--limit"', runner_source)

    def test_live_audit_applies_requested_ssh_key_to_transport_and_key_probe(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            private_key = Path(raw_directory) / "recovery_ed25519"
            public_key = Path(str(private_key) + ".pub")
            public_key.write_text(
                "ssh-ed25519 AAAATEST recovery@example.test\n",
                encoding="utf-8",
            )

            options = mavi._live_audit_transport_options(
                Path(raw_directory),
                {"vars": {"ansible_connection": "ssh"}},
                {},
                requested_ssh_key=private_key,
            )

            self.assertEqual(
                options["extra_vars"]["ansible_ssh_private_key_file"],
                str(private_key.resolve()),
            )
            self.assertEqual(
                mavi._public_key_prefix_for_private_key(private_key),
                "ssh-ed25519 AAAATEST",
            )
        status_source = inspect.getsource(mavi.cmd_ssh_status)
        self.assertIn("requested_ssh_key=requested_key_path", status_source)
        self.assertIn("_ssh_private_key_path_for_host(", status_source)
        key_path_source = inspect.getsource(mavi._ssh_private_key_path_for_host)
        self.assertIn('"ansible_ssh_private_key_file"', key_path_source)
        self.assertIn('"mavi_ssh_private_key_file"', key_path_source)

    def test_public_key_prefix_is_derived_when_companion_file_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            private_key = Path(raw_directory) / "recovery_ed25519"
            private_key.write_text("private-key-placeholder", encoding="utf-8")
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="ssh-ed25519 AAAADERIVED recovery@example.test\n",
                stderr="",
            )
            with (
                mock.patch(
                    "windows_provisioner.openssh.shutil.which",
                    return_value="ssh-keygen",
                ),
                mock.patch(
                    "windows_provisioner.openssh.subprocess.run",
                    return_value=completed,
                ) as run_mock,
            ):
                prefix = mavi._public_key_prefix_for_private_key(private_key)

        self.assertEqual(prefix, "ssh-ed25519 AAAADERIVED")
        command = run_mock.call_args.args[0]
        self.assertEqual(command[:5], ["ssh-keygen", "-y", "-P", "", "-f"])
        self.assertEqual(command[5], str(private_key.resolve()))
        self.assertIs(run_mock.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_public_key_derivation_works_with_real_ssh_keygen(self) -> None:
        ssh_keygen = shutil.which("ssh-keygen")
        if not ssh_keygen:
            self.skipTest("ssh-keygen ist auf diesem Testsystem nicht verfügbar.")
        with tempfile.TemporaryDirectory() as raw_directory:
            private_key = Path(raw_directory) / "real_ed25519"
            generated = subprocess.run(
                [
                    ssh_keygen,
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "mavi-regression-test",
                    "-f",
                    str(private_key),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                generated.returncode,
                0,
                msg=(generated.stderr or generated.stdout),
            )
            public_key = Path(str(private_key) + ".pub")
            expected_prefix = " ".join(
                public_key.read_text(encoding="utf-8").split()[:2]
            )
            public_key.unlink()

            self.assertEqual(
                mavi._public_key_prefix_for_private_key(private_key),
                expected_prefix,
            )

    def test_ssh_key_path_is_remembered_across_psrp_transport(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            custom_key = directory / "custom_ed25519"
            settings = {
                "private_key": directory / "default_ed25519",
                "known_hosts": directory / "known_hosts",
                "port": 22,
            }
            host_data: dict[str, object] = {}
            with mock.patch(
                "windows_provisioner.remote.get_ssh_settings",
                return_value=settings,
            ):
                mavi._apply_ssh_transport(
                    directory,
                    host_data,
                    key_path=custom_key,
                    port=2222,
                )

            expected_key = str(custom_key.resolve())
            self.assertEqual(host_data["mavi_ssh_private_key_file"], expected_key)
            self.assertEqual(host_data["ansible_ssh_private_key_file"], expected_key)

            with mock.patch(
                "windows_provisioner.remote._psrp_https_inventory_vars",
                return_value={"ansible_connection": "psrp", "ansible_port": 5986},
            ):
                mavi._apply_psrp_https_transport(
                    host_data,
                    settings={},
                    fqdn="pc01.example.test",
                    ca_cert=directory / "ca.pem",
                )

            self.assertEqual(host_data["mavi_ssh_private_key_file"], expected_key)
            self.assertNotIn("ansible_ssh_private_key_file", host_data)
            self.assertEqual(
                mavi._ssh_private_key_path_for_host(
                    directory,
                    {"vars": {}},
                    host_data,
                ),
                custom_key.resolve(),
            )

    def test_bootstrap_identity_is_persisted_only_after_host_remote_proof(self) -> None:
        guide_source = inspect.getsource(mavi.cmd_ssh_guide)
        self.assertNotIn('host_data["mavi_bootstrap"]', guide_source)
        self.assertNotIn("atomic_write_yaml", guide_source)

        source = inspect.getsource(mavi.cmd_ssh_winrm_https)
        remote_probe = source.index("play=_bootstrap_ca_probe_play")
        second_kerberos_probe = source.index('description="Zweiter Kerberos-HTTPS-Nachweis"')
        persistence = source.index('host_data["mavi_bootstrap"]')
        inventory_write = source.index(
            'atomic_write_yaml(project_paths(args.project)["inventory"], inv)'
        )
        self.assertLess(remote_probe, second_kerberos_probe)
        self.assertLess(second_kerberos_probe, persistence)
        self.assertLess(persistence, inventory_write)

    def test_full_reset_validates_all_version_three_proofs(self) -> None:
        source = inspect.getsource(mavi.cmd_ssh_winrm_reset)
        bootstrap_scope = source.index('not reset_result["bootstrap_scope_verified"]')
        listener_scope = source.index('not reset_result["winrm_listeners_cleared"]')
        sshd_scope = source.index('not reset_result["openssh_stopped_verified"]')
        version_three = source.index('"version": 3')
        inventory_write = source.index(
            'atomic_write_yaml(project_paths(args.project)["inventory"], inv)'
        )
        self.assertLess(bootstrap_scope, version_three)
        self.assertLess(listener_scope, version_three)
        self.assertLess(sshd_scope, version_three)
        self.assertLess(version_three, inventory_write)

    def test_full_reset_persists_an_explicit_fail_closed_transport(self) -> None:
        args = types.SimpleNamespace(
            project=Path("project"),
            host="PC-01",
            key=None,
            port=None,
            disable_openssh=True,
            yes=True,
        )
        bootstrap_der = b"bootstrap-root"
        bootstrap_thumbprint = mavi._certificate_thumbprint_from_der(bootstrap_der)
        bootstrap_certificate = base64.b64encode(bootstrap_der).decode("ascii")
        winrm_thumbprint = "A" * 40
        inventory = {"all": {}}
        windows = {"vars": {"ansible_connection": "ssh", "ansible_port": 22}}

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            key_path = directory / "controller-key"
            vault_path = directory / "vault-password"
            vault_path.write_text("temporary", encoding="utf-8")
            host_data = {
                "ansible_host": "192.0.2.10",
                "ansible_connection": "ssh",
                "ansible_port": 2222,
                "ansible_shell_type": "powershell",
                "ansible_ssh_private_key_file": str(key_path),
                "ansible_ssh_common_args": "strict-options",
                "ansible_password": "",
                "mavi_winrm_https": {"root_thumbprint": winrm_thumbprint},
                "mavi_winrm_fqdn": "pc01.example.test",
            }
            reset_result = {
                "winrm_root_thumbprint": winrm_thumbprint,
                "bootstrap_root_thumbprints": [bootstrap_thumbprint],
                "bootstrap_scope_verified": True,
                "openssh_startup_disabled": True,
                "openssh_disable_scheduled": True,
                "openssh_stopped_verified": True,
                "openssh_state": "Stopped",
                "openssh_start_mode": "Disabled",
                "winrm_scope_verified": True,
                "winrm_listeners_cleared": True,
                "removed_listeners": 1,
                "removed_certificates": 1,
                "removed_firewall_rules": 1,
                "removed_openssh_firewall_rules": 1,
                "removed_openssh_keys": 1,
                "removed_openssh_config_backups": 1,
                "removed_bootstrap_certificates": 1,
                "preserved_foreign_winrm_listeners": 0,
            }

            with (
                mock.patch("windows_provisioner.environment.ensure_initialized"),
                mock.patch(
                    "windows_provisioner.remote._host_inventory_entry",
                    return_value=(inventory, windows, host_data),
                ),
                mock.patch(
                    "windows_provisioner.openssh._controller_bound_bootstrap_root_certificates",
                    return_value=(
                        bootstrap_thumbprint,
                        {bootstrap_thumbprint: bootstrap_certificate},
                    ),
                ),
                mock.patch(
                    "windows_provisioner.openssh._ssh_private_key_path_for_host",
                    return_value=key_path,
                ),
                mock.patch(
                    "windows_provisioner.openssh._public_key_prefix_for_private_key",
                    return_value="ssh-ed25519 AAAATEST",
                ),
                mock.patch(
                    "windows_provisioner.remote._winrm_pki_paths",
                    return_value={
                        "ca_cert": directory / "ca.pem",
                        "ca_der": directory / "ca.cer",
                    },
                ),
                mock.patch(
                    "windows_provisioner.openssh._winrm_reset_root_identity",
                    return_value=(winrm_thumbprint, "winrm-root-der"),
                ),
                mock.patch(
                    "windows_provisioner.openssh._winrm_leaf_fqdn_for_host",
                    return_value="pc01.example.test",
                ),
                mock.patch(
                    "windows_provisioner.execution.create_temporary_vault_password_file",
                    return_value=vault_path,
                ),
                mock.patch(
                    "windows_provisioner.remote._run_winrm_temporary_play",
                    side_effect=["bootstrap-probe", "reset-result"],
                ),
                mock.patch(
                    "windows_provisioner.remote._extract_bootstrap_ca_probe_result",
                    return_value={
                        "current_root_thumbprint": bootstrap_thumbprint,
                        "present_root_thumbprints": [bootstrap_thumbprint],
                    },
                ),
                mock.patch(
                    "windows_provisioner.remote._extract_winrm_reset_result",
                    return_value=reset_result,
                ),
                mock.patch(
                    "windows_provisioner.remote._remove_host_winrm_certificate_artifacts",
                    return_value=(2, []),
                ),
                mock.patch(
                    "windows_provisioner.remote._remove_host_bootstrap_artifacts",
                    return_value=(2, []),
                ),
                mock.patch(
                    "windows_provisioner.remote._apply_ssh_transport",
                    side_effect=AssertionError("full reset must not reactivate SSH"),
                ) as apply_ssh_mock,
                mock.patch(
                    "windows_provisioner.environment.project_paths",
                    return_value={
                        "inventory": directory / "inventory.yml",
                        "config": directory / "mavi_config.yml",
                    },
                ),
                mock.patch("windows_provisioner.environment.atomic_write_yaml") as write_mock,
                mock.patch("windows_provisioner.openssh.getpass.getpass", return_value="vault"),
                mock.patch("builtins.print"),
            ):
                mavi.cmd_ssh_winrm_reset(args)

            apply_ssh_mock.assert_not_called()
            write_mock.assert_called_once_with(directory / "inventory.yml", inventory)
            self.assertEqual(host_data["ansible_connection"], "mavi_disabled")
            self.assertEqual(mavi._connection_label(windows, host_data), "AUS")
            self.assertEqual(host_data["mavi_ssh_port"], 2222)
            self.assertEqual(
                host_data["mavi_ssh_private_key_file"],
                str(key_path.resolve()),
            )
            for active_transport_var in (
                "ansible_port",
                "ansible_shell_type",
                "ansible_ssh_private_key_file",
                "ansible_ssh_common_args",
                "ansible_password",
            ):
                self.assertNotIn(active_transport_var, host_data)
            self.assertNotIn("mavi_winrm_https", host_data)
            self.assertNotIn("mavi_winrm_fqdn", host_data)
            self.assertTrue(
                host_data["mavi_remote_management_disabled"]["remote_cleanup_verified"]
            )

    def test_reset_removes_only_exactly_identified_listener_and_bootstrap_ca(self) -> None:
        bootstrap_certificate = base64.b64encode(b"bootstrap-root").decode("ascii")
        openssh_config_backup = (
            r"MaviProvisioner\bootstrap\test-instance"
            r"\sshd_config.pre-mavi.bak"
        )
        play = mavi._winrm_reset_play(
            root_thumbprint="A" * 40,
            root_certificate_der_base64=base64.b64encode(b"root").decode("ascii"),
            expected_fqdn="pc01.example.test",
            bootstrap_root_certificates_der_base64=[bootstrap_certificate],
            disable_openssh=True,
            public_key_prefix="ssh-ed25519 AAAA",
            openssh_config_backup=openssh_config_backup,
        )
        script = play[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]
        parameters = play[0]["tasks"][0]["ansible.windows.win_powershell"]["parameters"]
        self.assertIn("Get-MaviWinRmListeners", script)
        self.assertIn("Test-MaviLeafCertificate", script)
        self.assertIn("Get-MaviLeavesForRoot", script)
        self.assertNotRegex(script, r"(?im)^\s*\$matches\s*(?:=|\+=)")
        self.assertIn("$matchedListeners += $listener", script)
        self.assertIn("-AnyMaviLeafForRoot $disableOpenSsh", script)
        self.assertIn(
            "[Convert]::ToBase64String($chainRoot.RawData) -ceq",
            script,
        )
        self.assertIn("$certificatesToRemove = if ($disableOpenSsh)", script)
        self.assertIn("New-MaviCertificateRollbackSnapshot", script)
        self.assertIn("Restore-MaviWinRmArtifacts", script)
        self.assertIn(
            "Remove-Item -LiteralPath $certificate.PSPath -Force",
            script,
        )
        self.assertNotIn(
            "Remove-Item -LiteralPath $certificate.PSPath -DeleteKey",
            script,
        )
        self.assertIn("alte FQDNs", script)
        self.assertIn("$expectedFriendlyName", script)
        self.assertIn("GetNameInfo", script)
        self.assertIn("X509Chain", script)
        self.assertIn("ExtraStore.Add($ExpectedRoot)", script)
        self.assertIn("IgnoreNotTimeValid", script)
        self.assertIn("[string]$_.Group -eq 'Mavi Provisioner'", script)
        self.assertIn('Cert:\\LocalMachine\\Root\\$bootstrapRootThumbprint', script)
        self.assertIn("BootstrapRootThumbprints", script)
        self.assertIn("BootstrapRootCertificatesDerBase64", script)
        self.assertIn("stimmt nicht bytegenau mit dem Controller-Archiv überein", script)
        self.assertIn(
            "Die WinRM-Root im Root Store stimmt nicht bytegenau mit dem Controller-DER überein",
            script,
        )
        self.assertNotIn("$remoteRootPath", script)
        self.assertIn("RootCertificateDerBase64", script)
        self.assertIn("BootstrapScopeVerified", script)
        self.assertIn("WinRmListenersCleared", script)
        self.assertIn("OpenSshStoppedVerified", script)
        self.assertIn("OpenSshState", script)
        self.assertIn("OpenSshStartMode", script)
        self.assertIn("Der gestartete SYSTEM-Task hat sshd nicht nachweisbar gestoppt", script)
        self.assertNotIn("Start-Sleep -Seconds 20", script)
        self.assertIn("$OpenSshConfigBackupPath", script)
        self.assertNotIn("sshd_config.mavi-v", script)
        self.assertEqual(
            parameters["OpenSshConfigBackupPath"],
            openssh_config_backup,
        )
        self.assertNotIn("Remove-ItemProperty -LiteralPath $policyPath", script)
        self.assertNotIn("Nicht alle WinRM-Listener konnten entfernt werden", script)
        self.assertEqual(parameters["ExpectedFqdn"], "pc01.example.test")
        self.assertEqual(
            parameters["BootstrapRootCertificatesDerBase64"],
            [bootstrap_certificate],
        )

        preflight = script.index("$preflightWinRmListeners = @(")
        foreign_listener_gate = script.index(
            "$preflightWinRmListeners.Count -ne $preflightMaviWinRmListeners.Count"
        )
        first_listener_removal = script.index(
            "Remove-Item -LiteralPath $listener.PSPath"
        )
        self.assertLess(preflight, foreign_listener_gate)
        self.assertLess(foreign_listener_gate, first_listener_removal)

        task_preflight = script.index("Register-ScheduledTask")
        listener_snapshot = script.index("$winRmListenerSnapshots +=")
        firewall_snapshot = script.index("$winRmFirewallSnapshots +=")
        certificate_snapshot = script.index("$winRmCertificateSnapshots +=")
        mutation_gate = script.index("$winRmMutationStarted = $true")
        self.assertLess(task_preflight, listener_snapshot)
        self.assertLess(listener_snapshot, firewall_snapshot)
        self.assertLess(firewall_snapshot, certificate_snapshot)
        self.assertLess(certificate_snapshot, mutation_gate)
        self.assertLess(mutation_gate, first_listener_removal)

    def test_saved_winrm_fqdn_scopes_reset_and_live_audit_leaves(self) -> None:
        expected_fqdn = mavi._winrm_leaf_fqdn_for_host(
            Path("project-not-read"),
            "other-host",
            {"mavi_winrm_https": {"fqdn": "PC01.EXAMPLE.TEST"}},
        )

        self.assertEqual(expected_fqdn, "pc01.example.test")
        reset_source = inspect.getsource(mavi.cmd_ssh_winrm_reset)
        audit_source = inspect.getsource(mavi.cmd_ssh_status)
        self.assertIn("expected_fqdn=expected_winrm_fqdn", reset_source)
        self.assertIn("expected_fqdn=expected_winrm_fqdn", audit_source)

    def test_openssh_finalizer_prepares_first_and_rolls_back_every_access_artifact(self) -> None:
        script = mavi._winrm_reset_play(
            root_thumbprint="A" * 40,
            bootstrap_root_certificates_der_base64=[
                base64.b64encode(b"bootstrap-root").decode("ascii")
            ],
            disable_openssh=True,
            public_key_prefix="ssh-ed25519 AAAA",
        )[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]
        finalizer = script[script.index("$sshdServicePath ="):]

        child_start = finalizer.index("$childScript = @'")
        child_end = finalizer.index("\n'@", child_start)
        child_script = finalizer[child_start:child_end]
        self.assertNotIn("Unregister-ScheduledTask", child_script)

        register_task = finalizer.index("Register-ScheduledTask")
        start_task = finalizer.index("Start-ScheduledTask", register_task)
        stop_verified = finalizer.index("$openSshStoppedVerified = $true", start_task)
        unregister_task = finalizer.index("Unregister-ScheduledTask", stop_verified)
        key_removal = finalizer.index("[System.IO.File]::WriteAllLines", unregister_task)
        backup_removal = finalizer.index(
            "Remove-Item -LiteralPath $openSshConfigBackup",
            key_removal,
        )
        firewall_removal = finalizer.index(
            "Remove-NetFirewallRule -InputObject $rule",
            backup_removal,
        )
        self.assertLess(register_task, start_task)
        self.assertLess(start_task, stop_verified)
        self.assertLess(stop_verified, unregister_task)
        self.assertLess(unregister_task, key_removal)
        self.assertLess(key_removal, backup_removal)
        self.assertLess(backup_removal, firewall_removal)

        rollback = finalizer[finalizer.index("$openSshFinalizationError ="):]
        self.assertIn("Stop-ScheduledTask", rollback)
        self.assertIn("$taskRollbackDeadline", rollback)
        self.assertIn("-notin @('Running', 'Queued')", rollback)
        self.assertIn("[System.IO.File]::WriteAllBytes($keyFile", rollback)
        self.assertIn("$originalOpenSshConfigBackupBytes", rollback)
        self.assertIn("New-NetFirewallRule", rollback)
        self.assertIn("Restore-MaviSshdServiceState", rollback)
        self.assertIn("der ursprüngliche SSH-Zugang wurde wiederhergestellt", rollback)

    def test_cleanup_failure_restores_winrm_before_reset_throws(self) -> None:
        script = mavi._winrm_reset_play(
            root_thumbprint="A" * 40,
            bootstrap_root_certificates_der_base64=[
                base64.b64encode(b"bootstrap-root").decode("ascii")
            ],
            disable_openssh=True,
        )[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]
        cleanup_gate = script.index("if (-not [string]::IsNullOrWhiteSpace($cleanupError))")
        cleanup_throw = script.index(
            'throw "Mavi WinRM Reset wurde nicht vollständig ausgeführt: $cleanupError"',
            cleanup_gate,
        )
        final_stop = script.index(
            "Stop-Service -Name WinRM -Force -ErrorAction Stop",
            cleanup_gate,
        )
        self.assertLess(cleanup_throw, final_stop)
        self.assertNotIn(
            "finally {\n    Stop-Service -Name WinRM",
            script,
        )

        outer_rollback = script.rindex("$resetError = $_.Exception.Message")
        maintenance = script.index("Enable-MaviWinRmProviderMaintenance", outer_rollback)
        restore_artifacts = script.index("Restore-MaviWinRmArtifacts", maintenance)
        restore_policy = script.index("Restore-MaviAllowNegotiatePolicy", restore_artifacts)
        restore_service = script.index("Restore-MaviWinRmServiceState", restore_artifacts)
        remove_isolation = script.index("Remove-MaviResetIsolationRules", restore_service)
        restored_throw = script.index(
            "WinRM-Artefakte und Dienstzustand wurden wiederhergestellt",
            restore_service,
        )
        self.assertLess(maintenance, restore_artifacts)
        self.assertLess(restore_artifacts, restore_service)
        self.assertLess(restore_artifacts, restore_policy)
        self.assertLess(restore_policy, restore_service)
        self.assertLess(restore_service, remove_isolation)
        self.assertLess(restore_service, restored_throw)

    def test_reset_opens_local_wsman_only_behind_temporary_port_blocks(self) -> None:
        script = mavi._winrm_reset_play(
            root_thumbprint="A" * 40,
            root_certificate_der_base64=base64.b64encode(b"root").decode("ascii"),
            expected_fqdn="pc01.example.test",
            disable_openssh=True,
        )[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]

        self.assertIn("$originalAllowNegotiateExists", script)
        self.assertIn("$originalAllowNegotiateProperty.Value", script)
        maintenance_function = script.index(
            "function Enable-MaviWinRmProviderMaintenance"
        )
        block_http = script.index(
            "Enable-MaviResetIsolationRule -Name $resetHttpIsolationRuleName -Port 5985",
            maintenance_function,
        )
        block_https = script.index(
            "Enable-MaviResetIsolationRule -Name $resetHttpsIsolationRuleName -Port 5986",
            block_http,
        )
        enable_negotiate = script.index("-Value 1", block_https)
        restart_winrm = script.index(
            "Restart-Service -Name WinRM -Force -ErrorAction Stop",
            enable_negotiate,
        )
        provider_probe = script.index(
            "Get-ChildItem -Path WSMan:\\localhost\\Listener",
            restart_winrm,
        )
        self.assertLess(block_http, block_https)
        self.assertLess(block_https, enable_negotiate)
        self.assertLess(enable_negotiate, restart_winrm)
        self.assertLess(restart_winrm, provider_probe)
        main_attempt = script.index("$winRmMaintenanceAttempted = $true")
        main_maintenance = script.index(
            "Enable-MaviWinRmProviderMaintenance", main_attempt
        )
        first_reset_provider_access = script.index(
            "$preflightWinRmListeners = @(", main_maintenance
        )
        self.assertLess(main_attempt, main_maintenance)
        self.assertLess(main_maintenance, first_reset_provider_access)
        self.assertNotIn(
            "Start-Service -Name WinRM -ErrorAction SilentlyContinue",
            script,
        )

        finalization = script.index(
            "# Die ursprüngliche Richtlinie wird noch unter vollständiger"
        )
        restore_policy = script.index(
            "Restore-MaviAllowNegotiatePolicy", finalization
        )
        stop_winrm = script.index(
            "Stop-Service -Name WinRM -Force -ErrorAction Stop", restore_policy
        )
        remove_isolation = script.index(
            "Remove-MaviResetIsolationRules", stop_winrm
        )
        openssh_finalizer = script.index(
            "Start-ScheduledTask -TaskName $taskName", remove_isolation
        )
        self.assertLess(restore_policy, stop_winrm)
        self.assertLess(stop_winrm, remove_isolation)
        self.assertLess(remove_isolation, openssh_finalizer)

    def test_legacy_cleanup_removes_both_controller_artifact_namespaces(self) -> None:
        host = "-PC01"
        current_token, legacy_token = mavi._host_artifact_tokens(
            host,
            include_legacy=True,
        )
        request_id = "a" * 24

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pki_root = root / "pki"
            paths = {
                "root": pki_root,
                "requests": pki_root / "requests",
                "profiles": pki_root / "profiles",
                "certs": pki_root / "certs",
            }
            for directory in paths.values():
                directory.mkdir(parents=True, exist_ok=True)
            expected_files = []
            for token in (current_token, legacy_token):
                expected_files.extend(
                    [
                        paths["requests"] / f"{token}-{request_id}.csr.pem",
                        paths["profiles"] / f"{token}-{request_id}.cnf",
                        paths["certs"] / f"{token}-{request_id}.cert.pem",
                        paths["certs"] / f"{token}-{request_id}.cer",
                    ]
                )
            unrelated = paths["certs"] / f"PC02-{request_id}.cer"
            for artifact in [*expected_files, unrelated]:
                artifact.write_bytes(b"artifact")

            with mock.patch(
                "windows_provisioner.remote._winrm_pki_paths",
                return_value=paths,
            ):
                removed, warnings = mavi._remove_host_winrm_certificate_artifacts(
                    root,
                    host,
                    known_hosts=(host,),
                )

            self.assertEqual(removed, len(expected_files))
            self.assertEqual(warnings, [])
            self.assertTrue(all(not artifact.exists() for artifact in expected_files))
            self.assertTrue(unrelated.exists())

            webroot = root / "webroot"
            current_dir = webroot / current_token
            legacy_dir = webroot / legacy_token
            for directory in (current_dir, legacy_dir):
                directory.mkdir(parents=True)
                (directory / "setup.ps1").write_bytes(b"bootstrap")
            unrelated_dir = webroot / "PC02"
            unrelated_dir.mkdir()

            with mock.patch(
                "windows_provisioner.openssh._bootstrap_settings",
                return_value={"local_dir": webroot},
            ):
                removed, warnings = mavi._remove_host_bootstrap_artifacts(
                    root,
                    host,
                    known_hosts=(host,),
                )

            self.assertEqual(removed, 4)
            self.assertEqual(warnings, [])
            self.assertFalse(current_dir.exists())
            self.assertFalse(legacy_dir.exists())
            self.assertTrue(unrelated_dir.exists())

            collision_id = "b" * 24
            current_artifact = paths["certs"] / f"{current_token}-{collision_id}.cer"
            colliding_artifact = paths["certs"] / f"{legacy_token}-{collision_id}.cer"
            current_artifact.write_bytes(b"current")
            colliding_artifact.write_bytes(b"belongs to PC01")
            with mock.patch(
                "windows_provisioner.remote._winrm_pki_paths",
                return_value=paths,
            ):
                removed, warnings = mavi._remove_host_winrm_certificate_artifacts(
                    root,
                    host,
                    known_hosts=(host, "PC01"),
                )
            self.assertEqual(removed, 1)
            self.assertFalse(current_artifact.exists())
            self.assertTrue(colliding_artifact.exists())
            self.assertTrue(any("Host-Kollision" in warning for warning in warnings))

        issuer_source = inspect.getsource(mavi._issue_winrm_server_certificate)
        publisher_source = inspect.getsource(mavi._publish_https_ssh_bootstrap)
        self.assertIn("safe_host = _safe_host_token(host)", issuer_source)
        self.assertIn("safe_host = _safe_host_token(host)", publisher_source)
        self.assertNotIn("include_legacy=True", issuer_source)
        self.assertNotIn("include_legacy=True", publisher_source)

    def test_leaf_pruning_happens_after_listener_proof(self) -> None:
        play = mavi._winrm_install_https_play(
            certificate_path="C:\\Mavi\\leaf.cer",
            certificate_sha256="a" * 64,
            ca_certificate_path="C:\\Mavi\\root.cer",
            ca_certificate_sha256="b" * 64,
            identity={"fqdn": "pc01.example.test", "short_name": "pc01"},
            settings={"port": 5986},
            ansible_server_ip="192.0.2.10",
        )
        script = play[0]["tasks"][3]["ansible.windows.win_powershell"]["script"]
        self.assertLess(
            script.index("$finalListenerThumbprint"),
            script.index("$prunedServerCertificates"),
        )
        self.assertIn("if ($certificateThumbprint.Equals($selectedThumbprint", script)
        self.assertIn("Test-MaviManagedLeafForRoot", script)
        self.assertIn("-ExpectedFqdn $Fqdn", script)
        self.assertIn("$expectedFriendlyName", script)
        self.assertIn("GetNameInfo", script)
        self.assertIn("ExtraStore.Add($ExpectedRoot)", script)
        self.assertIn("IgnoreNotTimeValid", script)
        self.assertIn(
            "Remove-Item -LiteralPath $certificate.PSPath -DeleteKey",
            script,
        )

    def test_winrm_provider_is_not_reopened_after_kerberos_only_restart(self) -> None:
        play = mavi._winrm_install_https_play(
            certificate_path="C:\\Mavi\\leaf.cer",
            certificate_sha256="a" * 64,
            ca_certificate_path="C:\\Mavi\\root.cer",
            ca_certificate_sha256="b" * 64,
            identity={"fqdn": "pc01.example.test", "short_name": "pc01"},
            settings={"port": 5986},
            ansible_server_ip="192.0.2.10",
        )
        script = play[0]["tasks"][3]["ansible.windows.win_powershell"]["script"]
        kerberos_only_policy = script.index(
            "Set-ItemProperty -Path $policyPath -Name AllowNegotiate -Type DWord -Value 0"
        )
        final_restart = script.index(
            "Restart-Service -Name WinRM -Force -ErrorAction Stop",
            kerberos_only_policy,
        )
        last_provider_listener_read = script.rindex(
            "Get-ChildItem -Path WSMan:\\localhost\\Listener"
        )
        socket_proof = script.index("Get-NetTCPConnection `")
        isolation_release = script.rindex(
            "Get-NetFirewallRule -DisplayName $setupIsolationRuleName"
        )

        self.assertLess(last_provider_listener_read, kerberos_only_policy)
        self.assertLess(final_restart, socket_proof)
        self.assertLess(socket_proof, isolation_release)

    def test_live_audit_contains_no_mutating_powershell_command(self) -> None:
        play = mavi._remote_management_audit_play(
            winrm_root_thumbprint="A" * 40,
            winrm_root_certificate_der_base64=base64.b64encode(b"root").decode("ascii"),
            bootstrap_root_thumbprints=("B" * 40,),
            current_leaf_thumbprint="C" * 40,
            current_key_prefix="ssh-ed25519 AAAA",
            expected_fqdn="pc01.example.test",
        )
        script = play[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]
        parameters = play[0]["tasks"][0]["ansible.windows.win_powershell"]["parameters"]
        self.assertNotRegex(script, r"\b(?:Remove|Set|New)-[A-Za-z]+")
        self.assertIn("Test-MaviAuditLeafCertificate", script)
        self.assertIn("WinRmLeafIdentityProvided", script)
        self.assertIn("$expectedFriendlyName", script)
        self.assertIn("GetNameInfo", script)
        self.assertIn("ExtraStore.Add($ExpectedRoot)", script)
        self.assertIn("IgnoreNotTimeValid", script)
        disabled_gate = script.index("[int]$result.WinRM.Start -eq 4")
        provider_call = script.index("Get-ChildItem -Path WSMan:\\localhost\\Listener")
        self.assertLess(disabled_gate, provider_call)
        self.assertIn("ListenerCheckSkippedDisabled", script)
        self.assertEqual(parameters["ExpectedFqdn"], "pc01.example.test")

    def test_live_audit_reports_each_bootstrap_ca_individually(self) -> None:
        first_thumbprint = "B" * 40
        second_thumbprint = "C" * 40
        play = mavi._remote_management_audit_play(
            winrm_root_thumbprint="A" * 40,
            winrm_root_certificate_der_base64=base64.b64encode(b"root").decode("ascii"),
            bootstrap_root_thumbprints=(first_thumbprint, second_thumbprint),
            current_leaf_thumbprint="D" * 40,
            current_key_prefix="ssh-ed25519 AAAA",
            expected_fqdn="pc01.example.test",
        )
        script = play[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]
        self.assertIn("BootstrapRoots = [ordered]@{}", script)
        self.assertIn(
            "$result.Certificates.BootstrapRoots[$bootstrapRootThumbprint]",
            script,
        )
        self.assertNotIn("BootstrapRootNotAfter", script)

        audit = {
            "Certificates": {
                "CurrentLeafPresent": False,
                "WinRmRootPresent": False,
                "BootstrapRootPresent": True,
                "BootstrapRoots": {
                    first_thumbprint: {
                        "Present": True,
                        "NotAfter": "2000-01-01T00:00:00Z",
                    },
                    second_thumbprint: {"Present": False, "NotAfter": ""},
                },
                "ManagedLeafCount": 0,
            }
        }
        with mock.patch("builtins.print") as print_mock:
            mavi._print_live_audit_certificate_metadata(
                audit,
                winrm_root_thumbprint="A" * 40,
                bootstrap_root_thumbprints=(first_thumbprint, second_thumbprint),
                current_leaf_thumbprint="D" * 40,
            )
        output = "\n".join(str(call.args[0]) for call in print_mock.call_args_list)
        self.assertIn(f"{first_thumbprint} — 2000-01-01T00:00:00Z (abgelaufen)", output)
        self.assertIn(f"{second_thumbprint} — FEHLT", output)

    def test_bootstrap_probe_requires_current_ca_on_the_target(self) -> None:
        current_certificate = base64.b64encode(b"current-root").decode("ascii")
        historical_certificate = base64.b64encode(b"historical-root").decode("ascii")
        play = mavi._bootstrap_ca_probe_play(
            current_root_certificate_der_base64=current_certificate,
            candidate_root_certificates_der_base64=[
                current_certificate,
                historical_certificate,
            ],
        )
        parameters = play[0]["tasks"][0]["ansible.windows.win_powershell"]["parameters"]
        script = play[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]
        self.assertEqual(
            parameters["CandidateRootCertificatesDerBase64"],
            [current_certificate, historical_certificate],
        )
        self.assertEqual(
            parameters["CurrentRootCertificateDerBase64"],
            current_certificate,
        )
        self.assertEqual(parameters["RequireCurrentRootValue"], 1)
        self.assertIn("$presentThumbprints -notcontains $CurrentRootThumbprint", script)
        self.assertIn("stimmt nicht bytegenau mit der Controller-CA überein", script)
        self.assertNotRegex(script, r"(?i)Subject|Issuer")

        reset_probe = mavi._bootstrap_ca_probe_play(
            current_root_certificate_der_base64=current_certificate,
            candidate_root_certificates_der_base64=[historical_certificate],
            require_current_root=False,
        )
        reset_parameters = reset_probe[0]["tasks"][0]["ansible.windows.win_powershell"][
            "parameters"
        ]
        self.assertEqual(reset_parameters["RequireCurrentRootValue"], 0)

    def test_controller_bootstrap_scope_comes_only_from_current_and_archived_der(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            current_der = b"current-controller-root"
            historical_der = b"historical-controller-root"
            current_thumbprint = mavi._certificate_thumbprint_from_der(current_der)
            historical_thumbprint = mavi._certificate_thumbprint_from_der(historical_der)
            system_ca = directory / "current.cer"
            system_ca.write_bytes(current_der)
            archive = directory / "trusted-roots"
            archive.mkdir()
            (archive / f"{historical_thumbprint}.cer").write_bytes(historical_der)
            paths = {
                "system_ca": system_ca,
                "ca_cert": directory / "missing.pem",
                "ca_archive": archive,
            }

            resolved_current, certificates = (
                mavi._controller_bound_bootstrap_root_certificates(paths)
            )

        self.assertEqual(resolved_current, current_thumbprint)
        self.assertEqual(
            certificates,
            {
                current_thumbprint: base64.b64encode(current_der).decode("ascii"),
                historical_thumbprint: base64.b64encode(historical_der).decode("ascii"),
            },
        )
        self.assertNotIn("B" * 40, certificates)

    def test_controller_bootstrap_archive_rejects_thumbprint_filename_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            system_ca = directory / "current.cer"
            system_ca.write_bytes(b"current-controller-root")
            archive = directory / "trusted-roots"
            archive.mkdir()
            (archive / f"{'B' * 40}.cer").write_bytes(b"foreign-enterprise-root")
            paths = {
                "system_ca": system_ca,
                "ca_cert": directory / "missing.pem",
                "ca_archive": archive,
            }

            with self.assertRaisesRegex(ValueError, "Archivname und DER-Thumbprint"):
                mavi._controller_bound_bootstrap_root_certificates(paths)

    def test_manipulated_verified_bootstrap_state_cannot_authorize_foreign_root(self) -> None:
        args = types.SimpleNamespace(
            project=Path("project"),
            host="PC-01",
            key=None,
            port=None,
            disable_openssh=True,
            yes=True,
        )
        current_der = b"current-controller-root"
        current_thumbprint = mavi._certificate_thumbprint_from_der(current_der)
        current_certificate = base64.b64encode(current_der).decode("ascii")
        foreign_thumbprint = "B" * 40
        inventory = {"all": {}}
        windows = {"vars": {"ansible_connection": "ssh", "ansible_port": 22}}
        host_data = {
            "ansible_connection": "ssh",
            "ansible_port": 22,
            "mavi_bootstrap": {
                "version": 2,
                "remote_verified": True,
                "root_thumbprint": current_thumbprint,
                "root_thumbprints": [current_thumbprint, foreign_thumbprint],
            },
        }

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.remote._host_inventory_entry",
                return_value=(inventory, windows, host_data),
            ),
            mock.patch(
                "windows_provisioner.openssh._controller_bound_bootstrap_root_certificates",
                return_value=(
                    current_thumbprint,
                    {current_thumbprint: current_certificate},
                ),
            ),
            mock.patch("windows_provisioner.environment.eprint") as error_mock,
            mock.patch("windows_provisioner.remote._run_winrm_temporary_play") as run_mock,
        ):
            with self.assertRaises(SystemExit):
                mavi.cmd_ssh_winrm_reset(args)

        run_mock.assert_not_called()
        error_text = "\n".join(str(call.args[0]) for call in error_mock.call_args_list)
        self.assertIn("exakte DER", error_text)
        self.assertIn("keinen unvollständigen Rückbau-Nachweis", error_text)

    def test_live_audit_psrp_uses_the_verified_private_kerberos_session(self) -> None:
        windows = {"vars": {"ansible_connection": "ssh"}}
        host_data = {"ansible_connection": "psrp"}
        with mock.patch(
            "windows_provisioner.remote._saved_winrm_https_transport",
            return_value=(
                {"port": 5986, "auth": "kerberos", "message_encryption": "auto"},
                "pc01.example.test",
                Path("ca.pem"),
                "admin@EXAMPLE.TEST",
            ),
        ):
            options = mavi._live_audit_transport_options(Path("project"), windows, host_data)

        self.assertTrue(options["inherit_vault_psrp_credentials"])
        self.assertTrue(options["use_vault_kerberos_ticket"])
        self.assertEqual(options["kerberos_principal"], "admin@EXAMPLE.TEST")
        self.assertEqual(options["kerberos_target_fqdn"], "pc01.example.test")
        self.assertEqual(options["extra_vars"]["ansible_connection"], "psrp")
        self.assertEqual(options["extra_vars"]["ansible_psrp_protocol"], "https")
        self.assertEqual(options["extra_vars"]["ansible_psrp_cert_validation"], "validate")
        self.assertEqual(
            options["extra_vars"]["ansible_psrp_negotiate_hostname_override"],
            "pc01.example.test",
        )

    def test_live_audit_winrm_is_forced_to_verified_psrp_transport(self) -> None:
        windows = {"vars": {"ansible_connection": "ssh"}}
        host_data = {"ansible_connection": "winrm"}
        with mock.patch(
            "windows_provisioner.remote._saved_winrm_https_transport",
            return_value=(
                {"port": 5986, "auth": "kerberos", "message_encryption": "auto"},
                "pc01.example.test",
                Path("ca.pem"),
                "admin@EXAMPLE.TEST",
            ),
        ):
            options = mavi._live_audit_transport_options(Path("project"), windows, host_data)

        self.assertTrue(options["inherit_vault_psrp_credentials"])
        self.assertTrue(options["use_vault_kerberos_ticket"])
        self.assertEqual(options["kerberos_principal"], "admin@EXAMPLE.TEST")
        self.assertEqual(options["kerberos_target_fqdn"], "pc01.example.test")
        self.assertEqual(options["extra_vars"]["ansible_connection"], "psrp")
        self.assertEqual(options["extra_vars"]["ansible_psrp_protocol"], "https")
        self.assertEqual(options["extra_vars"]["ansible_psrp_cert_validation"], "validate")

    def test_legacy_v1_ca_hash_mismatch_refuses_root_scope_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            ca_cert = directory / "root.pem"
            ca_der = directory / "root.der"
            ca_cert.write_bytes(b"old-controller-ca")
            ca_der.write_bytes(b"new-controller-ca")
            with (
                mock.patch(
                    "windows_provisioner.openssh._sha256_file",
                    return_value="b" * 64,
                ),
                mock.patch(
                    "windows_provisioner.remote._certificate_thumbprint_from_file",
                    return_value="C" * 40,
                ),
            ):
                with self.assertRaisesRegex(ValueError, "v1-CA-Hash"):
                    mavi._winrm_reset_root_identity(
                        {"version": 1, "ca_sha256": "a" * 64},
                        ca_cert=ca_cert,
                        ca_der=ca_der,
                    )

    def test_legacy_v1_matching_ca_hash_recovers_exact_root_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            ca_cert = directory / "root.pem"
            ca_der = directory / "root.der"
            ca_cert.write_bytes(b"same-root-pem")
            ca_der.write_bytes(b"same-root-der")
            with (
                mock.patch(
                    "windows_provisioner.openssh._sha256_file",
                    return_value="a" * 64,
                ),
                mock.patch(
                    "windows_provisioner.remote._certificate_thumbprint_from_file",
                    side_effect=["C" * 40, "C" * 40],
                ),
                mock.patch(
                    "windows_provisioner.remote._certificate_der_base64_from_file",
                    return_value="cm9vdA==",
                ),
            ):
                identity = mavi._winrm_reset_root_identity(
                    {"version": 1, "ca_sha256": "a" * 64},
                    ca_cert=ca_cert,
                    ca_der=ca_der,
                )

        self.assertEqual(identity, ("C" * 40, "cm9vdA=="))

    def test_stored_winrm_thumbprint_without_controller_der_is_not_delete_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            with self.assertRaisesRegex(ValueError, "Inventory-Thumbprint allein"):
                mavi._winrm_reset_root_identity(
                    {"version": 2, "root_thumbprint": "C" * 40},
                    ca_cert=directory / "missing.pem",
                    ca_der=directory / "missing.cer",
                )

    def test_host_key_lookup_uses_ssh_port_instead_of_psrp_port(self) -> None:
        windows = {"vars": {"ansible_connection": "ssh", "ansible_port": 22}}
        psrp_host = {"ansible_connection": "psrp", "ansible_port": 5986}
        remembered_host = dict(psrp_host, mavi_ssh_port=2222)

        self.assertEqual(mavi._ssh_host_key_port(windows, psrp_host, 2200), 2200)
        self.assertEqual(mavi._ssh_host_key_port(windows, remembered_host, 2200), 2222)

    def test_reset_requires_explicit_port_for_legacy_psrp_without_memory(self) -> None:
        args = types.SimpleNamespace(
            project=Path("project"),
            host="PC-01",
            key=None,
            port=None,
            disable_openssh=False,
            yes=True,
        )
        inventory = {"all": {}}
        windows = {"vars": {"ansible_connection": "ssh", "ansible_port": 22}}
        host_data = {"ansible_connection": "psrp", "ansible_port": 5986}

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.remote._host_inventory_entry",
                return_value=(inventory, windows, host_data),
            ),
            mock.patch("windows_provisioner.environment.eprint") as error_mock,
            mock.patch("windows_provisioner.openssh.cmd_ssh_use") as use_mock,
        ):
            with self.assertRaises(SystemExit) as raised:
                mavi.cmd_ssh_winrm_reset(args)

        self.assertEqual(raised.exception.code, 1)
        use_mock.assert_not_called()
        error_text = "\n".join(str(call.args[0]) for call in error_mock.call_args_list)
        self.assertIn("--port", error_text)
        self.assertIn("rät nicht den globalen Standard", error_text)

    def test_reset_accepts_explicit_port_for_legacy_psrp_and_persists_via_ssh_use(self) -> None:
        args = types.SimpleNamespace(
            project=Path("project"),
            host="PC-01",
            key=None,
            port=2222,
            disable_openssh=False,
            yes=True,
        )
        inventory = {"all": {}}
        windows = {"vars": {"ansible_connection": "ssh", "ansible_port": 22}}
        host_data = {"ansible_connection": "psrp", "ansible_port": 5986}

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.remote._host_inventory_entry",
                return_value=(inventory, windows, host_data),
            ),
            mock.patch(
                "windows_provisioner.openssh.cmd_ssh_use",
                side_effect=RuntimeError("stop after SSH selection"),
            ) as use_mock,
        ):
            with self.assertRaisesRegex(RuntimeError, "stop after SSH selection"):
                mavi.cmd_ssh_winrm_reset(args)

        forwarded = use_mock.call_args.args[0]
        self.assertEqual(forwarded.port, 2222)

    def test_reset_reuses_remembered_ssh_port_when_leaving_psrp(self) -> None:
        args = types.SimpleNamespace(
            project=Path("project"),
            host="PC-01",
            key=None,
            port=None,
            disable_openssh=False,
            yes=True,
        )
        inventory = {"all": {}}
        windows = {"vars": {"ansible_connection": "ssh", "ansible_port": 22}}
        host_data = {
            "ansible_connection": "psrp",
            "ansible_port": 5986,
            "mavi_ssh_port": 2222,
            "mavi_ssh_private_key_file": "C:/keys/custom_ed25519",
        }

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.remote._host_inventory_entry",
                return_value=(inventory, windows, host_data),
            ),
            mock.patch(
                "windows_provisioner.remote.get_ssh_settings",
                return_value={"port": 2200},
            ),
            mock.patch(
                "windows_provisioner.openssh.cmd_ssh_use",
                side_effect=RuntimeError("stop after SSH selection"),
            ) as use_mock,
        ):
            with self.assertRaisesRegex(RuntimeError, "stop after SSH selection"):
                mavi.cmd_ssh_winrm_reset(args)

        forwarded = use_mock.call_args.args[0]
        self.assertEqual(forwarded.port, 2222)
        self.assertEqual(forwarded.key, "C:/keys/custom_ed25519")

    def test_live_all_uses_bounded_parallel_workers_and_reports_progress(self) -> None:
        source = inspect.getsource(mavi.cmd_ssh_status)
        worker_limit = source.index("worker_count = min(8, len(selected))")
        executor = source.index("with ThreadPoolExecutor(", worker_limit)
        completions = source.index("for future in as_completed(future_hosts)", executor)
        ordered_report = source.index('print("\\nHOSTS")', completions)

        self.assertLess(worker_limit, executor)
        self.assertLess(executor, completions)
        self.assertLess(completions, ordered_report)
        self.assertIn('print(f"  {symbol} {name}: {progress}", flush=True)', source)

    def test_generated_powershell_is_syntax_valid(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell ist auf diesem Testsystem nicht verfügbar.")
        reset = mavi._winrm_reset_play(
            root_thumbprint="A" * 40,
            root_certificate_der_base64=base64.b64encode(b"root").decode("ascii"),
            bootstrap_root_certificates_der_base64=[
                base64.b64encode(b"bootstrap-root").decode("ascii")
            ],
            disable_openssh=True,
        )[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]
        install = mavi._winrm_install_https_play(
            certificate_path="C:\\Mavi\\leaf.cer",
            certificate_sha256="a" * 64,
            ca_certificate_path="C:\\Mavi\\root.cer",
            ca_certificate_sha256="b" * 64,
            identity={"fqdn": "pc01.example.test", "short_name": "pc01"},
            settings={"port": 5986},
            ansible_server_ip="192.0.2.10",
        )[0]["tasks"][3]["ansible.windows.win_powershell"]["script"]
        audit = mavi._remote_management_audit_play(
            winrm_root_thumbprint="A" * 40,
            winrm_root_certificate_der_base64=base64.b64encode(b"root").decode("ascii"),
            bootstrap_root_thumbprints=("B" * 40,),
            current_leaf_thumbprint="C" * 40,
            current_key_prefix="ssh-ed25519 AAAA",
        )[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]
        bootstrap_probe = mavi._bootstrap_ca_probe_play(
            current_root_certificate_der_base64=base64.b64encode(
                b"bootstrap-root"
            ).decode("ascii"),
            candidate_root_certificates_der_base64=[
                base64.b64encode(b"bootstrap-root").decode("ascii"),
                base64.b64encode(b"historical-root").decode("ascii"),
            ],
        )[0]["tasks"][0]["ansible.windows.win_powershell"]["script"]

        for script in (reset, install, audit, bootstrap_probe):
            command = (
                "$ErrorActionPreference='Stop';"
                "$tokens=$null;$errors=$null;"
                "$source=[Console]::In.ReadToEnd();"
                "[void][System.Management.Automation.Language.Parser]::ParseInput("
                "$source,[ref]$tokens,[ref]$errors);"
                "if ($errors.Count -gt 0) { $errors | ForEach-Object { $_.Message }; exit 1 }"
            )
            completed = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                input=script,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=(completed.stderr or completed.stdout),
            )

    def test_powershell_can_verify_an_expired_leaf_against_its_exact_root(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell ist auf diesem Testsystem nicht verfügbar.")
        script = r'''
$ErrorActionPreference = 'Stop'
$rootKey = [System.Security.Cryptography.RSA]::Create(2048)
$rootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=Mavi Test Root', $rootKey,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)
$rootRequest.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
)
$root = $rootRequest.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-5), [DateTimeOffset]::UtcNow.AddDays(5))
$leafKey = [System.Security.Cryptography.RSA]::Create(2048)
$leafRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=Mavi Test Leaf', $leafKey,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)
$leafRequest.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
)
$serial = [byte[]]::new(16)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($serial)
$leaf = $leafRequest.Create($root, [DateTimeOffset]::UtcNow.AddDays(-3), [DateTimeOffset]::UtcNow.AddDays(-2), $serial)
if ($leaf.NotAfter.ToUniversalTime() -ge [DateTime]::UtcNow) { throw 'Das Test-Leaf ist nicht abgelaufen.' }
$strictChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$strictChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$strictChain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
[void]$strictChain.ChainPolicy.ExtraStore.Add($root)
if ($strictChain.Build($leaf)) { throw 'Die strikte Kette hat das abgelaufene Leaf unerwartet akzeptiert.' }
if (@($strictChain.ChainStatus | Where-Object Status -eq 'NotTimeValid').Count -eq 0) {
    throw 'Die strikte Kette meldet das abgelaufene Leaf nicht als NotTimeValid.'
}
$strictChain.Dispose()
$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chain.ChainPolicy.VerificationFlags = (
    [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority -bor
    [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid
)
[void]$chain.ChainPolicy.ExtraStore.Add($root)
if (-not $chain.Build($leaf)) { throw 'Kette wurde nicht aufgebaut.' }
$actualRoot = [string]$chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
if (-not $actualRoot.Equals([string]$root.Thumbprint, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Die Kette endete nicht am erwarteten Root-Thumbprint.'
}
'''
        completed = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=(completed.stderr or completed.stdout),
        )

    def test_inventory_is_written_only_after_remote_result_and_controller_cleanup(self) -> None:
        source = inspect.getsource(mavi.cmd_ssh_winrm_reset)
        remote_result = source.index("reset_result = _extract_winrm_reset_result")
        controller_cleanup = source.index(
            "removed_artifacts, artifact_warnings = _remove_host_winrm_certificate_artifacts",
            remote_result,
        )
        inventory_write = source.index("atomic_write_yaml(project_paths(args.project)[\"inventory\"], inv)")
        self.assertLess(remote_result, controller_cleanup)
        self.assertLess(controller_cleanup, inventory_write)


if __name__ == "__main__":
    unittest.main()
