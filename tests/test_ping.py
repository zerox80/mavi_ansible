from __future__ import annotations

import argparse
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

yaml_stub = types.ModuleType("yaml")
yaml_stub.safe_load = lambda *_args, **_kwargs: {}
yaml_stub.safe_dump = lambda *_args, **_kwargs: ""
yaml_stub.YAMLError = ValueError
sys.modules.setdefault("yaml", yaml_stub)

from windows_provisioner import execution


class PingSessionTests(unittest.TestCase):
    def test_ping_uses_single_host_inventory_with_bound_kerberos_session(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            project = directory / "project"
            project.mkdir()
            vault_path = directory / "vault.txt"
            vault_path.write_text("secret\n", encoding="utf-8")
            ansible_playbook = directory / "venv" / "bin" / "ansible-playbook"
            ansible_ad_hoc = ansible_playbook.with_name("ansible")
            ansible_ad_hoc.parent.mkdir(parents=True)
            ansible_ad_hoc.touch()
            ansible_python = directory / "venv" / "bin" / "python"
            inventory_path = project / "inventory" / "hosts.yml"
            single_host_inventory = project / "inventory" / ".mavi-single-host-test.yml"
            single_host_inventory.parent.mkdir(parents=True)
            single_host_inventory.write_text("all: {}\n", encoding="utf-8")
            session = {
                "host": "all",
                "ansible_executable": ansible_playbook,
                "ansible_python": ansible_python,
                "inventory_path": inventory_path,
                "environment": {
                    "PATH": "/usr/bin",
                    "KRB5CCNAME": "FILE:/tmp/private-krb5cc",
                },
                "extra_vars": {
                    "ansible_user": "",
                    "ansible_psrp_user": "",
                    "ansible_password": "",
                    "ansible_psrp_password": "",
                },
            }

            with (
                mock.patch(
                    "windows_provisioner.clients._create_prompted_client_vault_file",
                    return_value=vault_path,
                ),
                mock.patch(
                    "windows_provisioner.remote._open_client_ansible_session",
                    return_value=session,
                ) as open_session,
                mock.patch(
                    "windows_provisioner.remote._close_client_ansible_session",
                ) as close_session,
                mock.patch(
                    "windows_provisioner.remote._temporary_single_host_inventory",
                    return_value=single_host_inventory,
                ) as single_inventory,
                mock.patch(
                    "windows_provisioner.execution.run_subprocess",
                    return_value=0,
                ) as run,
            ):
                with self.assertRaises(SystemExit) as raised:
                    execution.cmd_ping(
                        argparse.Namespace(project=project, host="all")
                    )

            self.assertEqual(raised.exception.code, 0)
            open_session.assert_called_once_with(
                project=project,
                host="all",
                vault_password_file=vault_path,
            )
            single_inventory.assert_called_once_with(project, "all")
            close_session.assert_called_once_with(session)
            self.assertFalse(vault_path.exists())
            self.assertFalse(single_host_inventory.exists())

            command = run.call_args.args[0]
            self.assertEqual(
                command[:3],
                [str(ansible_python), "-I", str(ansible_ad_hoc)],
            )
            self.assertEqual(
                command[command.index("-i") + 1],
                str(single_host_inventory),
            )
            self.assertIn("all", command)
            self.assertIn("ansible.windows.win_ping", command)
            self.assertNotIn("--ask-vault-pass", command)
            self.assertEqual(
                command[command.index("--vault-password-file") + 1],
                str(vault_path),
            )
            self.assertIn("--extra-vars", command)
            run.assert_called_once_with(
                command,
                project,
                env=session["environment"],
            )

    def test_ping_cleans_up_vault_file_when_kerberos_session_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            vault_path = directory / "vault.txt"
            vault_path.write_text("secret\n", encoding="utf-8")
            args = argparse.Namespace(project=directory, host="PC-01")

            with (
                mock.patch(
                    "windows_provisioner.clients._create_prompted_client_vault_file",
                    return_value=vault_path,
                ),
                mock.patch(
                    "windows_provisioner.remote._open_client_ansible_session",
                    side_effect=RuntimeError("Matching credential not found"),
                ),
                mock.patch(
                    "windows_provisioner.remote._close_client_ansible_session",
                ) as close_session,
                mock.patch("windows_provisioner.environment.eprint"),
            ):
                with self.assertRaises(SystemExit) as raised:
                    execution.cmd_ping(args)

            self.assertEqual(raised.exception.code, 2)
            close_session.assert_called_once_with(None)
            self.assertFalse(vault_path.exists())


if __name__ == "__main__":
    unittest.main()
