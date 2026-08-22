from __future__ import annotations

import argparse
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


yaml_stub = types.ModuleType("yaml")
yaml_stub.safe_load = lambda *_args, **_kwargs: {}
yaml_stub.safe_dump = lambda *_args, **_kwargs: ""
yaml_stub.YAMLError = ValueError
sys.modules.setdefault("yaml", yaml_stub)

from windows_provisioner import (
    cli,
    execution,
)
from windows_provisioner.cli import build_parser


def _inventory() -> dict[str, object]:
    return {
        "all": {
            "children": {
                "windows": {
                    "vars": {"ansible_connection": "ssh"},
                    "hosts": {
                        "PC-01": {"ansible_host": "192.0.2.10"},
                        "PC-02": {"ansible_host": "192.0.2.11"},
                    },
                }
            }
        }
    }


class HostRemoveTests(unittest.TestCase):
    def test_host_remove_deletes_only_selected_inventory_entry(self) -> None:
        inventory = _inventory()
        args = argparse.Namespace(
            project=Path("project"),
            name="PC-01",
            yes=True,
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
            mock.patch(
                "windows_provisioner.environment.atomic_write_yaml"
            ) as write_mock,
            mock.patch("builtins.print") as print_mock,
        ):
            execution.cmd_host_remove(args)

        hosts = inventory["all"]["children"]["windows"]["hosts"]
        self.assertNotIn("PC-01", hosts)
        self.assertIn("PC-02", hosts)
        write_mock.assert_called_once_with(Path("inventory.yml"), inventory)
        self.assertTrue(
            any(
                "Remote-Konfiguration wurden nicht verändert" in str(call)
                for call in print_mock.call_args_list
            )
        )

    def test_host_remove_cancel_keeps_inventory_unchanged(self) -> None:
        inventory = _inventory()
        args = argparse.Namespace(
            project=Path("project"),
            name="PC-01",
            yes=False,
        )

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.execution.load_inventory",
                return_value=inventory,
            ),
            mock.patch(
                "windows_provisioner.catalogs.yes_no",
                return_value=False,
            ) as confirm_mock,
            mock.patch(
                "windows_provisioner.environment.atomic_write_yaml"
            ) as write_mock,
            mock.patch("builtins.print"),
        ):
            execution.cmd_host_remove(args)

        hosts = inventory["all"]["children"]["windows"]["hosts"]
        self.assertIn("PC-01", hosts)
        confirm_mock.assert_called_once_with(
            "PC 'PC-01' (192.0.2.10) wirklich aus dem Inventory entfernen?",
            default=False,
        )
        write_mock.assert_not_called()

    def test_host_remove_preserves_changes_made_while_confirmation_is_open(self) -> None:
        selected_inventory = _inventory()
        current_inventory = _inventory()
        current_hosts = current_inventory["all"]["children"]["windows"]["hosts"]
        current_hosts["PC-03"] = {"ansible_host": "192.0.2.12"}
        args = argparse.Namespace(
            project=Path("project"),
            name="PC-01",
            yes=False,
        )

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.environment.project_paths",
                return_value={"inventory": Path("inventory.yml")},
            ),
            mock.patch(
                "windows_provisioner.execution.load_inventory",
                side_effect=[selected_inventory, current_inventory],
            ) as load_mock,
            mock.patch(
                "windows_provisioner.catalogs.yes_no",
                return_value=True,
            ),
            mock.patch(
                "windows_provisioner.environment.atomic_write_yaml"
            ) as write_mock,
            mock.patch("builtins.print"),
        ):
            execution.cmd_host_remove(args)

        self.assertEqual(load_mock.call_count, 2)
        self.assertNotIn("PC-01", current_hosts)
        self.assertIn("PC-02", current_hosts)
        self.assertIn("PC-03", current_hosts)
        write_mock.assert_called_once_with(Path("inventory.yml"), current_inventory)

    def test_host_remove_rejects_a_changed_selected_entry(self) -> None:
        selected_inventory = _inventory()
        current_inventory = _inventory()
        current_hosts = current_inventory["all"]["children"]["windows"]["hosts"]
        current_hosts["PC-01"]["ansible_host"] = "192.0.2.99"
        args = argparse.Namespace(
            project=Path("project"),
            name="PC-01",
            yes=False,
        )

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.execution.load_inventory",
                side_effect=[selected_inventory, current_inventory],
            ),
            mock.patch(
                "windows_provisioner.catalogs.yes_no",
                return_value=True,
            ),
            mock.patch(
                "windows_provisioner.environment.atomic_write_yaml"
            ) as write_mock,
            mock.patch("windows_provisioner.environment.eprint"),
        ):
            with self.assertRaises(SystemExit):
                execution.cmd_host_remove(args)

        self.assertIn("PC-01", current_hosts)
        write_mock.assert_not_called()

    def test_host_remove_without_name_uses_interactive_list(self) -> None:
        inventory = _inventory()
        args = argparse.Namespace(
            project=Path("project"),
            name=None,
            yes=True,
        )

        with (
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.catalogs.choose_host_interactive",
                return_value="PC-02",
            ) as choose_mock,
            mock.patch(
                "windows_provisioner.execution.load_inventory",
                return_value=inventory,
            ),
            mock.patch(
                "windows_provisioner.environment.project_paths",
                return_value={"inventory": Path("inventory.yml")},
            ),
            mock.patch("windows_provisioner.environment.atomic_write_yaml"),
            mock.patch("builtins.print"),
        ):
            execution.cmd_host_remove(args)

        choose_mock.assert_called_once_with(Path("project"))
        hosts = inventory["all"]["children"]["windows"]["hosts"]
        self.assertNotIn("PC-02", hosts)
        self.assertIn("PC-01", hosts)

    def test_host_remove_cli_is_available(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["host", "remove", "PC-01", "--yes"])

        self.assertIs(args.func, execution.cmd_host_remove)
        self.assertEqual(args.name, "PC-01")
        self.assertTrue(args.yes)

    def test_main_menu_removes_host_selected_from_list(self) -> None:
        project = Path("project")

        with (
            mock.patch(
                "windows_provisioner.catalogs.get_default_catalog_name",
                return_value="default",
            ),
            mock.patch(
                "windows_provisioner.catalogs.choose_host_interactive",
                return_value="PC-02",
            ) as choose_mock,
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch(
                "windows_provisioner.execution.cmd_host_remove"
            ) as remove_mock,
            mock.patch("builtins.input", side_effect=["16", "0"]),
            mock.patch("builtins.print"),
        ):
            cli.menu(project)

        choose_mock.assert_called_once_with(project)
        remove_args = remove_mock.call_args.args[0]
        self.assertEqual(remove_args.project, project)
        self.assertEqual(remove_args.name, "PC-02")
        self.assertFalse(remove_args.yes)


if __name__ == "__main__":
    unittest.main()
