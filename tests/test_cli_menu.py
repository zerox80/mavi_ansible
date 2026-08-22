# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Tests für die kompakte vollständige Funktionsoberfläche."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest import TestCase, mock


yaml_stub = types.ModuleType("yaml")
yaml_stub.safe_load = lambda *_args, **_kwargs: {}
yaml_stub.safe_dump = lambda *_args, **_kwargs: ""
yaml_stub.YAMLError = ValueError
sys.modules.setdefault("yaml", yaml_stub)

from windows_provisioner import cli


class LegacyMenuTests(TestCase):
    def test_compact_menu_shows_frequent_actions_and_toggle(self) -> None:
        rendered = cli._render_legacy_menu("default", expanded=False)

        for key in cli._LEGACY_MENU_COMPACT_KEYS:
            label = dict(cli._LEGACY_MENU_ITEMS)[key]
            self.assertIn(label, rendered)

        self.assertNotIn("Microsoft-Produkt hinzufügen", rendered)
        self.assertNotIn("Windows-Client optimieren", rendered)
        self.assertIn("  M) Mehr anzeigen", rendered)
        self.assertIn("  0) Beenden", rendered)

    def test_expanded_menu_shows_every_action_and_collapse_toggle(self) -> None:
        rendered = cli._render_legacy_menu("default", expanded=True)

        for _, label in cli._LEGACY_MENU_ITEMS:
            self.assertIn(label, rendered)

        self.assertIn("  M) Weniger anzeigen", rendered)

    def test_m_toggles_full_menu_without_invalid_selection(self) -> None:
        project = Path("project")

        with (
            mock.patch(
                "windows_provisioner.catalogs.get_default_catalog_name",
                return_value="default",
            ),
            mock.patch("windows_provisioner.environment.ensure_initialized"),
            mock.patch("builtins.input", side_effect=["m", "0"]),
            mock.patch("builtins.print") as print_mock,
        ):
            cli.legacy_menu(project)

        rendered_menus = [
            call.args[0]
            for call in print_mock.call_args_list
            if call.args and "MAVI PROVISIONER — VOLLVERSION" in str(call.args[0])
        ]
        self.assertEqual(len(rendered_menus), 2)
        self.assertNotIn("Windows-Client optimieren", rendered_menus[0])
        self.assertIn("Windows-Client optimieren", rendered_menus[1])
        self.assertNotIn(
            "Ungültige Auswahl.",
            [call.args[0] for call in print_mock.call_args_list if call.args],
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
