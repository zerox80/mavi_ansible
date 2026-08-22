# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

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
    catalogs,
    cli,
    clients,
    environment,
    execution,
    installer_analysis,
    openssh,
    printers,
    remote,
    reports,
    software,
    templates,
)
from windows_provisioner import report_html


class ModuleLayoutTests(unittest.TestCase):
    def test_facades_keep_every_declared_export_available(self) -> None:
        for facade in (
            catalogs,
            cli,
            clients,
            environment,
            execution,
            installer_analysis,
            openssh,
            printers,
            remote,
            reports,
            software,
            templates,
        ):
            with self.subTest(module=facade.__name__):
                self.assertTrue(facade.__all__)
                for name in facade.__all__:
                    self.assertTrue(
                        hasattr(facade, name),
                        f"{facade.__name__} exportiert {name!r} nicht",
                    )

    def test_large_workflows_live_in_dedicated_implementation_modules(self) -> None:
        expected_modules = {
            cli.build_parser: "windows_provisioner.cli_parser",
            catalogs.cmd_software_edit: "windows_provisioner.catalog_editing",
            execution.cmd_install: "windows_provisioner.execution_install",
            installer_analysis.analyze_installer: "windows_provisioner.installer_workflow",
            openssh._publish_https_ssh_bootstrap: "windows_provisioner.openssh_bootstrap",
            openssh.cmd_ssh_status: "windows_provisioner.openssh_audit",
            remote._winrm_install_https_play: "windows_provisioner.remote_winrm_install",
            remote._winrm_reset_play: "windows_provisioner.remote_winrm_reset",
            printers.extract_inf_driver_names: "windows_provisioner.printer_inf",
            clients.cmd_client_uninstall: "windows_provisioner.client_uninstall",
            software.cmd_winget_add: "windows_provisioner.software_winget",
            environment.cmd_setup: "windows_provisioner.environment_mavi",
            execution.cmd_credentials_setup: "windows_provisioner.execution_credentials",
            openssh._openssh_artifact_instance_id: "windows_provisioner.openssh_lifecycle",
            reports.validate_installer_arguments: "windows_provisioner.report_security",
        }
        for function, expected_module in expected_modules.items():
            with self.subTest(function=function.__name__):
                self.assertEqual(function.__module__, expected_module)

    def test_report_server_starts_through_the_package_entrypoint(self) -> None:
        with (
            mock.patch.object(reports, "_port_available_for_http", return_value=True),
            mock.patch.object(reports, "_report_server_is_ours", return_value=True),
            mock.patch.object(report_html.subprocess, "Popen") as popen,
        ):
            report_url, error = reports._ensure_catalog_report_server(
                Path.cwd(),
                Path("software-report.html"),
            )

        self.assertIsNone(error)
        self.assertIn("/report/", report_url or "")
        command = popen.call_args.args[0]
        self.assertEqual(command[1:4], ["-m", "windows_provisioner", "_report-serve"])


if __name__ == "__main__":
    unittest.main()
