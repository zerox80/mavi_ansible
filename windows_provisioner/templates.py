# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Ansible- und PowerShell-Vorlagen für Windows-Endpunkte."""

from __future__ import annotations

from .template_printers import (
    PRINTER_PLAYBOOK_TEMPLATE,
    PRINTER_TASK_TEMPLATE,
)

from .template_installation import (
    PLAYBOOK_TEMPLATE,
    TASK_TEMPLATE,
    LIVE_PROBE_PLAYBOOK_TEMPLATE,
    DIAGNOSTIC_TASK_TEMPLATE,
)

from .template_clients import (
    CLIENT_OPTIMIZE_PLAYBOOK_TEMPLATE,
    CLIENT_UNINSTALL_PLAYBOOK_TEMPLATE,
)


__all__ = (
    "PRINTER_PLAYBOOK_TEMPLATE",
    "PRINTER_TASK_TEMPLATE",
    "PLAYBOOK_TEMPLATE",
    "TASK_TEMPLATE",
    "LIVE_PROBE_PLAYBOOK_TEMPLATE",
    "CLIENT_OPTIMIZE_PLAYBOOK_TEMPLATE",
    "CLIENT_UNINSTALL_PLAYBOOK_TEMPLATE",
    "DIAGNOSTIC_TASK_TEMPLATE",
)