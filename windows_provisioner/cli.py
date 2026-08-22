# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Interaktive Menüs, Argumentparser und Programmeinstieg."""

from __future__ import annotations

from ._dependencies import (
    Path,
    argparse,
)

from .cli_menu import (
    menu,
)

from .cli_parser import (
    build_parser,
)




def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        menu(args.project.resolve())
        return

    args.project = args.project.resolve()
    args.func(args)

from .cli_menu import (
    _LEGACY_MENU_COMPACT_KEYS,
    _LEGACY_MENU_ITEMS,
    _LEGACY_MENU_TOGGLE_CHOICES,
    _render_legacy_menu,
    legacy_menu,
    mavi_credentials_menu,
    mavi_doctor_menu,
    mavi_pc_menu,
    mavi_setup_menu,
    mavi_software_source_setup,
)

__all__ = (
    "build_parser",
    "main",
    "menu",
    "legacy_menu",
    "mavi_software_source_setup",
    "mavi_setup_menu",
    "mavi_doctor_menu",
    "mavi_credentials_menu",
    "mavi_pc_menu",
)
