# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Druckertreiberanalyse, Druckerkatalog und Installation."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    csv,
    ipaddress,
    json,
    re,
    sys,
    yaml,
)

from .printer_inf import (
    _read_inf_text,
    _parse_inf_sections,
    _inf_strings,
    extract_inf_driver_names,
    find_inf_driver_name_candidates,
    _inf_resolve_token,
    _inf_csv_fields,
    extract_inf_package_layout,
    extract_inf_referenced_files,
    _driver_package_inventory,
    _driver_package_resolution,
    choose_driver_package_root,
    _choose_driver_name_from_inf,
    _inf_section_values,
    inspect_printer_inf,
    scan_printer_driver_folder,
    _printer_inf_label,
    choose_printer_inf_from_folder,
    resolve_printer_driver_source,
)

from .printer_catalog import (
    get_printer_catalog,
    save_printer_catalog,
    choose_printer_interactive,
    cmd_printer_add,
    cmd_printer_list,
    cmd_printer_show,
    cmd_printer_remove,
)

from .printer_install import (
    cmd_printer_install,
    printer_menu,
)


__all__ = (
    "_read_inf_text",
    "_parse_inf_sections",
    "_inf_strings",
    "extract_inf_driver_names",
    "find_inf_driver_name_candidates",
    "_inf_resolve_token",
    "_inf_csv_fields",
    "extract_inf_package_layout",
    "extract_inf_referenced_files",
    "_driver_package_inventory",
    "_driver_package_resolution",
    "choose_driver_package_root",
    "_choose_driver_name_from_inf",
    "_inf_section_values",
    "inspect_printer_inf",
    "scan_printer_driver_folder",
    "_printer_inf_label",
    "choose_printer_inf_from_folder",
    "resolve_printer_driver_source",
    "get_printer_catalog",
    "save_printer_catalog",
    "choose_printer_interactive",
    "cmd_printer_add",
    "cmd_printer_list",
    "cmd_printer_show",
    "cmd_printer_remove",
    "cmd_printer_install",
    "printer_menu",
)