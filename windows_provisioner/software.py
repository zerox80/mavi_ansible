# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Office-, WinGet-, Store- und Softwareaufnahme-Workflows."""

from __future__ import annotations

from ._dependencies import (
    Any,
    ET,
    Path,
    argparse,
    base64,
    getpass,
    json,
    os,
    re,
    subprocess,
    sys,
    tempfile,
    yaml,
)

from .software_office import (
    looks_like_office_candidate,
    friendly_product_from_id,
    parse_office_xml,
    choose_office_profile,
    choose_office_architecture,
    choose_office_language,
    office_default_creates_path,
    generate_office_xml,
    choose_xml_file,
    choose_odt_setup,
    cmd_add_office_odt,
    cmd_microsoft_add,
)

from .software_catalog import (
    cmd_software_scan,
    _neutralize_jinja_literal,
    sanitize_catalog_data,
    compact_silent_detection_for_catalog,
    compact_analysis_for_catalog,
    repair_catalog_jinja_noise,
    cmd_catalog_repair,
)

from .software_winget import (
    WINGET_PACKAGE_ID_RE,
    WINGET_SOURCE_RE,
    WINGET_VERSION_RE,
    _is_msstore_app,
    _software_type_label,
    _winget_validate_identifier,
    _winget_validate_source,
    _winget_validate_version,
    _parse_winget_search_table,
    _run_winget_search_remote,
    cmd_winget_add,
    cmd_store_add,
)

from .software_manual import (
    cmd_software_add,
)


__all__ = (
    "looks_like_office_candidate",
    "friendly_product_from_id",
    "parse_office_xml",
    "choose_office_profile",
    "choose_office_architecture",
    "choose_office_language",
    "office_default_creates_path",
    "generate_office_xml",
    "choose_xml_file",
    "choose_odt_setup",
    "cmd_add_office_odt",
    "cmd_microsoft_add",
    "cmd_software_scan",
    "_neutralize_jinja_literal",
    "sanitize_catalog_data",
    "compact_silent_detection_for_catalog",
    "compact_analysis_for_catalog",
    "repair_catalog_jinja_noise",
    "cmd_catalog_repair",
    "WINGET_PACKAGE_ID_RE",
    "WINGET_SOURCE_RE",
    "WINGET_VERSION_RE",
    "_is_msstore_app",
    "_software_type_label",
    "_winget_validate_identifier",
    "_winget_validate_source",
    "_winget_validate_version",
    "_parse_winget_search_table",
    "_run_winget_search_remote",
    "cmd_winget_add",
    "cmd_store_add",
    "cmd_software_add",
)