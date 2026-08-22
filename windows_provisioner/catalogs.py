# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Softwarekataloge, Parameterprofile und interaktive Auswahl."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    os,
    re,
    sys,
    yaml,
)

from .catalog_selection import (
    slugify,
    prompt,
    prompt_choice,
    select_from_list,
    choose_host_interactive,
    choose_software_interactive,
    CTRL2_SENTINEL,
    _input_with_ctrl2,
    _software_selection_rows,
    choose_software_single_with_multi_shortcut,
    choose_software_multi_interactive,
    choose_catalog_by_number,
    yes_no,
)

from .catalog_storage import (
    CATALOG_NAME_RE,
    validate_catalog_name,
    catalog_path,
    list_catalog_names,
    get_default_catalog_name,
    resolve_catalog_name,
    choose_catalog_interactive,
    get_catalog,
    save_catalog,
    cmd_catalog_list,
    cmd_catalog_create,
    cmd_catalog_set_default,
    cmd_catalog_copy,
)

from .catalog_parameters import (
    PARAMETER_PROFILE_FIELDS,
    load_parameter_backups,
    save_parameter_backups,
    parameter_profile_from_app,
    backup_parameter_profile,
    cmd_params_backup,
    cmd_params_list,
    _restore_parameter_profile,
    cmd_params_restore,
    parameter_backup_menu,
)

from .catalog_contexts import (
    EDITABLE_CONTEXTS,
    _context_label,
    DEFAULT_VISIBLE_INSTALL_CONTEXTS,
    _normalize_context_value,
    get_visible_install_contexts,
    _visible_context_choices,
    prompt_install_context,
    install_context_options_menu,
    options_menu,
)

from .catalog_editing import (
    _save_quick_edit,
    cmd_software_edit,
    _parse_multi_program_selection,
    _bulk_context_compatibility,
    _apply_bulk_install_context,
    bulk_install_context_menu,
)

from .catalog_menu import (
    catalog_menu,
    cmd_init,
)

from .catalog_products import (
    OFFICE_PRODUCTS,
)


from .catalog_parameters import (
    _scrub_parameter_backup_secrets,
)

from .catalog_storage import (
    SOFTWARE_KEY_RE,
    _validate_catalog_for_persistence,
    validate_host_address,
    validate_software_key,
)

__all__ = (
    "slugify",
    "prompt",
    "prompt_choice",
    "select_from_list",
    "choose_host_interactive",
    "choose_software_interactive",
    "CTRL2_SENTINEL",
    "_input_with_ctrl2",
    "_software_selection_rows",
    "choose_software_single_with_multi_shortcut",
    "choose_software_multi_interactive",
    "choose_catalog_by_number",
    "yes_no",
    "CATALOG_NAME_RE",
    "validate_catalog_name",
    "catalog_path",
    "list_catalog_names",
    "get_default_catalog_name",
    "resolve_catalog_name",
    "choose_catalog_interactive",
    "get_catalog",
    "save_catalog",
    "cmd_catalog_list",
    "cmd_catalog_create",
    "cmd_catalog_set_default",
    "cmd_catalog_copy",
    "PARAMETER_PROFILE_FIELDS",
    "load_parameter_backups",
    "save_parameter_backups",
    "parameter_profile_from_app",
    "backup_parameter_profile",
    "cmd_params_backup",
    "cmd_params_list",
    "_restore_parameter_profile",
    "cmd_params_restore",
    "parameter_backup_menu",
    "EDITABLE_CONTEXTS",
    "_context_label",
    "DEFAULT_VISIBLE_INSTALL_CONTEXTS",
    "_normalize_context_value",
    "get_visible_install_contexts",
    "_visible_context_choices",
    "prompt_install_context",
    "install_context_options_menu",
    "options_menu",
    "_save_quick_edit",
    "cmd_software_edit",
    "_parse_multi_program_selection",
    "_bulk_context_compatibility",
    "_apply_bulk_install_context",
    "bulk_install_context_menu",
    "catalog_menu",
    "cmd_init",
    "OFFICE_PRODUCTS",
    "SOFTWARE_KEY_RE",
    "validate_software_key",
    "validate_host_address",
    "_validate_catalog_for_persistence",
    "_scrub_parameter_backup_secrets",
)