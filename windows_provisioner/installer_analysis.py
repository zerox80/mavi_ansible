# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Portable Erkennung und Analyse von Installationsprogrammen."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    pefile,
    re,
    shutil,
    struct,
    subprocess,
    sys,
)

from .installer_rules import (
    SILENT_SWITCH_DEFINITIONS,
    HELP_CONTEXT_MARKERS,
    normalize_rule_key,
    learned_rule_identity,
    load_installer_rules,
    save_installer_rules,
    find_learned_installer_rule,
    remember_installer_rule,
)

from .installer_switches import (
    _ascii_readability,
    _word_quality,
    _embedded_cli_records_from_binary,
    _switch_context_is_plausible,
    _extract_switch_occurrences_from_binary,
    _extract_switch_occurrences,
    _dedupe_switch_candidates,
    infer_silent_arguments_from_binary,
    infer_silent_arguments_from_strings,
    print_silent_detection,
)

from .installer_rule_commands import (
    cmd_rules_list,
    cmd_rules_remove,
)

from .installer_metadata import (
    PE_VERSION_KEYS,
    _clean_pe_text,
    _pe_architecture_from_bytes,
    _printable_pe_strings,
    _versioninfo_from_strings,
    _versioninfo_with_pefile,
    inspect_pe_metadata,
    _metadata_blob,
    _citrix_detection_path,
    _apply_known_exe_product_rule,
)

from .installer_workflow import (
    analyze_installer,
)


__all__ = (
    "SILENT_SWITCH_DEFINITIONS",
    "HELP_CONTEXT_MARKERS",
    "normalize_rule_key",
    "learned_rule_identity",
    "load_installer_rules",
    "save_installer_rules",
    "find_learned_installer_rule",
    "remember_installer_rule",
    "_ascii_readability",
    "_word_quality",
    "_embedded_cli_records_from_binary",
    "_switch_context_is_plausible",
    "_extract_switch_occurrences_from_binary",
    "_extract_switch_occurrences",
    "_dedupe_switch_candidates",
    "infer_silent_arguments_from_binary",
    "infer_silent_arguments_from_strings",
    "print_silent_detection",
    "cmd_rules_list",
    "cmd_rules_remove",
    "PE_VERSION_KEYS",
    "_clean_pe_text",
    "_pe_architecture_from_bytes",
    "_printable_pe_strings",
    "_versioninfo_from_strings",
    "_versioninfo_with_pefile",
    "inspect_pe_metadata",
    "_metadata_blob",
    "_citrix_detection_path",
    "_apply_known_exe_product_rule",
    "analyze_installer",
)