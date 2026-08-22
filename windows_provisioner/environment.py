# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Projekt-, Datei-, Pfad- und Umgebungsverwaltung."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    hashlib,
    os,
    re,
    shutil,
    subprocess,
    sys,
    tempfile,
    yaml,
)

from .environment_files import (
    eprint,
    die,
    project_paths,
    load_yaml,
    atomic_write_yaml,
    write_if_missing,
    write_managed_file,
    ensure_initialized,
)

from .environment_paths import (
    get_config,
    normalize_path,
    _path_signature,
    _installer_candidates,
    resolve_installer_path,
    display_share_path,
    browse_files,
    browse_installer,
    choose_installer_path,
)

from .environment_installers import (
    sha256_file,
    read_binary_sample,
    _decode_binary_text,
    _extract_execution_level,
    _inspect_msi_properties,
)





# ---------------------------------------------------------------------
# Intelligente Silent-Parameter-Erkennung und lokale Lernregeln
# ---------------------------------------------------------------------

from .environment_files import (
    atomic_write_text,
)

from .environment_mavi import (
    _mavi_collect_remote_windows_facts,
    _mavi_controller_ipv4_candidates,
    _mavi_doctor_fact_checks,
    _mavi_doctor_finding,
    _mavi_doctor_print,
    _mavi_doctor_profile_checks,
    _mavi_doctor_summary,
    _mavi_doctor_target_checks,
    _mavi_doctor_windows_collector,
    _mavi_drive_label,
    _mavi_fact_dict,
    _mavi_fact_list,
    _mavi_has_cifs_support,
    _mavi_install_cifs_support,
    _mavi_load_windows_facts,
    _mavi_mount_smb_source,
    _mavi_normalize_allowed_cidrs,
    _mavi_normalize_ansible_user,
    _mavi_normalize_controller_ipv4,
    _mavi_normalize_domain,
    _mavi_profile_ready,
    _mavi_profile_validation_issues,
    _mavi_prompt_normalized,
    _mavi_prompt_source_root,
    _mavi_root_command_prefix,
    _mavi_source_label,
    _mavi_source_root,
    _mavi_unc_mount_parts,
    _mavi_valid_dns_name,
    _mavi_valid_https_url,
    _mavi_write_config,
    _mavi_write_windows_collector,
    cmd_doctor,
    cmd_doctor_collector,
    cmd_setup,
)

__all__ = (
    "eprint",
    "die",
    "project_paths",
    "load_yaml",
    "atomic_write_yaml",
    "write_if_missing",
    "write_managed_file",
    "ensure_initialized",
    "get_config",
    "normalize_path",
    "_path_signature",
    "_installer_candidates",
    "resolve_installer_path",
    "display_share_path",
    "browse_files",
    "browse_installer",
    "choose_installer_path",
    "sha256_file",
    "read_binary_sample",
    "_decode_binary_text",
    "_extract_execution_level",
    "_inspect_msi_properties",
    "atomic_write_text",
    "_mavi_drive_label",
    "_mavi_source_root",
    "_mavi_source_label",
    "_mavi_normalize_controller_ipv4",
    "_mavi_normalize_domain",
    "_mavi_normalize_ansible_user",
    "_mavi_normalize_allowed_cidrs",
    "_mavi_profile_validation_issues",
    "_mavi_profile_ready",
    "_mavi_controller_ipv4_candidates",
    "_mavi_write_config",
    "_mavi_prompt_normalized",
    "_mavi_prompt_source_root",
    "_mavi_root_command_prefix",
    "_mavi_has_cifs_support",
    "_mavi_install_cifs_support",
    "_mavi_unc_mount_parts",
    "_mavi_mount_smb_source",
    "cmd_setup",
    "_mavi_doctor_finding",
    "_mavi_doctor_print",
    "_mavi_doctor_summary",
    "_mavi_valid_dns_name",
    "_mavi_valid_https_url",
    "_mavi_doctor_profile_checks",
    "_mavi_doctor_target_checks",
    "_mavi_doctor_windows_collector",
    "_mavi_write_windows_collector",
    "_mavi_load_windows_facts",
    "_mavi_collect_remote_windows_facts",
    "_mavi_fact_dict",
    "_mavi_fact_list",
    "_mavi_doctor_fact_checks",
    "cmd_doctor_collector",
    "cmd_doctor",
)