# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Inventory-, Ansible- und Installationsausführung."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    base64,
    json,
    os,
    queue,
    re,
    subprocess,
    sys,
    tempfile,
    threading,
    time,
    yaml,
)

from .execution_inventory import (
    load_inventory,
    ensure_windows_tree,
)

from .execution_hosts import (
    cmd_host_add,
    cmd_host_list,
    cmd_host_remove,
)

from .execution_process import (
    shlex_quote,
    run_subprocess,
    ANSI_ESCAPE_RE,
    strip_ansi,
    format_elapsed,
    is_live_install_task,
    task_software_key,
    print_live_install_status,
    print_general_wait_status,
    _stdout_reader,
    create_temporary_vault_password_file,
    redact_live_text,
    _probe_process_map,
    print_remote_live_probe,
    _bound_ansible_session_context,
    run_remote_live_probe,
    run_install_subprocess,
)

from .execution_ping import (
    cmd_ping,
)

from .execution_install import (
    selected_apps_need_user,
    _existing_target_installer_processes,
    _probe_pid_set,
    _new_busy_installer_processes,
    wait_for_post_install_settle,
    wait_for_host_ready,
    _installed_precheck_payload,
    precheck_installed_apps,
    _build_install_command,
    cmd_install,
)


from .execution_credentials import (
    VAULT_SECRET_VARIABLE_RE,
    _atomic_write_private_text,
    _credentials_vault_path,
    _encrypted_vault_variable_block,
    _prompt_secret_twice,
    _store_vault_secret,
    _upsert_encrypted_vault_variable,
    cmd_credentials_set,
    cmd_credentials_setup,
)

__all__ = (
    "load_inventory",
    "ensure_windows_tree",
    "cmd_host_add",
    "cmd_host_list",
    "cmd_host_remove",
    "shlex_quote",
    "run_subprocess",
    "ANSI_ESCAPE_RE",
    "strip_ansi",
    "format_elapsed",
    "is_live_install_task",
    "task_software_key",
    "print_live_install_status",
    "print_general_wait_status",
    "_stdout_reader",
    "create_temporary_vault_password_file",
    "redact_live_text",
    "_probe_process_map",
    "print_remote_live_probe",
    "_bound_ansible_session_context",
    "run_remote_live_probe",
    "run_install_subprocess",
    "cmd_ping",
    "selected_apps_need_user",
    "_existing_target_installer_processes",
    "_probe_pid_set",
    "_new_busy_installer_processes",
    "wait_for_post_install_settle",
    "wait_for_host_ready",
    "_installed_precheck_payload",
    "precheck_installed_apps",
    "_build_install_command",
    "cmd_install",
    "VAULT_SECRET_VARIABLE_RE",
    "_credentials_vault_path",
    "_atomic_write_private_text",
    "_encrypted_vault_variable_block",
    "_upsert_encrypted_vault_variable",
    "_prompt_secret_twice",
    "_store_vault_secret",
    "cmd_credentials_setup",
    "cmd_credentials_set",
)