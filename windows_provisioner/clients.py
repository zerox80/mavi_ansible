# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Windows-Clientoptimierung und Programmbereinigung."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    base64,
    binascii,
    getpass,
    json,
    re,
    subprocess,
    time,
)
from .remote import (
    _close_client_ansible_session,
    _open_client_ansible_session,
)
from .settings import DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES

from .client_runtime import (
    _monitor_timeout_minutes,
    _client_uninstall_timeout_minutes,
    _create_prompted_client_vault_file,
    _wait_for_client_host_ready,
    _client_playbook_failure_detail,
    _run_client_playbook_result,
)

from .client_optimization import (
    _run_client_optimize,
    _format_client_timeout,
    _format_fast_startup_state,
    _print_client_optimization_state,
    _prompt_monitor_timeout,
    _prompt_client_optimize_changes,
    _print_client_optimize_result,
    cmd_client_optimize,
)

from .client_uninstall import (
    _query_client_classic_programs,
    _client_program_search_text,
    choose_client_programs_interactive,
    _prompt_client_uninstall_timeout,
    _print_client_uninstall_preview,
    _uninstall_client_program_once,
    _client_uninstall_base_result,
    _run_client_uninstall_sequence,
    _print_client_uninstall_summary,
    client_uninstall_interactive,
    cmd_client_uninstall,
)

from .client_menu import (
    client_menu,
)


__all__ = (
    "_monitor_timeout_minutes",
    "_client_uninstall_timeout_minutes",
    "_create_prompted_client_vault_file",
    "_wait_for_client_host_ready",
    "_client_playbook_failure_detail",
    "_run_client_playbook_result",
    "_run_client_optimize",
    "_format_client_timeout",
    "_format_fast_startup_state",
    "_print_client_optimization_state",
    "_prompt_monitor_timeout",
    "_prompt_client_optimize_changes",
    "_print_client_optimize_result",
    "cmd_client_optimize",
    "_query_client_classic_programs",
    "_client_program_search_text",
    "choose_client_programs_interactive",
    "_prompt_client_uninstall_timeout",
    "_print_client_uninstall_preview",
    "_uninstall_client_program_once",
    "_client_uninstall_base_result",
    "_run_client_uninstall_sequence",
    "_print_client_uninstall_summary",
    "client_uninstall_interactive",
    "cmd_client_uninstall",
    "client_menu",
)