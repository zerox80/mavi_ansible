# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Katalogdarstellung, Berichte und redigierte Ausgaben."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    html,
    ipaddress,
    os,
    re,
    shutil,
    socket,
    subprocess,
    sys,
    time,
    urllib,
    yaml,
)

from .report_catalog import (
    _clip_cell,
    _software_mode_meta,
    _software_installer_display,
    _software_parameters_display,
    _software_detection_display,
    _software_timeout_display,
    _render_catalog_terminal_table,
)

from .report_redaction import (
    _SENSITIVE_ARGUMENT_NAME,
    _SENSITIVE_ARGUMENT_VALUE,
    _SENSITIVE_ARGUMENT_PATTERNS,
    redact_sensitive_text,
    _report_safe_arguments,
)

from .report_html import (
    REPORT_HTTP_PORT,
    REPORT_SERVER_MARKER,
    _html_badge,
    _generate_catalog_html_report,
    _local_ipv4_for_target,
    _port_available_for_http,
    _report_bind_ip,
    _report_server_is_ours,
    _ensure_catalog_report_server,
)

from .report_commands import (
    _print_catalog_summary,
    cmd_software_list,
    cmd_software_show,
    cmd_software_remove,
)


from .report_security import (
    REPORT_HTTP_DEFAULT_TTL,
    VAULT_ARGUMENT_REFERENCE_RE,
    _catalog_report_bind_ip,
    _catalog_report_ttl,
    _literal_secret_argument_names,
    _unquote_argument_value,
    cmd_internal_report_serve,
    validate_installer_arguments,
)

__all__ = (
    "REPORT_HTTP_PORT",
    "REPORT_SERVER_MARKER",
    "_clip_cell",
    "_software_mode_meta",
    "_software_installer_display",
    "_software_parameters_display",
    "_software_detection_display",
    "_software_timeout_display",
    "_render_catalog_terminal_table",
    "_SENSITIVE_ARGUMENT_NAME",
    "_SENSITIVE_ARGUMENT_VALUE",
    "_SENSITIVE_ARGUMENT_PATTERNS",
    "redact_sensitive_text",
    "_report_safe_arguments",
    "_html_badge",
    "_generate_catalog_html_report",
    "_local_ipv4_for_target",
    "_port_available_for_http",
    "_report_bind_ip",
    "_report_server_is_ours",
    "_ensure_catalog_report_server",
    "_print_catalog_summary",
    "cmd_software_list",
    "cmd_software_show",
    "cmd_software_remove",
    "REPORT_HTTP_DEFAULT_TTL",
    "VAULT_ARGUMENT_REFERENCE_RE",
    "_unquote_argument_value",
    "_literal_secret_argument_names",
    "validate_installer_arguments",
    "_catalog_report_bind_ip",
    "_catalog_report_ttl",
    "cmd_internal_report_serve",
)