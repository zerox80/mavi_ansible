# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Verbindungstest.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

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




def cmd_ping(args: argparse.Namespace) -> None:
    from .execution import (
        _bound_ansible_session_context,
        run_subprocess,
    )

    from .clients import _create_prompted_client_vault_file
    from .environment import die
    from .remote import (
        _close_client_ansible_session,
        _open_client_ansible_session,
        _temporary_single_host_inventory,
    )

    vault_password_file = _create_prompted_client_vault_file()
    ansible_session: dict[str, Any] | None = None
    temporary_inventory_path: Path | None = None
    return_code = 2
    try:
        try:
            ansible_session = _open_client_ansible_session(
                project=args.project,
                host=str(args.host),
                vault_password_file=vault_password_file,
            )
            (
                ansible_executable,
                ansible_python,
                inventory_path,
                runtime_environment,
                transport_vars,
            ) = _bound_ansible_session_context(
                host=str(args.host),
                ansible_session=ansible_session,
            )
            temporary_inventory_path = _temporary_single_host_inventory(
                args.project,
                str(args.host),
            )
            inventory_path = temporary_inventory_path
            ansible_ad_hoc = ansible_executable.with_name("ansible")
            if not ansible_ad_hoc.is_file():
                raise RuntimeError(
                    "Das ansible-Kommando fehlt in der erkannten Ansible-Umgebung."
                )

            command = [
                str(ansible_python),
                "-I",
                str(ansible_ad_hoc),
                "-i",
                str(inventory_path),
                str(args.host),
                "-m",
                "ansible.windows.win_ping",
                "--vault-password-file",
                str(vault_password_file),
            ]
            if transport_vars:
                command.extend([
                    "--extra-vars",
                    json.dumps(
                        transport_vars,
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ),
                ])

            return_code = run_subprocess(
                command,
                args.project,
                env=runtime_environment,
            )
        except RuntimeError as exc:
            die(str(exc), code=2)
    finally:
        try:
            if temporary_inventory_path is not None:
                temporary_inventory_path.unlink(missing_ok=True)
        finally:
            try:
                _close_client_ansible_session(ansible_session)
            finally:
                vault_password_file.unlink(missing_ok=True)

    raise SystemExit(return_code)
