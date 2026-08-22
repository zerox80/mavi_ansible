# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Transport-, Kerberos- und WinRM-Grundlagen."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    base64,
    binascii,
    datetime,
    hashlib,
    ipaddress,
    json,
    os,
    re,
    secrets,
    shutil,
    ssl,
    subprocess,
    tempfile,
    timezone,
)

from .remote_transport import (
    get_ssh_settings,
    _host_inventory_entry,
    _effective_host_var,
    _connection_label,
    _clear_host_transport_vars,
    _apply_remote_management_disabled_transport,
    _apply_ssh_transport,
    _apply_psrp_transport,
    _psrp_https_inventory_vars,
    _apply_psrp_https_transport,
    _remember_winrm_https_state,
    _saved_winrm_https_transport,
    _apply_saved_winrm_https_transport,
    _normalize_winrm_dns_name,
    _winrm_https_settings,
)

from .remote_kerberos import (
    _kerberos_runtime_config_path,
    _normalize_kerberos_dns_server,
    _configured_kerberos_dns_servers,
    _direct_dns_query,
    _discover_kerberos_kdc_endpoints,
    _activate_existing_kerberos_runtime_config,
    _prepare_kerberos_runtime_config,
    _winrm_https_target_identity,
    _kerberos_principal_for_host,
    _vault_host_context,
    _vault_ansible_user_for_host,
)

from .remote_pki import (
    _certificate_thumbprint_from_der,
    _certificate_der_from_file,
    _certificate_thumbprint_from_file,
    _certificate_der_base64_from_file,
    _bootstrap_root_ca_thumbprint,
    _normalized_certificate_thumbprint,
    _utc_now_iso,
    _winrm_pki_paths,
    _winrm_local_command,
    _ensure_winrm_ca,
    _winrm_leaf_openssl_config,
    _validate_inventory_host_alias,
    _validate_new_host_alias,
    _safe_host_token,
    _host_artifact_tokens,
    _cleanup_host_artifact_tokens,
    _issue_winrm_server_certificate,
)

from .remote_cleanup import (
    _remove_host_bootstrap_artifacts,
    _remove_host_winrm_certificate_artifacts,
)

from .remote_session import (
    _temporary_psrp_vault_inventory,
    _retain_single_inventory_host,
    _temporary_single_host_inventory,
    _vault_psrp_password_for_host,
    _discard_kerberos_ticket_cache,
    _verify_kerberos_ticket_cache,
    _acquire_vault_kerberos_ticket,
    _open_client_ansible_session,
    _close_client_ansible_session,
)

from .remote_play_runner import (
    _run_winrm_temporary_play,
    _winrm_csr_play,
    _extract_json_marker,
    _bootstrap_certificate_identities,
    _bootstrap_ca_probe_play,
    _extract_bootstrap_ca_probe_result,
    _normalized_certificate_timestamp,
    _marker_nonnegative_int,
    _extract_winrm_https_install_result,
    _extract_winrm_reset_result,
    _extract_winrm_csr,
)

from .remote_winrm_install import (
    _winrm_install_https_play,
    _winrm_remove_http_play,
)

from .remote_winrm_reset import (
    _winrm_reset_play,
    _winrm_kerberos_https_ping_play,
)



def _absolute_without_symlink(path: Path) -> Path:
    """Absoluten Pfad bilden, ohne die für venv essenzielle Symlink-Identität zu verlieren."""
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _ansible_playbook_candidates() -> list[Path]:
    """Bevorzugte Ansible-Startpunkte ohne PATH-/sudo-Mehrdeutigkeit liefern."""
    raw_candidates: list[Path] = []

    # Bei einem sudo-Start bleibt die Benutzer-pipx-Installation der korrekte
    # Ansible-Kontext. /root/.local oder /usr/bin dürfen sie nicht verdrängen.
    sudo_user = str(os.environ.get("SUDO_USER", "") or "").strip()
    if sudo_user and sudo_user != "root" and re.fullmatch(r"[A-Za-z0-9_.-]+", sudo_user):
        try:
            import pwd

            sudo_home = Path(pwd.getpwnam(sudo_user).pw_dir)
            raw_candidates.append(sudo_home / ".local" / "bin" / "ansible-playbook")
        except (ImportError, KeyError, OSError):
            pass

    raw_candidates.append(Path.home() / ".local" / "bin" / "ansible-playbook")
    path_executable = shutil.which("ansible-playbook")
    if path_executable:
        raw_candidates.append(Path(path_executable))

    candidates: list[Path] = []
    seen: set[Path] = set()
    for candidate in raw_candidates:
        try:
            if not candidate.is_file():
                continue
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        candidates.append(resolved)
    return candidates


_ANSIBLE_RUNTIME_CACHE: tuple[Path, Path] | None = None


def _ansible_playbook_runtime() -> tuple[Path, Path]:
    """Exakten Ansible-Startpunkt und dessen wirklichen Python-Interpreter koppeln."""
    global _ANSIBLE_RUNTIME_CACHE
    if _ANSIBLE_RUNTIME_CACHE is not None:
        executable, interpreter = _ANSIBLE_RUNTIME_CACHE
        if executable.is_file() and interpreter.is_file():
            return _ANSIBLE_RUNTIME_CACHE

    candidates = _ansible_playbook_candidates()
    if not candidates:
        raise RuntimeError("ansible-playbook fehlt auf dem Controller.")

    for executable in candidates:
        # `ansible-playbook --version` wird vom tatsächlichen Ansible-Prozess
        # erzeugt und nennt dessen Python samt absolutem Pfad.
        try:
            version_result = subprocess.run(
                [str(executable), "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            version_result = None
        if version_result is not None and version_result.returncode == 0:
            version_output = (version_result.stdout or "") + "\n" + (version_result.stderr or "")
            for line in version_output.splitlines():
                match = re.search(
                    r"^\s*python\s+version\s*=.*\((/[^)]+)\)\s*$",
                    line,
                    re.IGNORECASE,
                )
                if not match:
                    continue
                reported = Path(match.group(1).strip()).expanduser()
                if reported.is_file():
                    # NIEMALS resolve(): venv/bin/python ist absichtlich ein
                    # Symlink auf das Basis-Python. Nur der logische Venv-Pfad
                    # aktiviert pyvenv.cfg und damit dessen site-packages.
                    _ANSIBLE_RUNTIME_CACHE = (
                        executable,
                        _absolute_without_symlink(reported),
                    )
                    return _ANSIBLE_RUNTIME_CACHE

        # Fallback nur auf den Shebang genau dieses Startpunkts. Es gibt keinen
        # Rückfall auf sys.executable, da dies erneut zwei Umgebungen vermischen würde.
        try:
            first_line = executable.open("r", encoding="utf-8", errors="replace").readline().strip()
        except OSError:
            first_line = ""
        if not first_line.startswith("#!"):
            continue
        shebang = first_line[2:].strip().split()
        if not shebang:
            continue
        interpreter = shebang[0]
        if Path(interpreter).name == "env" and len(shebang) > 1:
            env_arguments = shebang[1:]
            if env_arguments and env_arguments[0] == "-S":
                env_arguments = env_arguments[1:]
            interpreter_name = next(
                (value for value in env_arguments if value and not value.startswith("-")),
                "",
            )
            interpreter = shutil.which(interpreter_name) or ""
        if interpreter and Path(interpreter).is_file():
            _ANSIBLE_RUNTIME_CACHE = (
                executable,
                _absolute_without_symlink(Path(interpreter)),
            )
            return _ANSIBLE_RUNTIME_CACHE

    raise RuntimeError(
        "Der Python-Interpreter des verfügbaren ansible-playbook konnte nicht eindeutig ermittelt werden."
    )


def _ansible_playbook_executable() -> Path:
    return _ansible_playbook_runtime()[0]


def _ansible_controller_python() -> Path:
    return _ansible_playbook_runtime()[1]


def _ansible_inventory_executable() -> Path:
    """ansible-inventory aus exakt derselben Installation wie ansible-playbook."""
    candidate = _ansible_playbook_executable().with_name("ansible-inventory")
    if not candidate.is_file():
        raise RuntimeError(
            "ansible-inventory fehlt in der erkannten Ansible-Umgebung."
        )
    return candidate


def _ansible_runtime_environment(ansible_python: Path) -> dict[str, str]:
    """Saubere Prozessumgebung für den gebundenen venv-/pipx-Interpreter."""
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PATH"] = str(ansible_python.parent) + os.pathsep + environment.get("PATH", "")
    venv_root = ansible_python.parent.parent
    if (venv_root / "pyvenv.cfg").is_file():
        environment["VIRTUAL_ENV"] = str(venv_root)
    return environment


def _python_imports_gssapi(python_executable: Path) -> bool:
    """Die vollständige PSRP-/pyspnego-Kerberos-Kette im Ansible-Venv prüfen."""
    probe = (
        "import gssapi, krb5, pypsrp\n"
        "from spnego import _gss\n"
        "assert _gss.HAS_GSSAPI, _gss.GSSAPI_IMP_ERR\n"
        "assert _gss.HAS_IOV, _gss.GSSAPI_IOV_IMP_ERR\n"
    )
    try:
        result = subprocess.run(
            [str(python_executable), "-I", "-c", probe],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
            env=_ansible_runtime_environment(python_executable),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _controller_root_prefix() -> list[str]:
    """Root-Prefix für die einmalige Controller-Paketinstallation."""
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if not sudo:
        raise RuntimeError(
            "GSSAPI fehlt und sudo ist für die automatische Controller-Einrichtung nicht verfügbar."
        )
    return [sudo]


def _ansible_pipx_venv_root(ansible_python: Path) -> Path | None:
    """pipx-Venv-Wurzel ausschließlich aus dem unaufgelösten Interpreterpfad ableiten."""
    lexical_python = _absolute_without_symlink(ansible_python)
    for parent in lexical_python.parents:
        if parent.parent.name != "venvs" or parent.parent.parent.name != "pipx":
            continue
        if re.fullmatch(r"[A-Za-z0-9_.-]+", parent.name) and (parent / "pyvenv.cfg").is_file():
            return parent
    return None


def _ansible_pipx_package(ansible_python: Path) -> str:
    """pipx-Paketname aus .../pipx/venvs/<paket>/bin/python ableiten."""
    venv_root = _ansible_pipx_venv_root(ansible_python)
    return venv_root.name if venv_root is not None else ""


def _pipx_command_for_ansible(ansible_python: Path) -> list[str]:
    """pipx im Besitz genau der erkannten Ansible-Umgebung ausführen."""
    pipx_path: Path | None = None
    lexical_python = _absolute_without_symlink(ansible_python)
    venv_root = _ansible_pipx_venv_root(lexical_python)
    for parent in lexical_python.parents:
        if parent.name != ".local":
            continue
        associated = parent / "bin" / "pipx"
        if associated.is_file():
            pipx_path = _absolute_without_symlink(associated)
            break
    if pipx_path is None:
        discovered = shutil.which("pipx")
        if discovered:
            pipx_path = _absolute_without_symlink(Path(discovered))
    if pipx_path is None:
        raise RuntimeError("Die erkannte Ansible-pipx-Umgebung kann nicht repariert werden, weil pipx fehlt.")

    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid):
        return [str(pipx_path)]
    try:
        # Nicht den Python-Symlink statten: dessen Ziel /usr/bin gehört root.
        runtime_owner = (venv_root or lexical_python.parent.parent).stat().st_uid
    except OSError:
        runtime_owner = geteuid()
    if runtime_owner == geteuid():
        return [str(pipx_path)]

    # Wurde Mavi vollständig mit sudo gestartet, muss pipx trotzdem als
    # Besitzer der Benutzerumgebung laufen. Sonst sucht pipx irrtümlich unter /root.
    if geteuid() == 0:
        try:
            import pwd

            owner_name = pwd.getpwuid(runtime_owner).pw_name
        except (ImportError, KeyError, OSError) as exc:
            raise RuntimeError("Der Besitzer der Ansible-pipx-Umgebung konnte nicht ermittelt werden.") from exc
        sudo = shutil.which("sudo")
        if not sudo:
            raise RuntimeError("sudo fehlt für die Reparatur der Benutzer-pipx-Umgebung.")
        return [sudo, "-u", owner_name, "-H", str(pipx_path)]

    raise RuntimeError("Die Ansible-pipx-Umgebung gehört einem anderen Benutzer und ist nicht sicher änderbar.")


def _ensure_psrp_kerberos_controller_dependencies(*, force_pipx_inject: bool = False) -> None:
    """Offizielle PSRP-Kerberos-Abhängigkeiten vor jeder Windows-Änderung bereitstellen."""
    from .openssh import _root_command

    ansible_executable, ansible_python = _ansible_playbook_runtime()
    pipx_package = _ansible_pipx_package(ansible_python)
    gssapi_available = _python_imports_gssapi(ansible_python)
    if gssapi_available and not force_pipx_inject:
        return

    print("\nMavi KERBEROS-CONTROLLER-SETUP")
    print("================================")
    if gssapi_available:
        print("  → Der Ansible-Worker meldete GSSAPI trotz Vorprüfung als fehlend; Mavi repariert die pipx-Umgebung einmalig.")
    else:
        print("  → GSSAPI fehlt im Python-Kontext von Ansible und wird einmalig eingerichtet.")
    print(f"  → Ansible-Start:  {ansible_executable}")
    print(f"  → Ansible-Python: {ansible_python}")
    if pipx_package:
        print(f"  → pipx-Paket:      {pipx_package}")

    if not gssapi_available:
        apt_get = shutil.which("apt-get")
        if apt_get:
            root_prefix = _controller_root_prefix()
            noninteractive = ["env", "DEBIAN_FRONTEND=noninteractive"]
            _root_command(
                [*root_prefix, *noninteractive, apt_get, "update"],
                description="Kerberos-Paketlisten aktualisieren",
            )
            _root_command(
                [
                    *root_prefix,
                    *noninteractive,
                    apt_get,
                    "install",
                    "-y",
                    "--no-install-recommends",
                    "krb5-user",
                    "libkrb5-dev",
                    "python3-dev",
                    "gcc",
                    "python3-gssapi",
                ],
                description="Kerberos, GSSAPI und Python-Buildabhängigkeiten installieren",
            )
        else:
            raise RuntimeError(
                "GSSAPI fehlt. Die automatische Einrichtung unterstützt hier Debian/Ubuntu mit apt-get."
            )

    if _python_imports_gssapi(ansible_python) and not force_pipx_inject:
        print("  ✓ GSSAPI, Kerberos und WinRM-IOV sind im Ansible-Python verfügbar.")
        return

    # pipx-Umgebungen werden ausschließlich über die dafür vorgesehene
    # Injection erweitert. Ein direktes `venv/bin/python -m pip` kann zwar
    # funktionieren, umgeht aber pipx' Paketverwaltung und war bei der realen
    # Mavi-Ansible-Installation mit Python 3.14 nicht zuverlässig.
    ansible_python_text = str(_absolute_without_symlink(ansible_python))
    system_python_candidates = {
        _absolute_without_symlink(candidate)
        for directory in (Path("/usr/bin"), Path("/bin"))
        for candidate in directory.glob("python*")
        if candidate.is_file()
        and re.fullmatch(r"python\d+(?:\.\d+)*", candidate.name)
    }
    if pipx_package:
        pipx_command = _pipx_command_for_ansible(ansible_python)
        _root_command(
            [
                *pipx_command,
                "inject",
                "--force",
                pipx_package,
                "pypsrp[kerberos]>=0.4.0,<1.0.0",
            ],
            description=f"PSRP-Kerberos-Extra in pipx-Paket {pipx_package} injizieren",
        )
    elif _absolute_without_symlink(ansible_python) not in system_python_candidates:
        _root_command(
            [
                ansible_python_text,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "pypsrp[kerberos]>=0.4.0,<1.0.0",
            ],
            description="PSRP-Kerberos-Extra in die isolierte Ansible-Umgebung installieren",
        )

    # `inject` ist der vorgesehene pipx-Weg. Sollte dessen Extra-Auflösung die
    # vollständige pyspnego-Kette dennoch nicht bereitstellen, installiert Mavi
    # die vier konkreten Kerberos-Komponenten direkt in exakt dieselbe Venv.
    if pipx_package and not _python_imports_gssapi(ansible_python):
        pipx_command = _pipx_command_for_ansible(ansible_python)
        _root_command(
            [
                *pipx_command,
                "runpip",
                pipx_package,
                "install",
                "--upgrade",
                "--force-reinstall",
                "--no-cache-dir",
                "gssapi>=1.6.0",
                "krb5>=0.3.0",
                "pyspnego[kerberos]>=0.7.0,<1.0.0",
                "pypsrp[kerberos]>=0.4.0,<1.0.0",
            ],
            description=f"Kerberos-Komponenten im pipx-Paket {pipx_package} vollständig reparieren",
        )

    if not _python_imports_gssapi(ansible_python):
        raise RuntimeError(
            "Die vollständige GSSAPI-/Kerberos-/IOV-Kette ist nach der Einrichtung "
            f"im Ansible-Python {ansible_python} weiterhin nicht verfügbar."
        )
    print("  ✓ GSSAPI, Kerberos und WinRM-IOV sind im Ansible-Python verfügbar.")


def _is_missing_gssapi_failure(exc: BaseException) -> bool:
    """Eindeutige Ausfälle der lokalen GSSAPI-/Kerberos-Kette erkennen."""
    folded = str(exc).casefold()
    return (
        "gssapiproxy requires the python gssapi library" in folded
        or (
            "no module named" in folded
            and any(module in folded for module in ("gssapi", "krb5"))
        )
        or "gssapi iov extension not available" in folded
    )

from .remote_kerberos import (
    _kerberos_cache_connection_overrides,
)

from .remote_transport import (
    _ssh_environment_marker,
)

__all__ = (
    "get_ssh_settings",
    "_host_inventory_entry",
    "_effective_host_var",
    "_connection_label",
    "_clear_host_transport_vars",
    "_apply_remote_management_disabled_transport",
    "_apply_ssh_transport",
    "_apply_psrp_transport",
    "_psrp_https_inventory_vars",
    "_apply_psrp_https_transport",
    "_remember_winrm_https_state",
    "_saved_winrm_https_transport",
    "_apply_saved_winrm_https_transport",
    "_normalize_winrm_dns_name",
    "_winrm_https_settings",
    "_kerberos_runtime_config_path",
    "_normalize_kerberos_dns_server",
    "_configured_kerberos_dns_servers",
    "_direct_dns_query",
    "_discover_kerberos_kdc_endpoints",
    "_activate_existing_kerberos_runtime_config",
    "_prepare_kerberos_runtime_config",
    "_winrm_https_target_identity",
    "_kerberos_principal_for_host",
    "_vault_host_context",
    "_vault_ansible_user_for_host",
    "_winrm_pki_paths",
    "_validate_inventory_host_alias",
    "_validate_new_host_alias",
    "_safe_host_token",
    "_winrm_local_command",
    "_ensure_winrm_ca",
    "_winrm_leaf_openssl_config",
    "_issue_winrm_server_certificate",
    "_remove_host_winrm_certificate_artifacts",
    "_absolute_without_symlink",
    "_ansible_playbook_candidates",
    "_ANSIBLE_RUNTIME_CACHE",
    "_ansible_playbook_runtime",
    "_ansible_playbook_executable",
    "_ansible_controller_python",
    "_ansible_inventory_executable",
    "_ansible_runtime_environment",
    "_python_imports_gssapi",
    "_controller_root_prefix",
    "_ansible_pipx_venv_root",
    "_ansible_pipx_package",
    "_pipx_command_for_ansible",
    "_ensure_psrp_kerberos_controller_dependencies",
    "_is_missing_gssapi_failure",
    "_temporary_psrp_vault_inventory",
    "_retain_single_inventory_host",
    "_temporary_single_host_inventory",
    "_vault_psrp_password_for_host",
    "_discard_kerberos_ticket_cache",
    "_verify_kerberos_ticket_cache",
    "_acquire_vault_kerberos_ticket",
    "_open_client_ansible_session",
    "_close_client_ansible_session",
    "_run_winrm_temporary_play",
    "_winrm_csr_play",
    "_extract_winrm_csr",
    "_winrm_install_https_play",
    "_winrm_remove_http_play",
    "_winrm_reset_play",
    "_winrm_kerberos_https_ping_play",
    "_ssh_environment_marker",
    "_kerberos_cache_connection_overrides",
)
