# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Generische Mavi-Einrichtung und Doctor-Prüfungen."""

from __future__ import annotations


from ._dependencies import (
    Any,
    Path,
    argparse,
    base64,
    binascii,
    getpass,
    ipaddress,
    json,
    os,
    re,
    shutil,
    socket,
    subprocess,
    tempfile,
    urllib,
    yaml,
)


def _mavi_drive_label(value: Any) -> str:
    """Ein Windows-Laufwerk einheitlich darstellen, ohne eines zu erfinden."""
    raw = str(value or "").strip().replace("/", "\\")
    if re.fullmatch(r"[A-Za-z]:\\?", raw):
        return raw[:2].upper() + "\\"
    return raw


def _mavi_source_root(config: dict[str, Any]) -> Path | None:
    source = config.get("software_source", {}) or {}
    raw_root = str(source.get("local_root", "") or "").strip()
    return Path(raw_root).expanduser() if raw_root else None


def _mavi_source_label(config: dict[str, Any]) -> str:
    source = config.get("software_source", {}) or {}
    label = str(source.get("label", "") or "").strip()
    if label:
        return label
    drive = _mavi_drive_label(source.get("drive"))
    if drive:
        return drive
    unc_root = str(source.get("unc_root", "") or "").strip()
    if unc_root:
        return unc_root
    root = _mavi_source_root(config)
    return str(root) if root else "(noch nicht eingerichtet)"


def _mavi_normalize_controller_ipv4(value: Any) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError as exc:
        raise ValueError("Controller-Adresse ist keine gültige IPv4-Adresse.") from exc
    if (
        address.version != 4
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
    ):
        raise ValueError(
            "Controller-Adresse muss eine routbare IPv4 sein; Loopback, "
            "Link-Local, Multicast und Wildcards sind unzulässig."
        )
    return str(address)


def _mavi_normalize_domain(value: Any) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not domain:
        return ""
    if len(domain) > 253 or "." not in domain:
        raise ValueError("AD-Domäne muss ein vollständiger DNS-Name sein.")
    labels = domain.split(".")
    if any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("AD-Domäne enthält einen ungültigen DNS-Bestandteil.")
    return domain


def _mavi_normalize_ansible_user(value: Any) -> str:
    user = str(value or "").strip()
    if not user:
        return ""
    if (
        len(user) > 256
        or any(ord(char) < 32 or ord(char) == 127 for char in user)
        or "{{" in user
        or "{%" in user
        or not re.fullmatch(r"[A-Za-z0-9_.@-]+(?:\\[A-Za-z0-9_.@$-]+)?", user)
    ):
        raise ValueError(
            r"Ansible-Benutzer muss user@domain, DOMAIN\user oder ein lokaler Benutzer sein."
        )
    return user


def _mavi_normalize_allowed_cidrs(value: Any) -> list[str]:
    if value in (None, "", []):
        return []
    if isinstance(value, str):
        raw_values = [part for part in re.split(r"[,;\s]+", value) if part]
    elif isinstance(value, list):
        raw_values = [str(part or "").strip() for part in value if str(part or "").strip()]
    else:
        raise ValueError("Erlaubte Bootstrap-Netze müssen eine Liste oder CIDR-Zeichenfolge sein.")
    networks: list[str] = []
    for raw in raw_values:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"Ungültiges Bootstrap-Netz {raw!r}: {exc}") from exc
        if (
            network.prefixlen == 0
            or network.is_unspecified
            or network.is_loopback
            or network.is_link_local
            or network.is_multicast
        ):
            raise ValueError(f"Unzulässiges Bootstrap-Netz: {network}")
        normalized = str(network)
        if normalized not in networks:
            networks.append(normalized)
    return networks


def _mavi_profile_validation_issues(config: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    profile = config.get("profile", {}) or {}
    profile_name = str(profile.get("name", "") or "").strip() if isinstance(profile, dict) else ""
    if not profile_name or len(profile_name) > 128 or any(ord(char) < 32 for char in profile_name):
        issues.append("gültiger Profilname fehlt")

    try:
        _mavi_normalize_controller_ipv4(config.get("ansible_server_ip", ""))
    except ValueError:
        issues.append("gültige Controller-IPv4 fehlt")

    source = config.get("software_source", {}) or {}
    source_root = str(source.get("local_root", "") or "").strip() if isinstance(source, dict) else ""
    if not source_root or not Path(source_root).expanduser().is_absolute():
        issues.append("absoluter Controller-Pfad zur Softwarequelle fehlt")

    winrm = config.get("winrm_https", {}) or {}
    domain = winrm.get("domain_suffix", "") if isinstance(winrm, dict) else ""
    try:
        _mavi_normalize_domain(domain)
    except ValueError:
        issues.append("AD-DNS-Domäne ist ungültig")
    return issues


def _mavi_profile_ready(config: dict[str, Any]) -> bool:
    """Bereitschaft aus Fakten ableiten; das gespeicherte Boolean ist kein Beweis."""
    return not _mavi_profile_validation_issues(config)


def _mavi_controller_ipv4_candidates() -> list[str]:
    """Nicht-invasive Vorschläge für den Setup-Assistenten ermitteln."""
    candidates: set[str] = set()
    try:
        entries = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        entries = []

    for entry in entries:
        address = str(entry[4][0] or "").strip()
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not parsed.is_loopback and not parsed.is_unspecified:
            candidates.add(str(parsed))
    return sorted(candidates, key=lambda value: tuple(int(part) for part in value.split(".")))


def _mavi_write_config(project: Path, config: dict[str, Any]) -> None:

    from .environment import (
        atomic_write_yaml,
        project_paths,
    )
    atomic_write_yaml(project_paths(project)["config"], config)


def _mavi_prompt_normalized(
    label: str,
    default: str,
    normalizer: Any,
    *,
    allow_empty: bool = True,
) -> str:
    """Einfacher Dialog für nicht geheime Werte mit verständlicher Korrektur."""
    from .catalogs import prompt

    while True:
        value = prompt(label, default).strip()
        if not value and allow_empty:
            return ""
        try:
            return str(normalizer(value))
        except ValueError as exc:
            print(f"! {exc}")


def _mavi_prompt_source_root(default: str) -> str:
    """Nur einen absoluten Controller-Pfad akzeptieren."""
    from .catalogs import prompt

    while True:
        label = "Software-Ordner auf dem Controller"
        if default:
            label += " (Enter = Vorschlag übernehmen)"
        else:
            label += " (Enter = später)"
        value = prompt(label, default).strip()
        if not value:
            return ""
        candidate = Path(value).expanduser()
        if candidate.is_absolute():
            return str(candidate)
        print("! Bitte einen absoluten Pfad eingeben, z. B. /srv/mavi-software.")


def _mavi_root_command_prefix() -> list[str]:
    """Root-Aufrufe aus der TUI heraus ermöglichen."""

    from .environment import (
        die,
    )
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if not sudo:
        die("Für das automatische Einbinden der SMB-Freigabe fehlt sudo.")
    return [sudo]


def _mavi_has_cifs_support() -> bool:
    return bool(
        shutil.which("mount.cifs")
        or Path("/usr/sbin/mount.cifs").is_file()
        or Path("/sbin/mount.cifs").is_file()
    )


def _mavi_install_cifs_support() -> bool:
    """Fehlende CIFS-Unterstützung direkt aus der TUI installieren."""
    from .catalogs import yes_no

    if _mavi_has_cifs_support():
        return True

    print()
    print("Die SMB-Unterstützung (cifs-utils) fehlt auf dem Controller.")
    if not yes_no("Jetzt automatisch installieren?", True):
        return False

    installers = (
        ("apt-get", ["install", "-y", "cifs-utils"]),
        ("dnf", ["install", "-y", "cifs-utils"]),
        ("yum", ["install", "-y", "cifs-utils"]),
        ("zypper", ["--non-interactive", "install", "cifs-utils"]),
        ("pacman", ["-S", "--noconfirm", "cifs-utils"]),
    )
    for executable_name, arguments in installers:
        executable = shutil.which(executable_name)
        if not executable:
            continue
        command = _mavi_root_command_prefix() + [executable, *arguments]
        result = subprocess.run(command, check=False)
        if result.returncode == 0 and _mavi_has_cifs_support():
            return True
        print("! cifs-utils konnte nicht automatisch installiert werden.")
        return False

    print("! Kein unterstützter Paketmanager für cifs-utils gefunden.")
    return False


def _mavi_unc_mount_parts(unc_root: str) -> tuple[str, str]:
    """UNC-Wurzel in CIFS-Share und optionalen Unterpfad zerlegen."""
    normalized = str(unc_root or "").strip().replace("\\", "/")
    if not normalized.startswith("//"):
        raise ValueError("UNC muss mit \\\\ beginnen, z. B. \\\\server\\freigabe.")
    parts = [part for part in normalized[2:].split("/") if part]
    if len(parts) < 2:
        raise ValueError("UNC muss Server und Freigabe enthalten.")
    share = f"//{parts[0]}/{parts[1]}"
    prefix_path = "/".join(parts[2:])
    return share, prefix_path


def _mavi_mount_smb_source(
    unc_root: str,
    mount_path: Path,
    mount_user: str,
    mount_host: str = "",
) -> tuple[bool, str]:
    """Eine SMB-Quelle interaktiv unter Mavis internem Pfad einbinden."""
    from .catalogs import prompt

    if os.name == "nt":
        print("! Automatisches CIFS-Mounting ist nur auf dem Linux-Controller verfügbar.")
        return False, mount_host

    try:
        share, prefix_path = _mavi_unc_mount_parts(unc_root)
    except ValueError as exc:
        print(f"! {exc}")
        return False, mount_host

    share_server, share_name = share[2:].split("/", 1)
    endpoint = str(mount_host or "").strip() or share_server
    while True:
        try:
            socket.getaddrinfo(endpoint, 445, type=socket.SOCK_STREAM)
            break
        except socket.gaierror:
            print()
            print(f"! Der SMB-Server '{endpoint}' ist auf dem Controller nicht auflösbar.")
            endpoint = prompt(
                f"IP-Adresse oder vollständiger DNS-Name für {share_server}"
            ).strip()
            if not endpoint:
                return False, ""
    mount_share = f"//{endpoint}/{share_name}"

    mount_path = mount_path.expanduser()
    mount_path.mkdir(parents=True, exist_ok=True)
    if os.path.ismount(mount_path):
        return True, endpoint
    if not _mavi_install_cifs_support():
        return False, endpoint

    options = ["vers=3.0"]
    if prefix_path:
        options.append(f"prefixpath={prefix_path}")

    credentials_path: Path | None = None
    try:
        user = str(mount_user or "").strip()
        if user:
            password = getpass.getpass(f"SMB-Kennwort für {user}: ")
            domain = ""
            username = user
            if "\\" in user:
                domain, username = user.split("\\", 1)

            fd, raw_credentials_path = tempfile.mkstemp(prefix="mavi-smb-")
            credentials_path = Path(raw_credentials_path)
            try:
                os.fchmod(fd, 0o600)
            except Exception:
                os.close(fd)
                raise
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(f"username={username}\n")
                handle.write(f"password={password}\n")
                if domain:
                    handle.write(f"domain={domain}\n")
            options.append(f"credentials={credentials_path}")
        else:
            options.append("guest")

        mount_executable = shutil.which("mount") or "/usr/bin/mount"
        command = _mavi_root_command_prefix() + [
            mount_executable,
            "-t",
            "cifs",
            mount_share,
            str(mount_path),
            "-o",
            ",".join(options),
        ]
        print()
        print(f"Mavi bindet {unc_root} jetzt automatisch ein …")
        result = subprocess.run(command, check=False)
    except (OSError, RuntimeError) as exc:
        print(f"! SMB-Freigabe konnte nicht eingebunden werden: {exc}")
        return False, endpoint
    finally:
        if credentials_path is not None:
            try:
                credentials_path.unlink()
            except OSError:
                pass

    if result.returncode != 0 or not os.path.ismount(mount_path):
        print("! SMB-Freigabe konnte nicht eingebunden werden.")
        return False, endpoint

    print(f"✓ SMB-Freigabe verbunden: {unc_root}")
    return True, endpoint


def cmd_setup(args: argparse.Namespace) -> None:
    """
    Den nicht-geheimen Teil einer neuen Umgebung schrittweise erfassen.
    Der Schnellstart fragt nur die Fakten, die wirklich sofort benötigt werden.
    """

    from .environment import (
        atomic_write_yaml,
        ensure_initialized,
        get_config,
        project_paths,
    )
    from .catalogs import (
        prompt,
        prompt_choice,
        yes_no,
    )
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )

    project = args.project
    ensure_initialized(project, quiet=True)
    config = get_config(project)
    profile = dict(config.get("profile", {}) or {})
    source = dict(config.get("software_source", {}) or {})
    old_source = dict(source)
    identity = dict(config.get("identity", {}) or {})
    winrm = dict(config.get("winrm_https", {}) or {})
    advanced = bool(getattr(args, "advanced", False))

    print()
    print("MAVI PROVISIONER — SCHNELLSTART")
    print("================================")
    print(
        "In wenigen Schritten wird nur das Grundprofil angelegt. "
        "Passwörter, SSH, WinRM, CA und Netzlaufwerke kommen erst dazu, "
        "wenn du die jeweilige Funktion wirklich nutzt."
    )
    print(
        "Es werden hier keine Passwörter, Tokens oder privaten Schlüssel abgefragt."
    )
    if advanced:
        print("Erweiterter Modus: Laufwerk, SMB und Bootstrap-Details werden zusätzlich abgefragt.")
    print()

    existing_name = str(profile.get("name", "") or "").strip()
    while True:
        profile_name = prompt("Name dieser Umgebung", existing_name or "Meine Umgebung").strip()
        if profile_name and len(profile_name) <= 128 and not any(ord(char) < 32 for char in profile_name):
            break
        print("! Bitte einen kurzen Namen ohne Steuerzeichen eingeben.")

    current_ip = str(config.get("ansible_server_ip", "") or "").strip()
    suggestions = _mavi_controller_ipv4_candidates()
    suggested_ip = current_ip or (suggestions[0] if len(suggestions) == 1 else "")
    if suggestions and not current_ip:
        print("Gefundene Controller-IPv4-Adressen: " + ", ".join(suggestions))
    controller_ip = _mavi_prompt_normalized(
        "IPv4 des Ansible-Controllers (Enter = später)",
        suggested_ip,
        _mavi_normalize_controller_ipv4,
    )

    source["kind"] = str(source.get("kind", "local") or "local").lower()
    if source["kind"] not in {"local", "smb"}:
        source["kind"] = "local"
    source["label"] = str(source.get("label", "") or "").strip() or "Softwarequelle"
    source_root = _mavi_prompt_source_root(
        str(source.get("local_root", "") or "").strip()
        or str(project / "software-source")
    )
    source["local_root"] = source_root
    if source_root:
        try:
            Path(source_root).expanduser().mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"! Software-Ordner konnte nicht automatisch angelegt werden: {exc}")

    ansible_user = _mavi_prompt_normalized(
        r"Windows-/Domänen-Benutzer (z. B. DOMAIN\Provisioning; Enter = später)",
        str(identity.get("ansible_user", "") or "").strip(),
        _mavi_normalize_ansible_user,
    )
    identity["ansible_user"] = ansible_user

    current_domain = str(winrm.get("domain_suffix", "") or "").strip()
    if advanced or yes_no("AD-DNS-Domäne jetzt eintragen?", bool(current_domain)):
        winrm["domain_suffix"] = _mavi_prompt_normalized(
            "AD-DNS-Domäne (Enter = später)",
            current_domain,
            _mavi_normalize_domain,
        )

    if advanced:
        source_kind = prompt_choice(
            "Wie liegt die Softwarequelle auf dem Controller vor?",
            [
                ("1", "Lokaler oder gemounteter Ordner"),
                ("2", "SMB/UNC-Quelle, die auf dem Controller gemountet ist"),
            ],
            "2" if source["kind"] == "smb" else "1",
        )
        source["kind"] = "smb" if source_kind == "2" else "local"
        if yes_no("Windows-Laufwerksbuchstabe für diese Quelle hinterlegen?", bool(_mavi_drive_label(source.get("drive")))):
            while True:
                drive = _mavi_drive_label(prompt("Laufwerk (z. B. S:)", _mavi_drive_label(source.get("drive")) or "S:\\"))
                if re.fullmatch(r"[A-Z]:\\", drive):
                    source["drive"] = drive
                    break
                print("! Bitte nur einen Laufwerksbuchstaben wie S: eingeben.")
        else:
            source["drive"] = ""
        if source["kind"] == "smb":
            source["unc_root"] = prompt(
                "UNC-Wurzel (z. B. \\\\server\\freigabe)",
                str(source.get("unc_root", "") or "").strip(),
            ).strip().rstrip("\\/")
        else:
            source["unc_root"] = ""
        bootstrap_default = str(config.get("bootstrap_base_url", "") or "").strip()
        if not bootstrap_default and controller_ip:
            bootstrap_default = f"https://{controller_ip}/mavi-bootstrap/"
        config["bootstrap_base_url"] = prompt(
            "HTTPS-Basis-URL für den OpenSSH-Bootstrap (Enter = später)",
            bootstrap_default,
        ).strip()
        config["bootstrap_local_dir"] = prompt(
            "Lokaler Webroot für Bootstrap-Dateien (Enter = später)",
            str(config.get("bootstrap_local_dir", "") or "").strip() or "/var/www/mavi-bootstrap",
        ).strip()
    else:
        # Der bewährte SSH-Standard wird automatisch vorbereitet und erst bei
        # `ssh server-setup` tatsächlich verwendet.
        if controller_ip and not str(config.get("bootstrap_base_url", "") or "").strip():
            config["bootstrap_base_url"] = f"https://{controller_ip}/mavi-bootstrap/"
        if controller_ip and not str(config.get("bootstrap_local_dir", "") or "").strip():
            config["bootstrap_local_dir"] = "/var/www/mavi-bootstrap"

    config["profile"] = profile
    config["profile"]["schema_version"] = 2
    config["profile"]["name"] = profile_name
    config["ansible_server_ip"] = controller_ip
    config["software_source"] = source
    config["identity"] = identity
    config["winrm_https"] = winrm
    # Veraltetes Feld nicht länger abfragen. Es dient nicht als Zugangsdatenquelle.
    config["local_admin_user"] = ""

    mappings = dict(config.get("path_mappings", {}) or {})
    for old_key in (
        _mavi_drive_label(old_source.get("drive")),
        _mavi_drive_label(old_source.get("drive"))[:2],
        str(old_source.get("unc_root", "") or "").strip().rstrip("\\/"),
    ):
        if old_key:
            mappings.pop(old_key, None)
    drive = _mavi_drive_label(source.get("drive"))
    if drive and source_root:
        mappings[drive] = source_root
        mappings[drive[:2]] = source_root
    unc_root = str(source.get("unc_root", "") or "").strip().rstrip("\\/")
    if unc_root and source_root:
        mappings[unc_root] = source_root
    config["path_mappings"] = mappings

    # Der Erststart braucht nur Name, Controller und Softwarepfad. Credentials,
    # AD/WinRM und SSH sind spätere, eigene Assistenten.
    config["profile"]["setup_completed"] = not _mavi_profile_validation_issues(config)
    _mavi_write_config(project, config)

    if ansible_user:
        inventory = load_inventory(project)
        windows = ensure_windows_tree(inventory)
        windows.setdefault("vars", {})["ansible_user"] = ansible_user
        atomic_write_yaml(project_paths(project)["inventory"], inventory)

    print()
    if config["profile"]["setup_completed"]:
        print("✓ Grundprofil gespeichert.")
    else:
        print("! Grundprofil gespeichert; Controller-IP oder Softwareordner können später ergänzt werden.")
    print(f"  Datei: {project_paths(project)['config']}")
    if not ansible_user:
        print("  Nächster Schritt: Zugangsdaten / Vault → Windows-Benutzer und Kennwort einmal einrichten.")
    else:
        print("  Nächster Schritt: Zugangsdaten / Vault → Kennwort verschlüsselt speichern.")
    print("  Danach: PCs & Verbindung → ersten PC hinzufügen.")


def _mavi_doctor_finding(
    status: str,
    check_id: str,
    title: str,
    detail: str,
    next_step: str = "",
) -> dict[str, str]:
    from .reports import redact_sensitive_text

    def safe_text(value: Any, limit: int) -> str:
        text_value = redact_sensitive_text(value)
        text_value = text_value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        text_value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "?", text_value)
        return text_value[:limit]

    return {
        "status": status,
        "id": check_id,
        "title": title,
        "detail": safe_text(detail, 4000),
        "next_step": safe_text(next_step, 1000),
    }


def _mavi_doctor_print(findings: list[dict[str, str]]) -> None:
    symbols = {
        "pass": "✓",
        "warn": "!",
        "fail": "✗",
        "info": "·",
    }
    labels = {
        "pass": "OK",
        "warn": "HINWEIS",
        "fail": "OFFEN",
        "info": "INFO",
    }
    print()
    print("MAVI DOCTOR — BERICHT")
    print("=====================")
    for finding in findings:
        status = finding["status"]
        symbol = symbols.get(status, "·")
        label = labels.get(status, status.upper())
        print(f"{symbol} [{label}] {finding['title']}")
        print(f"  {finding['detail']}")
        if finding["next_step"]:
            print(f"  Nächster Schritt: {finding['next_step']}")

    failed = sum(1 for finding in findings if finding["status"] == "fail")
    warned = sum(1 for finding in findings if finding["status"] == "warn")
    passed = sum(1 for finding in findings if finding["status"] == "pass")
    print()
    print(f"Ergebnis: {passed} OK, {warned} Hinweise, {failed} offene Punkte.")
    print("Doctor hat keine Projekt- oder Systemkonfiguration verändert.")
    if failed:
        print("Behebe die offenen Punkte über die TUI und starte Doctor erneut.")


def _mavi_doctor_summary(findings: list[dict[str, str]]) -> dict[str, int]:
    return {
        "passed": sum(1 for item in findings if item.get("status") == "pass"),
        "warnings": sum(1 for item in findings if item.get("status") == "warn"),
        "failed": sum(1 for item in findings if item.get("status") == "fail"),
        "info": sum(1 for item in findings if item.get("status") == "info"),
    }


def _mavi_valid_dns_name(value: str) -> bool:
    candidate = str(value or "").strip().rstrip(".")
    if not candidate or len(candidate) > 253 or "." not in candidate:
        return False
    labels = candidate.split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def _mavi_valid_https_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(str(value or "").strip())
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    return bool(
        parsed.scheme == "https"
        and hostname
        and not parsed.username
        and not parsed.password
        and (port is None or 1 <= port <= 65535)
    )


def _mavi_doctor_profile_checks(
    project: Path,
    feature: str,
) -> tuple[list[dict[str, str]], dict[str, Any]]:

    from .environment import (
        get_config,
        project_paths,
    )
    from .remote import _ansible_playbook_candidates
    from .reports import redact_sensitive_text
    from .settings import CONFIG_TEMPLATE

    findings: list[dict[str, str]] = []
    config_path = project_paths(project)["config"]
    if not config_path.is_file():
        config = dict(CONFIG_TEMPLATE)
        findings.append(_mavi_doctor_finding(
            "fail",
            "profile.file",
            "Umgebungskonfiguration",
            f"Konfigurationsdatei fehlt: {config_path}",
            "TUI → Neue Umgebung einrichten.",
        ))
    else:
        try:
            config = get_config(project)
        except (OSError, TypeError, AttributeError, ValueError, yaml.YAMLError) as exc:
            config = dict(CONFIG_TEMPLATE)
            findings.append(_mavi_doctor_finding(
                "fail",
                "profile.file",
                "Umgebungskonfiguration",
                f"Konfiguration ist nicht lesbar oder strukturell ungültig: {redact_sensitive_text(exc)}",
                "YAML korrigieren oder das Profil über das Setup neu anlegen.",
            ))
        else:
            findings.append(_mavi_doctor_finding(
                "pass",
                "profile.file",
                "Umgebungskonfiguration",
                f"Konfiguration read-only geladen: {config_path}",
            ))

    profile = config.get("profile", {}) or {}
    profile_name = str(profile.get("name", "") or "").strip()

    if profile_name:
        findings.append(_mavi_doctor_finding(
            "pass",
            "profile.name",
            "Umgebungsprofil",
            f"Profil „{profile_name}“ geladen.",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "fail",
            "profile.name",
            "Umgebungsprofil",
            "Der Profilname fehlt; damit ist diese Umgebung nicht nachvollziehbar.",
            "TUI → Neue Umgebung einrichten.",
        ))

    if _mavi_profile_ready(config):
        findings.append(_mavi_doctor_finding(
            "pass",
            "profile.complete",
            "Grundkonfiguration",
            "Setup-Assistent hat die Mindestdaten markiert.",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "fail",
            "profile.complete",
            "Grundkonfiguration",
            "Controller-IP, Profilname oder Softwarequelle fehlen noch.",
            "TUI → Neue Umgebung einrichten.",
        ))

    controller_ip = str(config.get("ansible_server_ip", "") or "").strip()
    try:
        parsed_controller_ip = ipaddress.ip_address(controller_ip)
        valid_controller_ip = (
            parsed_controller_ip.version == 4
            and not parsed_controller_ip.is_unspecified
            and not parsed_controller_ip.is_multicast
            and not parsed_controller_ip.is_loopback
        )
    except ValueError:
        valid_controller_ip = False
    if valid_controller_ip:
        findings.append(_mavi_doctor_finding(
            "pass",
            "controller.ip",
            "Ansible-Controller-IP",
            f"{controller_ip} ist eine gültige IPv4-Adresse.",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "fail",
            "controller.ip",
            "Ansible-Controller-IP",
            "Keine gültige IPv4-Adresse konfiguriert.",
            "TUI → Neue Umgebung einrichten.",
        ))

    raw_identity = config.get("identity", {}) or {}
    identity = raw_identity if isinstance(raw_identity, dict) else {}
    ansible_user = str(identity.get("ansible_user", "") or "").strip()
    try:
        normalized_ansible_user = _mavi_normalize_ansible_user(ansible_user)
    except ValueError:
        normalized_ansible_user = ""
        invalid_ansible_user = bool(ansible_user)
    else:
        invalid_ansible_user = False
    if normalized_ansible_user:
        findings.append(_mavi_doctor_finding(
            "pass",
            "identity.ansible_user",
            "Ansible-Identität",
            f"Nicht geheime Benutzeridentität ist gesetzt: {normalized_ansible_user}",
        ))
    elif invalid_ansible_user:
        findings.append(_mavi_doctor_finding(
            "fail",
            "identity.ansible_user",
            "Ansible-Identität",
            "Der gespeicherte ansible_user hat kein unterstütztes Format.",
            r"TUI → Zugangsdaten & Vault → Windows-Benutzer erneut einrichten.",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "warn",
            "identity.ansible_user",
            "Ansible-Identität",
            "Noch kein Windows-Benutzer hinterlegt. Für den ersten Programmstart ist das in Ordnung.",
            "Vor dem ersten PC: TUI → Zugangsdaten & Vault → Windows-Benutzer und Kennwort einrichten.",
        ))

    raw_vault_path = str(identity.get("vault_path", "") or "").strip()
    vault_path: Path | None = None
    vault_within_project = False
    if raw_vault_path:
        candidate = Path(raw_vault_path).expanduser()
        if not candidate.is_absolute():
            candidate = project / candidate
        try:
            project_root = project.resolve(strict=False)
            vault_path = candidate.resolve(strict=False)
            vault_path.relative_to(project_root)
            vault_within_project = True
        except (OSError, ValueError):
            vault_within_project = False
    if vault_path and vault_within_project and vault_path.is_file():
        findings.append(_mavi_doctor_finding(
            "pass",
            "identity.vault_path",
            "Ansible-Vault-Datei",
            f"Vault-Datei liegt innerhalb des Laufzeitprojekts: {vault_path}",
        ))
    elif vault_path and not vault_within_project:
        findings.append(_mavi_doctor_finding(
            "fail",
            "identity.vault_path",
            "Ansible-Vault-Datei",
            "Der konfigurierte Vault-Pfad verlässt die Grenze des Laufzeitprojekts.",
            "Vault unter inventory/group_vars/windows im Laufzeitprojekt ablegen.",
        ))
    elif vault_path:
        findings.append(_mavi_doctor_finding(
            "warn",
            "identity.vault_path",
            "Ansible-Vault-Datei",
            f"Vault-Datei ist noch nicht angelegt: {vault_path}",
            "Vor dem ersten PC: TUI → Zugangsdaten & Vault → Windows-Kennwort verschlüsselt speichern.",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "warn",
            "identity.vault_path",
            "Ansible-Vault-Datei",
            "Kein Vault-Pfad hinterlegt.",
            "TUI → Zugangsdaten & Vault → Windows-Kennwort verschlüsselt speichern.",
        ))

    source_root = _mavi_source_root(config)
    if source_root is None:
        findings.append(_mavi_doctor_finding(
            "fail",
            "software.source",
            "Softwarequelle",
            "Es wurde kein lokaler Quellpfad auf dem Controller hinterlegt.",
            "TUI → Neue Umgebung einrichten → Softwarequelle angeben.",
        ))
    elif not source_root.is_absolute():
        findings.append(_mavi_doctor_finding(
            "fail",
            "software.source",
            "Softwarequelle",
            f"Der lokale Quellpfad muss absolut sein: {source_root}",
            "Absoluten Mount-/Quellpfad im Setup eintragen.",
        ))
    elif source_root.exists() and source_root.is_dir():
        findings.append(_mavi_doctor_finding(
            "pass",
            "software.source",
            "Softwarequelle",
            f"{_mavi_source_label(config)} ist auf dem Controller erreichbar: {source_root}",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "fail",
            "software.source",
            "Softwarequelle",
            f"Der konfigurierte Ordner ist nicht erreichbar: {source_root}",
            "Share mounten/berechtigen oder den Pfad im Setup korrigieren.",
        ))

    if _ansible_playbook_candidates():
        findings.append(_mavi_doctor_finding(
            "pass",
            "controller.ansible",
            "Ansible-Startpunkt",
            "Mindestens ein ansible-playbook-Startpunkt wurde gefunden.",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "fail",
            "controller.ansible",
            "Ansible-Startpunkt",
            "ansible-playbook wurde auf dem Controller nicht gefunden.",
            "Ansible in der Controller-Umgebung installieren und Doctor erneut starten.",
        ))

    if feature in {"all", "ssh"}:
        # SSH ist ein optionaler späterer Schritt. Im Gesamt-Doctor wird ein
        # noch nicht vorbereiteter Bootstrap daher als Hinweis dargestellt;
        # der gezielte SSH-Doctor bleibt dagegen bewusst strikt.
        ssh_status = "fail" if feature == "ssh" else "warn"
        base_url = str(config.get("bootstrap_base_url", "") or "").strip()
        bootstrap_dir = str(config.get("bootstrap_local_dir", "") or "").strip()
        if _mavi_valid_https_url(base_url):
            findings.append(_mavi_doctor_finding(
                "pass",
                "ssh.bootstrap_url",
                "SSH-Bootstrap-URL",
                f"HTTPS-URL gesetzt: {base_url}",
            ))
        else:
            findings.append(_mavi_doctor_finding(
                ssh_status,
                "ssh.bootstrap_url",
                "SSH-Bootstrap-URL",
                "Für den OpenSSH-Bootstrap fehlt eine HTTPS-Basis-URL.",
                "TUI → Neue Umgebung einrichten oder SSH → HTTPS-Setup verwenden.",
            ))
        bootstrap_path = Path(bootstrap_dir).expanduser() if bootstrap_dir else None
        if bootstrap_path and not bootstrap_path.is_absolute():
            findings.append(_mavi_doctor_finding(
                ssh_status,
                "ssh.bootstrap_dir",
                "SSH-Bootstrap-Webroot",
                f"Webroot muss ein absoluter Pfad sein: {bootstrap_path}",
                "Absoluten Webroot im Setup eintragen.",
            ))
        elif bootstrap_path and bootstrap_path.is_dir():
            findings.append(_mavi_doctor_finding(
                "pass",
                "ssh.bootstrap_dir",
                "SSH-Bootstrap-Webroot",
                f"Vorhandener Ordner: {bootstrap_path}",
            ))
        elif bootstrap_path:
            findings.append(_mavi_doctor_finding(
                ssh_status,
                "ssh.bootstrap_dir",
                "SSH-Bootstrap-Webroot",
                f"Konfigurierter Ordner fehlt oder ist kein Verzeichnis: {bootstrap_path}",
                "Webroot anlegen/berechtigen oder den Pfad im Setup korrigieren.",
            ))
        else:
            findings.append(_mavi_doctor_finding(
                ssh_status,
                "ssh.bootstrap_dir",
                "SSH-Bootstrap-Webroot",
                "Kein lokaler Webroot für veröffentlichte Bootstrap-Dateien konfiguriert.",
                "TUI → Neue Umgebung einrichten.",
            ))
        if shutil.which("ssh-keygen"):
            findings.append(_mavi_doctor_finding(
                "pass",
                "ssh.keygen",
                "SSH-Key-Werkzeug",
                "ssh-keygen ist auf dem Controller verfügbar.",
            ))
        else:
            findings.append(_mavi_doctor_finding(
                "warn",
                "ssh.keygen",
                "SSH-Key-Werkzeug",
                "ssh-keygen wurde nicht im PATH gefunden.",
                "Vor dem OpenSSH-Setup openssh-client installieren.",
            ))

    if feature in {"all", "winrm"}:
        winrm = config.get("winrm_https", {}) or {}
        domain = str(winrm.get("domain_suffix", "") or "").strip()
        if _mavi_valid_dns_name(domain):
            findings.append(_mavi_doctor_finding(
                "pass",
                "winrm.domain",
                "Kerberos-Domäne",
                f"Konfiguriert: {domain}",
            ))
        elif domain:
            findings.append(_mavi_doctor_finding(
                "fail",
                "winrm.domain",
                "Kerberos-Domäne",
                f"Die konfigurierte AD-DNS-Domäne ist syntaktisch ungültig: {domain}",
                "FQDN der AD-Domäne im Setup korrigieren, z. B. ad.example.org.",
            ))
        else:
            findings.append(_mavi_doctor_finding(
                "warn",
                "winrm.domain",
                "Kerberos-Domäne",
                "Keine AD-Domäne hinterlegt. Das ist nur nötig, wenn PSRP/WinRM HTTPS + Kerberos verwendet werden soll.",
                "Nach dem SSH-Doctor die AD-DNS-Domäne im Setup eintragen.",
            ))

    return findings, config


def _mavi_doctor_target_checks(
    project: Path,
    host: str,
    feature: str,
) -> tuple[list[dict[str, str]], str | None]:
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )
    from .remote import (
        _effective_host_var,
        get_ssh_settings,
    )

    findings: list[dict[str, str]] = []
    inventory = load_inventory(project)
    windows = ensure_windows_tree(inventory)
    hosts = windows.get("hosts", {}) or {}
    raw_host = hosts.get(host)
    if not isinstance(raw_host, dict):
        findings.append(_mavi_doctor_finding(
            "fail",
            "target.inventory",
            "Ziel-PC im Inventory",
            f"„{host}“ ist nicht im Windows-Inventory vorhanden.",
            "TUI → PCs & Verbindung → Neuen PC hinzufügen.",
        ))
        return findings, None

    target_address = str(raw_host.get("ansible_host", "") or host).strip()
    connection = str(
        _effective_host_var(windows, raw_host, "ansible_connection", "ssh") or "ssh"
    ).lower()
    remote_allowed = False
    findings.append(_mavi_doctor_finding(
        "pass",
        "target.inventory",
        "Ziel-PC im Inventory",
        f"{host} → {target_address}; Transport: {connection.upper()}",
    ))

    if connection == "ssh":
        settings = get_ssh_settings(project)
        key_path = Path(settings["private_key"]).expanduser()
        if key_path.exists():
            remote_allowed = True
            findings.append(_mavi_doctor_finding(
                "pass",
                "target.ssh_key",
                "SSH-Automationsschlüssel",
                f"Privater Schlüssel vorhanden: {key_path}",
            ))
        else:
            findings.append(_mavi_doctor_finding(
                "fail",
                "target.ssh_key",
                "SSH-Automationsschlüssel",
                f"Privater Schlüssel fehlt: {key_path}",
                "TUI → PCs & Verbindung → OpenSSH einrichten.",
            ))
    elif connection in {"psrp", "winrm"}:
        protocol = str(
            _effective_host_var(windows, raw_host, "ansible_psrp_protocol", "") or ""
        ).lower()
        auth = str(
            _effective_host_var(windows, raw_host, "ansible_psrp_auth", "") or ""
        ).lower()
        if connection == "psrp" and protocol == "https" and auth == "kerberos":
            remote_allowed = True
            findings.append(_mavi_doctor_finding(
                "pass",
                "target.winrm_transport",
                "PSRP/WinRM-Transport",
                "HTTPS + Kerberos-only ist im Inventory gesetzt.",
            ))
        else:
            findings.append(_mavi_doctor_finding(
                "fail",
                "target.winrm_transport",
                "PSRP/WinRM-Transport",
                "Der Ziel-PC ist nicht auf PSRP HTTPS + Kerberos-only konfiguriert.",
                "TUI → OpenSSH/Windows → geprüftes PSRP/WinRM HTTPS + Kerberos.",
            ))
    else:
        findings.append(_mavi_doctor_finding(
            "warn",
            "target.transport",
            "Ziel-PC-Transport",
            f"Unbekannter oder nicht unterstützter Transport: {connection}",
            "SSH oder PSRP HTTPS + Kerberos über die TUI konfigurieren.",
        ))

    if feature == "software":
        findings.append(_mavi_doctor_finding(
            "info",
            "target.software",
            "Software-Installation",
            "Für eine genaue Zielprüfung starte den Remote-Doctor oder importiere einen Windows-Faktenbericht.",
        ))
    # Remote-Fakten werden nur über den sicheren, bereits geprüften
    # Management-Transport abgerufen. Doctor darf keinen Legacy-Transport
    # als bequemen Fallback verwenden.
    return findings, connection if remote_allowed else None


def _mavi_doctor_windows_collector() -> str:
    """
    Ein read-only PowerShell-Collector. Lokal schreibt er ausschließlich
    einen JSON-Bericht; über Ansible liefert er denselben Inhalt als Result.
    """
    return r'''param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'Stop'
$errors = New-Object System.Collections.Generic.List[string]

function Add-MaviDoctorError {
    param([string]$Message)
    if ($Message) {
        [void]$errors.Add($Message)
    }
}

function Get-MaviDoctorService {
    param([string]$Name)
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        return [ordered]@{
            Present = $true
            Status = [string]$service.Status
            StartType = [string]$service.StartType
        }
    }
    catch {
        return [ordered]@{
            Present = $false
            Status = ""
            StartType = ""
        }
    }
}

$facts = [ordered]@{
    collector_version = "2"
    collected_utc = [DateTime]::UtcNow.ToString("o")
    computer_name = $env:COMPUTERNAME
    os = [ordered]@{}
    domain = [ordered]@{}
    directory = [ordered]@{}
    network = [ordered]@{}
    network_drives = @()
    time = [ordered]@{}
    proxy = [ordered]@{}
    services = [ordered]@{}
    remoting = [ordered]@{}
    errors = $errors
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $facts.os = [ordered]@{
        Caption = [string]$os.Caption
        Version = [string]$os.Version
        BuildNumber = [string]$os.BuildNumber
        Architecture = [string]$os.OSArchitecture
    }
}
catch {
    Add-MaviDoctorError ("Win32_OperatingSystem: " + $_.Exception.Message)
}

try {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $facts.domain = [ordered]@{
        Joined = [bool]$computer.PartOfDomain
        Name = [string]$computer.Domain
        DomainRole = [int]$computer.DomainRole
        LogonServer = ([string]$env:LOGONSERVER).TrimStart([char]92)
    }
}
catch {
    Add-MaviDoctorError ("Win32_ComputerSystem: " + $_.Exception.Message)
}

try {
    $ipConfigurations = @(Get-NetIPConfiguration -ErrorAction Stop)
    $adapterConfigurations = @(
        Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction Stop
    )
    $adapters = @(
        foreach ($item in $ipConfigurations) {
            $cimAdapter = @(
                $adapterConfigurations |
                Where-Object { [int]$_.InterfaceIndex -eq [int]$item.InterfaceIndex }
            ) | Select-Object -First 1
            $addresses = @(
                Get-NetIPAddress -InterfaceIndex $item.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -and $_.IPAddress -ne "127.0.0.1" } |
                ForEach-Object {
                    [ordered]@{
                        Address = [string]$_.IPAddress
                        PrefixLength = [int]$_.PrefixLength
                    }
                }
            )
            if ($addresses.Count -eq 0) { continue }
            [ordered]@{
                InterfaceAlias = [string]$item.InterfaceAlias
                InterfaceIndex = [int]$item.InterfaceIndex
                IPv4 = @($addresses)
                DnsServers = @($item.DNSServer.ServerAddresses | Where-Object { $_ })
                DefaultGateways = @($item.IPv4DefaultGateway.NextHop | Where-Object { $_ })
                DhcpEnabled = if ($null -ne $cimAdapter) { [bool]$cimAdapter.DHCPEnabled } else { $null }
                DhcpServer = if ($null -ne $cimAdapter) { [string]$cimAdapter.DHCPServer } else { "" }
                DnsSuffix = if ($null -ne $cimAdapter) { [string]$cimAdapter.DNSDomain } else { "" }
            }
        }
    )
    $ipv4 = @($adapters | ForEach-Object { $_.IPv4 } | ForEach-Object { $_.Address } | Sort-Object -Unique)
    $dns = @($adapters | ForEach-Object { $_.DnsServers } | Where-Object { $_ } | Sort-Object -Unique)
    $gateways = @($adapters | ForEach-Object { $_.DefaultGateways } | Where-Object { $_ } | Sort-Object -Unique)
    $dhcpServers = @($adapters | ForEach-Object { $_.DhcpServer } | Where-Object { $_ } | Sort-Object -Unique)
    $facts.network = [ordered]@{
        IPv4 = @($ipv4)
        DnsServers = @($dns)
        DefaultGateways = @($gateways)
        DhcpServers = @($dhcpServers)
        Adapters = @($adapters)
    }
}
catch {
    Add-MaviDoctorError ("Netzwerk: " + $_.Exception.Message)
}

try {
    $mappedDrives = @(
        Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=4" -ErrorAction Stop |
        ForEach-Object {
            [ordered]@{
                LocalPath = [string]$_.DeviceID
                RemotePath = [string]$_.ProviderName
                Label = [string]$_.VolumeName
                Source = "Win32_LogicalDisk"
            }
        }
    )
    $smbMappings = @()
    if (Get-Command -Name Get-SmbMapping -ErrorAction SilentlyContinue) {
        $smbMappings = @(
            Get-SmbMapping -ErrorAction Stop |
            ForEach-Object {
                [ordered]@{
                    LocalPath = [string]$_.LocalPath
                    RemotePath = [string]$_.RemotePath
                    Status = [string]$_.Status
                    Persistent = [bool]$_.Persistent
                    Source = "Get-SmbMapping"
                }
            }
        )
    }
    $facts.network_drives = @($mappedDrives + $smbMappings)
}
catch {
    Add-MaviDoctorError ("Netzlaufwerke/SMB: " + $_.Exception.Message)
}

try {
    $domainName = [string]$facts.domain.Name
    $domainControllers = @()
    $ldapSrv = @()
    $kdcSrv = @()
    $enterpriseCas = @()
    $forestName = ""
    $clientSite = ""
    if ([bool]$facts.domain.Joined -and $domainName) {
        try {
            $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $forestName = [string]$currentDomain.Forest.Name
            $domainControllers = @(
                $currentDomain.DomainControllers |
                ForEach-Object {
                    [ordered]@{
                        Name = [string]$_.Name
                        SiteName = [string]$_.SiteName
                        IPAddress = [string]$_.IPAddress
                    }
                }
            )
        }
        catch {
            Add-MaviDoctorError ("Domain Controller: " + $_.Exception.Message)
        }
        try {
            if (Get-Command -Name nltest.exe -ErrorAction SilentlyContinue) {
                $siteOutput = @(& nltest.exe /dsgetsite 2>$null)
                $clientSite = ([string]($siteOutput | Select-Object -First 1)).Trim()
            }
        }
        catch {
            Add-MaviDoctorError ("AD-Site: " + $_.Exception.Message)
        }
        try {
            $ldapSrv = @(
                Resolve-DnsName -Type SRV ("_ldap._tcp.dc._msdcs." + $domainName) -ErrorAction Stop |
                Where-Object { $_.Type -eq "SRV" } |
                ForEach-Object {
                    [ordered]@{
                        Target = [string]($_.NameTarget.TrimEnd('.'))
                        Port = [int]$_.Port
                        Priority = [int]$_.Priority
                        Weight = [int]$_.Weight
                    }
                }
            )
        }
        catch {
            Add-MaviDoctorError ("AD LDAP DNS-SRV: " + $_.Exception.Message)
        }
        try {
            $kdcSrv = @(
                Resolve-DnsName -Type SRV ("_kerberos._tcp." + $domainName) -ErrorAction Stop |
                Where-Object { $_.Type -eq "SRV" } |
                ForEach-Object {
                    [ordered]@{
                        Target = [string]($_.NameTarget.TrimEnd('.'))
                        Port = [int]$_.Port
                        Priority = [int]$_.Priority
                        Weight = [int]$_.Weight
                    }
                }
            )
        }
        catch {
            Add-MaviDoctorError ("Kerberos DNS-SRV: " + $_.Exception.Message)
        }
        try {
            $rootDse = [ADSI]"LDAP://RootDSE"
            $configurationNamingContext = [string]$rootDse.configurationNamingContext
            $enrollmentServicesPath = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services," + $configurationNamingContext
            $searchRoot = [System.DirectoryServices.DirectoryEntry]::new($enrollmentServicesPath)
            $searcher = [System.DirectoryServices.DirectorySearcher]::new($searchRoot)
            $searcher.Filter = "(objectClass=pKIEnrollmentService)"
            [void]$searcher.PropertiesToLoad.Add("cn")
            [void]$searcher.PropertiesToLoad.Add("dNSHostName")
            [void]$searcher.PropertiesToLoad.Add("certificateTemplates")
            $enterpriseCas = @(
                $searcher.FindAll() |
                ForEach-Object {
                    [ordered]@{
                        Name = [string]$_.Properties["cn"][0]
                        DnsHostName = [string]$_.Properties["dnshostname"][0]
                        Templates = @($_.Properties["certificatetemplates"] | ForEach-Object { [string]$_ })
                    }
                }
            )
        }
        catch {
            Add-MaviDoctorError ("Enterprise-CA/AD CS: " + $_.Exception.Message)
        }
    }
    $facts.directory = [ordered]@{
        Forest = $forestName
        ClientSite = $clientSite
        DomainControllers = @($domainControllers)
        LdapSrv = @($ldapSrv)
        KdcSrv = @($kdcSrv)
        EnterpriseCas = @($enterpriseCas)
    }
}
catch {
    Add-MaviDoctorError ("Verzeichnisdienste: " + $_.Exception.Message)
}

try {
    $timeSource = ""
    if (Get-Command -Name w32tm.exe -ErrorAction SilentlyContinue) {
        $timeSource = [string]((& w32tm.exe /query /source 2>$null) -join " ").Trim()
    }
    $timeParameters = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction SilentlyContinue
    $facts.time = [ordered]@{
        Source = $timeSource
        Type = if ($null -ne $timeParameters) { [string]$timeParameters.Type } else { "" }
        NtpServer = if ($null -ne $timeParameters) { [string]$timeParameters.NtpServer } else { "" }
    }
}
catch {
    Add-MaviDoctorError ("Zeitquelle: " + $_.Exception.Message)
}

try {
    $internetSettings = Get-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    $winHttp = ""
    if (Get-Command -Name netsh.exe -ErrorAction SilentlyContinue) {
        $winHttp = [string]((& netsh.exe winhttp show proxy 2>$null) -join "`n").Trim()
    }
    $facts.proxy = [ordered]@{
        UserProxyEnabled = if ($null -ne $internetSettings) { [bool]$internetSettings.ProxyEnable } else { $false }
        UserProxyServer = if ($null -ne $internetSettings) { [string]$internetSettings.ProxyServer } else { "" }
        AutoConfigUrl = if ($null -ne $internetSettings) { [string]$internetSettings.AutoConfigURL } else { "" }
        AutoDetect = if ($null -ne $internetSettings) { [bool]$internetSettings.AutoDetect } else { $false }
        WinHttpSummary = $winHttp
    }
}
catch {
    Add-MaviDoctorError ("Proxy: " + $_.Exception.Message)
}

$facts.services = [ordered]@{
    sshd = Get-MaviDoctorService -Name "sshd"
    WinRM = Get-MaviDoctorService -Name "WinRM"
}

try {
    $listeners = @(
        Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
        ForEach-Object {
            [ordered]@{
                Transport = [string]$_.Keys["Transport"]
                Address = [string]$_.Keys["Address"]
                Port = [string]$_.Port
                CertificateThumbprint = [string]$_.CertificateThumbprint
            }
        }
    )
    $facts.remoting = [ordered]@{
        WinRMListeners = @($listeners)
        SshdConfigPresent = [bool](Test-Path -LiteralPath "$env:ProgramData\ssh\sshd_config")
    }
}
catch {
    Add-MaviDoctorError ("Remoting: " + $_.Exception.Message)
}

$json = $facts | ConvertTo-Json -Depth 8
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$factsB64 = [Convert]::ToBase64String($bytes)

if (Get-Variable -Name Ansible -ErrorAction SilentlyContinue) {
    $Ansible.Result = @{
        FactsB64 = $factsB64
        CollectorVersion = "2"
    }
}
else {
    if (-not $OutputPath) {
        $OutputPath = Join-Path $env:TEMP "Mavi-Doctor-Facts.json"
    }
    [System.IO.File]::WriteAllText(
        $OutputPath,
        $json,
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Output "MAVI_DOCTOR_FACTS_FILE=$OutputPath"
}
'''


def _mavi_write_windows_collector(project: Path, host: str | None = None) -> Path:

    from .environment import (
        project_paths,
    )
    from .catalogs import slugify

    reports_dir = project_paths(project)["reports_dir"] / "doctor"
    reports_dir.mkdir(parents=True, exist_ok=True)
    suffix = slugify(host) if host else "offline"
    path = reports_dir / f"Mavi-Doctor-Collector-{suffix}.ps1"
    path.write_bytes(
        _mavi_doctor_windows_collector().replace("\n", "\r\n").encode("utf-8")
    )
    return path


def _mavi_load_windows_facts(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8-sig")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Faktenbericht kann nicht gelesen werden: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Faktenbericht enthält kein JSON-Objekt.")
    return data


def _mavi_collect_remote_windows_facts(
    project: Path,
    host: str,
    *,
    ask_vault: bool,
) -> dict[str, Any]:
    """
    Eine temporäre, nur lesende Ansible-Playbook-Ausführung. Das Playbook wird
    danach gelöscht; dauerhaft bleibt kein Agent auf Windows zurück.
    """

    from .environment import (
        project_paths,
    )
    from .execution import create_temporary_vault_password_file
    from .remote import (
        _ansible_playbook_runtime,
        _ansible_runtime_environment,
        _effective_host_var,
        _host_inventory_entry,
    )
    from .reports import redact_sensitive_text

    inventory, windows, host_data = _host_inventory_entry(project, host)
    del inventory
    connection = str(
        _effective_host_var(windows, host_data, "ansible_connection", "ssh") or "ssh"
    ).lower()
    playbook = [{
        "name": "Mavi Doctor read-only Windows facts",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Read-only Windows facts",
                "ansible.windows.win_powershell": {
                    "error_action": "continue",
                    "script": _mavi_doctor_windows_collector(),
                },
                "register": "mavi_doctor_facts",
            },
            {
                "name": "Expose Mavi Doctor facts",
                "ansible.builtin.debug": {
                    "msg": "MAVI_DOCTOR_FACTS_B64={{ mavi_doctor_facts.result.FactsB64 | default('') }}",
                },
            },
        ],
    }]

    fd, raw_playbook_path = tempfile.mkstemp(
        prefix=".mavi-doctor-",
        suffix=".yml",
    )
    playbook_path = Path(raw_playbook_path)
    vault_file: Path | None = None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            yaml.safe_dump(playbook, handle, allow_unicode=True, sort_keys=False)

        # Auch SSH-Inventories können ihren ansible_user in Vault ablegen.
        # Der Aufrufer entscheidet deshalb bewusst, ob ein temporäres
        # Vault-Passwort für diese reine Faktenabfrage nötig ist.
        if ask_vault:
            vault_file = create_temporary_vault_password_file(
                getpass.getpass("Ansible-Vault-Passwort für den Remote-Doctor: ")
            )

        executable, ansible_python = _ansible_playbook_runtime()
        command = [
            str(ansible_python),
            "-I",
            str(executable),
            "-i",
            str(project_paths(project)["inventory"]),
            str(playbook_path),
            "--limit",
            host,
        ]
        if vault_file is not None:
            command.extend(["--vault-password-file", str(vault_file)])

        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            env=_ansible_runtime_environment(ansible_python),
            cwd=str(project),
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        marker = re.search(r"MAVI_DOCTOR_FACTS_B64=([A-Za-z0-9+/=]+)", output)
        if result.returncode != 0 or marker is None:
            detail = redact_sensitive_text(output.strip())
            detail = detail[-3000:] if detail else "keine verwertbare Ansible-Ausgabe"
            raise RuntimeError(
                "Remote-Collector konnte keine Fakten liefern: " + detail
            )
        try:
            decoded = base64.b64decode(marker.group(1), validate=True)
            facts = json.loads(decoded.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Remote-Collector lieferte ungültige Fakten: {exc}"
            ) from exc
        if not isinstance(facts, dict):
            raise RuntimeError("Remote-Collector lieferte kein Faktenobjekt.")
        return facts
    finally:
        playbook_path.unlink(missing_ok=True)
        if vault_file is not None:
            vault_file.unlink(missing_ok=True)


def _mavi_fact_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _mavi_fact_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _mavi_doctor_fact_checks(facts: dict[str, Any]) -> list[dict[str, str]]:
    from .reports import redact_sensitive_text

    findings: list[dict[str, str]] = []
    collector_version = str(facts.get("collector_version", "") or "").strip()
    if collector_version and collector_version != "2":
        findings.append(_mavi_doctor_finding(
            "warn",
            "windows.collector_version",
            "Collector-Version",
            f"Fakten stammen aus Collector-Version {collector_version}; aktuell ist Version 2.",
            "Aktuellen Offline-Collector erzeugen und erneut ausführen.",
        ))
    computer_name = str(facts.get("computer_name", "") or "").strip()
    if computer_name:
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.collector",
            "Windows-Fakten",
            f"Read-only Faktenbericht von {computer_name} geladen.",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "warn",
            "windows.collector",
            "Windows-Fakten",
            "Faktenbericht enthält keinen Computernamen.",
        ))

    os_info = _mavi_fact_dict(facts.get("os"))
    caption = str(os_info.get("Caption", "") or "").strip()
    version = str(os_info.get("Version", "") or "").strip()
    if caption:
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.os",
            "Windows-Version",
            f"{caption} {version}".strip(),
        ))

    domain = _mavi_fact_dict(facts.get("domain"))
    if bool(domain.get("Joined", False)):
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.domain",
            "Domänenmitgliedschaft",
            f"Mit Domäne verbunden: {domain.get('Name', '(unbekannt)')}",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "warn",
            "windows.domain",
            "Domänenmitgliedschaft",
            "Der PC ist nicht als AD-Mitglied erkannt. Das ist für SSH nicht nötig, für Kerberos jedoch relevant.",
        ))

    network = _mavi_fact_dict(facts.get("network"))
    dns_servers = _mavi_fact_list(network.get("DnsServers"))
    if dns_servers:
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.dns",
            "DNS-Server",
            ", ".join(str(value) for value in dns_servers),
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "warn",
            "windows.dns",
            "DNS-Server",
            "Der Collector konnte keine IPv4-DNS-Server lesen.",
        ))

    adapters = _mavi_fact_list(network.get("Adapters"))
    adapter_summaries: list[str] = []
    for adapter in adapters:
        if not isinstance(adapter, dict):
            continue
        address_values: list[str] = []
        for address in _mavi_fact_list(adapter.get("IPv4")):
            if not isinstance(address, dict):
                continue
            ip_value = str(address.get("Address", "") or "").strip()
            prefix = address.get("PrefixLength", "")
            if ip_value:
                address_values.append(f"{ip_value}/{prefix}")
        gateways = ",".join(
            str(item) for item in _mavi_fact_list(adapter.get("DefaultGateways"))
            if item
        ) or "kein Gateway"
        dhcp = str(adapter.get("DhcpServer", "") or "").strip()
        label = str(adapter.get("InterfaceAlias", "") or "Interface")
        adapter_summaries.append(
            f"{label}: {','.join(address_values) or 'keine IPv4'}; "
            f"Gateway {gateways}; DHCP {dhcp or 'aus/unbekannt'}"
        )
    if adapter_summaries:
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.network_topology",
            "Netzwerkpräfix, Gateway und DHCP",
            " | ".join(adapter_summaries[:6]),
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "warn",
            "windows.network_topology",
            "Netzwerkpräfix, Gateway und DHCP",
            "Keine detaillierte IPv4-Adaptertopologie im Faktenbericht.",
        ))

    directory = _mavi_fact_dict(facts.get("directory"))
    domain_controllers = _mavi_fact_list(directory.get("DomainControllers"))
    ldap_srv = _mavi_fact_list(directory.get("LdapSrv"))
    dc_names = sorted({
        str(item.get("Name") or item.get("Target") or "").strip().rstrip(".")
        for item in list(domain_controllers) + list(ldap_srv)
        if isinstance(item, dict)
        and str(item.get("Name") or item.get("Target") or "").strip()
    })
    logon_server = str(domain.get("LogonServer", "") or "").strip().lstrip("\\")
    if logon_server and logon_server not in dc_names:
        dc_names.append(logon_server)
        dc_names.sort()
    if dc_names:
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.domain_controllers",
            "Domain Controller / LDAP-SRV",
            ", ".join(dc_names),
        ))
    elif bool(domain.get("Joined", False)):
        findings.append(_mavi_doctor_finding(
            "warn",
            "windows.domain_controllers",
            "Domain Controller / LDAP-SRV",
            "Der domänengebundene PC lieferte keine Domain-Controller-Metadaten.",
            "DNS-SRV-Auflösung und AD-Erreichbarkeit prüfen.",
        ))

    forest_name = str(directory.get("Forest", "") or "").strip()
    client_site = str(directory.get("ClientSite", "") or "").strip()
    if forest_name or client_site:
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.ad_topology",
            "AD-Forest und Client-Site",
            f"Forest: {forest_name or '(unbekannt)'}; Site: {client_site or '(unbekannt)'}",
        ))

    kdc_srv = _mavi_fact_list(directory.get("KdcSrv"))
    kdc_names = sorted({
        str(item.get("Target", "") or "").strip().rstrip(".")
        for item in kdc_srv
        if isinstance(item, dict) and str(item.get("Target", "") or "").strip()
    })
    if kdc_names:
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.kdc_srv",
            "Kerberos-KDC-SRV",
            ", ".join(kdc_names),
        ))
    elif bool(domain.get("Joined", False)):
        findings.append(_mavi_doctor_finding(
            "warn",
            "windows.kdc_srv",
            "Kerberos-KDC-SRV",
            "Keine _kerberos._tcp-SRV-Antwort im Faktenbericht.",
            "AD-DNS-Zone und Client-DNS-Konfiguration prüfen.",
        ))

    enterprise_cas = _mavi_fact_list(directory.get("EnterpriseCas"))
    ca_summaries = []
    for ca in enterprise_cas:
        if not isinstance(ca, dict):
            continue
        name = str(ca.get("Name", "") or "").strip()
        host_name = str(ca.get("DnsHostName", "") or "").strip()
        templates = _mavi_fact_list(ca.get("Templates"))
        if name or host_name:
            ca_summaries.append(
                f"{name or '(ohne Namen)'}@{host_name or '(ohne DNS)'} "
                f"({len(templates)} Templates)"
            )
    findings.append(_mavi_doctor_finding(
        "pass" if ca_summaries else "info",
        "windows.enterprise_ca",
        "Enterprise-CA / AD CS",
        " | ".join(ca_summaries[:10])
        if ca_summaries
        else "Keine Enterprise-CA über AD Enrollment Services erkannt; das kann beabsichtigt sein.",
    ))

    network_drives = _mavi_fact_list(facts.get("network_drives"))
    drive_summaries = sorted({
        f"{str(item.get('LocalPath', '') or '-').strip()} → "
        f"{str(item.get('RemotePath', '') or '').strip()}"
        for item in network_drives
        if isinstance(item, dict) and str(item.get("RemotePath", "") or "").strip()
    })
    findings.append(_mavi_doctor_finding(
        "pass" if drive_summaries else "info",
        "windows.network_drives",
        "Gemappte Netzlaufwerke / SMB",
        " | ".join(drive_summaries[:20])
        if drive_summaries
        else "Im Kontext des Collectors wurden keine gemappten SMB-Laufwerke erkannt.",
    ))

    time_info = _mavi_fact_dict(facts.get("time"))
    time_source = str(time_info.get("Source", "") or "").strip()
    time_type = str(time_info.get("Type", "") or "").strip()
    time_ntp = str(time_info.get("NtpServer", "") or "").strip()
    findings.append(_mavi_doctor_finding(
        "pass" if time_source else "warn",
        "windows.time_source",
        "Windows-Zeitquelle",
        (
            f"Quelle: {time_source or '(nicht ermittelt)'}; "
            f"Typ: {time_type or '(unbekannt)'}; NTP: {time_ntp or '(nicht gesetzt)'}"
        ),
        "w32time-Status und Domänenzeithierarchie prüfen." if not time_source else "",
    ))

    proxy = _mavi_fact_dict(facts.get("proxy"))
    proxy_enabled = bool(proxy.get("UserProxyEnabled", False))
    proxy_server = redact_sensitive_text(
        str(proxy.get("UserProxyServer", "") or "").strip()
    )
    auto_config = redact_sensitive_text(
        str(proxy.get("AutoConfigUrl", "") or "").strip()
    )
    proxy_parts = [
        f"Benutzerproxy: {'an' if proxy_enabled else 'aus'}",
        f"Server: {proxy_server}" if proxy_server else "",
        f"PAC: {auto_config}" if auto_config else "",
        f"AutoDetect: {'an' if bool(proxy.get('AutoDetect', False)) else 'aus'}",
    ]
    findings.append(_mavi_doctor_finding(
        "info",
        "windows.proxy",
        "Proxy-Erkennung",
        "; ".join(part for part in proxy_parts if part),
    ))

    services = _mavi_fact_dict(facts.get("services"))
    sshd = _mavi_fact_dict(services.get("sshd"))
    if bool(sshd.get("Present", False)):
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.sshd",
            "OpenSSH-Server",
            f"sshd vorhanden, Status: {sshd.get('Status', '(unbekannt)')}",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "warn",
            "windows.sshd",
            "OpenSSH-Server",
            "sshd wurde nicht gefunden. Für den SSH-Weg erst den OpenSSH-Bootstrap verwenden.",
        ))

    remoting = _mavi_fact_dict(facts.get("remoting"))
    listeners = _mavi_fact_list(remoting.get("WinRMListeners"))
    https_listeners = [
        item for item in listeners
        if isinstance(item, dict)
        and str(item.get("Transport", "") or "").upper() == "HTTPS"
    ]
    if https_listeners:
        findings.append(_mavi_doctor_finding(
            "pass",
            "windows.winrm_https",
            "WinRM-HTTPS-Listener",
            f"{len(https_listeners)} HTTPS-Listener erkannt.",
        ))
    else:
        findings.append(_mavi_doctor_finding(
            "info",
            "windows.winrm_https",
            "WinRM-HTTPS-Listener",
            "Kein HTTPS-Listener erkannt. Für reines SSH ist das nicht erforderlich.",
        ))

    collector_errors = _mavi_fact_list(facts.get("errors"))
    if collector_errors:
        findings.append(_mavi_doctor_finding(
            "warn",
            "windows.collector_errors",
            "Teilweise nicht lesbare Fakten",
            "; ".join(str(item) for item in collector_errors[:3]),
        ))
    return findings


def cmd_doctor_collector(args: argparse.Namespace) -> None:
    """
    Explizite Artefakterzeugung, getrennt vom read-only Doctor. Dieser Befehl
    schreibt ausschließlich die angegebene PowerShell-Datei.
    """
    output_path = Path(args.out).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(
        _mavi_doctor_windows_collector().replace("\n", "\r\n").encode("utf-8")
    )
    print(f"✓ Read-only Windows-Collector geschrieben: {output_path}")
    print("  Der Collector liest Fakten und schreibt auf Windows nur die explizite JSON-Ausgabedatei.")


def cmd_doctor(args: argparse.Namespace) -> None:
    """
    Deterministischer Read-only Doctor: Profil, Controller, Inventory und
    optional ein Windows-Ziel untersuchen. Er nimmt keine Konfigurations- oder
    Systemänderung vor.
    """
    from .reports import redact_sensitive_text

    project = args.project
    feature = str(getattr(args, "feature", "all") or "all").lower()
    host = str(getattr(args, "host", "") or "").strip()
    findings, _config = _mavi_doctor_profile_checks(project, feature)

    connection: str | None = None
    if host:
        target_findings, connection = _mavi_doctor_target_checks(
            project,
            host,
            feature,
        )
        findings.extend(target_findings)

    facts_path = getattr(args, "facts", None)
    if facts_path:
        try:
            facts = _mavi_load_windows_facts(Path(facts_path).expanduser())
        except ValueError as exc:
            findings.append(_mavi_doctor_finding(
                "fail",
                "windows.fact_file",
                "Windows-Faktenbericht",
                str(exc),
                "Collector erneut ausführen oder den korrekten JSON-Pfad auswählen.",
            ))
        else:
            findings.extend(_mavi_doctor_fact_checks(facts))

    if bool(getattr(args, "remote", False)):
        if not host:
            findings.append(_mavi_doctor_finding(
                "fail",
                "windows.remote",
                "Remote-Doctor",
                "Für einen Remote-Doctor fehlt ein Ziel-PC.",
                "Im TUI zuerst einen PC auswählen.",
            ))
        elif connection not in {"ssh", "psrp", "winrm"}:
            findings.append(_mavi_doctor_finding(
                "fail",
                "windows.remote",
                "Remote-Doctor",
                "Der Inventory-Transport ist nicht für den Remote-Collector geeignet.",
                "SSH oder PSRP HTTPS + Kerberos konfigurieren.",
            ))
        else:
            try:
                facts = _mavi_collect_remote_windows_facts(
                    project,
                    host,
                    ask_vault=bool(getattr(args, "ask_vault", True)),
                )
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                findings.append(_mavi_doctor_finding(
                    "fail",
                    "windows.remote",
                    "Remote-Doctor",
                    redact_sensitive_text(exc),
                    "Bei fehlender Verbindung den Offline-Collector aus der TUI erzeugen und auf dem PC ausführen.",
                ))
            else:
                findings.extend(_mavi_doctor_fact_checks(facts))

    summary = _mavi_doctor_summary(findings)
    if str(getattr(args, "output_format", "text") or "text") == "json":
        print(json.dumps(
            {
                "schema_version": 1,
                "read_only": True,
                "feature": feature,
                "host": host or None,
                "summary": summary,
                "findings": findings,
            },
            ensure_ascii=False,
            indent=2,
        ))
    else:
        _mavi_doctor_print(findings)

    if summary["failed"]:
        raise SystemExit(1)
