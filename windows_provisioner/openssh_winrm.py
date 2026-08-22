# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""WinRM-/PSRP-Migration über OpenSSH.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    ThreadPoolExecutor,
    argparse,
    as_completed,
    base64,
    datetime,
    getpass,
    hashlib,
    ipaddress,
    json,
    os,
    re,
    secrets,
    shutil,
    socket,
    ssl,
    subprocess,
    sys,
    tempfile,
    time,
    timezone,
    urllib,
    yaml,
)



def cmd_ssh_winrm_https(args: argparse.Namespace) -> None:
    """WinRM ausschließlich aus einer bestehenden Mavi-SSH-Key-Sitzung heraus härten."""

    from .openssh import (
        _bootstrap_settings,
        _controller_bound_bootstrap_root_certificates,
    )


    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )
    from .execution import create_temporary_vault_password_file
    from .remote import (
        _apply_psrp_https_transport,
        _bootstrap_ca_probe_play,
        _certificate_thumbprint_from_file,
        _effective_host_var,
        _ensure_psrp_kerberos_controller_dependencies,
        _extract_bootstrap_ca_probe_result,
        _extract_winrm_csr,
        _extract_winrm_https_install_result,
        _host_inventory_entry,
        _is_missing_gssapi_failure,
        _issue_winrm_server_certificate,
        _kerberos_principal_for_host,
        _prepare_kerberos_runtime_config,
        _psrp_https_inventory_vars,
        _remember_winrm_https_state,
        _remove_host_winrm_certificate_artifacts,
        _run_winrm_temporary_play,
        _utc_now_iso,
        _vault_ansible_user_for_host,
        _winrm_csr_play,
        _winrm_https_settings,
        _winrm_https_target_identity,
        _winrm_install_https_play,
        _winrm_kerberos_https_ping_play,
    )
    from .reports import redact_sensitive_text
    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    connection = str(_effective_host_var(windows, host_data, "ansible_connection", "") or "").lower()
    if connection != "ssh":
        die(
            f"{args.host} ist nicht per OpenSSH konfiguriert. Mavi führt die WinRM-Härtung "
            "ausschließlich über die bestehende SSH-Key-Verbindung aus; HTTP/NTLM wird nicht verwendet."
        )

    try:
        bootstrap = _bootstrap_settings(args.project)
        (
            current_bootstrap_thumbprint,
            controller_bootstrap_certificates,
        ) = _controller_bound_bootstrap_root_certificates(project=args.project)
        current_bootstrap_certificate = controller_bootstrap_certificates[
            current_bootstrap_thumbprint
        ]
        current_bootstrap_ca_sha256 = hashlib.sha256(
            base64.b64decode(current_bootstrap_certificate, validate=True)
        ).hexdigest()
        bootstrap_probe_candidates = list(
            controller_bootstrap_certificates.values()
        )
        settings = _winrm_https_settings(args.project)
        identity = _winrm_https_target_identity(args.host, host_data, settings)
        _, kdc_endpoints = _prepare_kerberos_runtime_config(args.project, settings)
    except (OSError, ValueError, RuntimeError) as exc:
        die(f"WinRM-HTTPS-Konfiguration ist nicht sicher verwendbar: {exc}")

    try:
        _ensure_psrp_kerberos_controller_dependencies()
    except (OSError, RuntimeError, ValueError) as exc:
        die(f"Kerberos-Abhängigkeiten auf dem Ansible-Server konnten nicht eingerichtet werden: {exc}")

    vault_password = getpass.getpass("Vault password: ")
    try:
        vault_file = create_temporary_vault_password_file(vault_password)
    except OSError as exc:
        die(f"Temporäre Vault-Datei konnte nicht sicher angelegt werden: {exc}")

    try:
        try:
            kerberos_principal = _kerberos_principal_for_host(windows, host_data, settings)
        except ValueError as principal_error:
            # ansible_user kann korrekt ausschließlich im verschlüsselten
            # group_vars-Vault liegen. Erst nach dessen Entschlüsselung darf
            # Mavi daraus die UPN erzeugen; ein erfundenes Konto ist verboten.
            vault_ansible_user = _vault_ansible_user_for_host(
                args.project, args.host, vault_file
            )
            try:
                kerberos_principal = _kerberos_principal_for_host(
                    windows,
                    host_data,
                    settings,
                    vault_ansible_user=vault_ansible_user,
                )
            except ValueError:
                raise principal_error

        print("\nMavi WINRM HTTPS + KERBEROS-ONLY")
        print("================================")
        print(f"Host:              {args.host}")
        print(f"SSH-Umbaukanal:    {host_data.get('ansible_host', args.host)}")
        print(f"WinRM-FQDN:        {identity['fqdn']}")
        print("PSRP-Endzustand:   HTTPS:5986 / Zertifikatsprüfung / Kerberos-only")
        print(f"Kerberos-Principal:{kerberos_principal}")
        print(f"KDC-Bindung:       {', '.join(kdc_endpoints)} (direkt aus AD-DNS)")
        print(f"TCP/5986 nur von:  {bootstrap['ansible_server_ip']}")
        print("HTTP/5985:         wird per SSH entfernt; es gibt keinen NTLM-Rückweg.")

        bootstrap_probe_output = _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_bootstrap_ca_probe_play(
                current_root_certificate_der_base64=current_bootstrap_certificate,
                candidate_root_certificates_der_base64=bootstrap_probe_candidates,
            ),
            vault_password_file=vault_file,
            description="Hostgebundener Bootstrap-CA-Nachweis über SSH",
        )
        bootstrap_probe_result = _extract_bootstrap_ca_probe_result(
            bootstrap_probe_output
        )
        if bootstrap_probe_result["current_root_thumbprint"] != current_bootstrap_thumbprint:
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Zielhost bestätigt nicht die aktuell veröffentlichte "
                "Mavi-Bootstrap-CA."
            )
        unexpected_bootstrap_roots = set(
            bootstrap_probe_result["present_root_thumbprints"]
        ) - set(controller_bootstrap_certificates)
        if unexpected_bootstrap_roots:
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Zielhost meldet eine Bootstrap-CA, die nicht "
                "durch DER-Material auf dem Controller gebunden ist."
            )

        request_id = secrets.token_hex(16)
        csr_output = _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_winrm_csr_play(identity=identity, request_id=request_id),
            vault_password_file=vault_file,
            description="WinRM-CSR-Erzeugung über SSH",
        )
        csr_pem = _extract_winrm_csr(csr_output)
        issued = _issue_winrm_server_certificate(
            args.project,
            host=args.host,
            identity=identity,
            csr_pem=csr_pem,
        )
        install_output = _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_winrm_install_https_play(
                certificate_path=str(issued["cert_der"]),
                certificate_sha256=str(issued["cert_sha256"]),
                ca_certificate_path=str(issued["ca_der"]),
                ca_certificate_sha256=str(issued["ca_der_sha256"]),
                identity=identity,
                settings=settings,
                ansible_server_ip=bootstrap["ansible_server_ip"],
            ),
            vault_password_file=vault_file,
            description="WinRM-HTTPS-Installation über SSH",
        )
        install_result = _extract_winrm_https_install_result(install_output)
        expected_root_thumbprint = _certificate_thumbprint_from_file(Path(issued["ca_der"]))
        if not secrets.compare_digest(
            install_result["certificate_sha256"],
            str(issued["cert_sha256"]).strip().lower(),
        ):
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Windows-Abschlussbeleg gehört nicht zum gerade signierten "
                "Mavi-WinRM-Serverzertifikat."
            )
        if (
            install_result["fqdn"] != str(identity["fqdn"]).lower()
            or install_result["port"] != int(settings["port"])
            or install_result["root_thumbprint"] != expected_root_thumbprint
        ):
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Windows-Abschlussbeleg stimmt nicht mit dem erwarteten "
                "Mavi-WinRM-Endpunkt bzw. der Mavi-Root-CA überein."
            )

        # HTTP/5985 wird bereits innerhalb derselben abgeschotteten Windows-
        # Transaktion entfernt, bevor Negotiate endgültig deaktiviert wird.
        # Ein nachträglicher WSMan:\localhost-Aufruf wäre bei Kerberos-only
        # absichtlich nicht mehr möglich.
        secure_vars = _psrp_https_inventory_vars(
            settings,
            fqdn=identity["fqdn"],
            ca_cert=Path(issued["ca_cert"]),
        )
        secure_vars["ansible_user"] = kerberos_principal
        try:
            _run_winrm_temporary_play(
                args.project,
                host=args.host,
                play=_winrm_kerberos_https_ping_play(),
                vault_password_file=vault_file,
                description="Erster Kerberos-HTTPS-Nachweis",
                extra_vars=secure_vars,
                use_vault_kerberos_ticket=True,
                kerberos_principal=kerberos_principal,
                kerberos_target_fqdn=identity["fqdn"],
            )
        except RuntimeError as first_probe_error:
            if not _is_missing_gssapi_failure(first_probe_error):
                raise
            print(
                "\n! GSSAPI fehlt im tatsächlichen Ansible-Worker; Mavi repariert "
                "die pipx-Umgebung und wiederholt den Nachweis einmalig."
            )
            _ensure_psrp_kerberos_controller_dependencies(force_pipx_inject=True)
            _run_winrm_temporary_play(
                args.project,
                host=args.host,
                play=_winrm_kerberos_https_ping_play(),
                vault_password_file=vault_file,
                description="Erster Kerberos-HTTPS-Nachweis nach GSSAPI-Reparatur",
                extra_vars=secure_vars,
                use_vault_kerberos_ticket=True,
                kerberos_principal=kerberos_principal,
                kerberos_target_fqdn=identity["fqdn"],
            )
        _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_winrm_kerberos_https_ping_play(),
            vault_password_file=vault_file,
            description="Zweiter Kerberos-HTTPS-Nachweis",
            extra_vars=secure_vars,
            use_vault_kerberos_ticket=True,
            kerberos_principal=kerberos_principal,
            kerberos_target_fqdn=identity["fqdn"],
        )
        removed_controller_artifacts, artifact_warnings = _remove_host_winrm_certificate_artifacts(
            args.project,
            args.host,
            keep_request_id=str(issued["request_id"]),
            known_hosts=(windows.get("hosts", {}) or {}).keys(),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print("\nSICHERHEITSABBRUCH: WinRM wurde nicht als Mavi-Transport übernommen.")
        print(redact_sensitive_text(exc))
        print("Der Inventory-Host bleibt auf SSH. HTTP/5985 wird von Mavi nicht erneut aktiviert.")
        raise SystemExit(2)
    finally:
        vault_file.unlink(missing_ok=True)

    # Erst die direkte Windows-Abfrage über die funktionierende SSH-Sitzung
    # bindet Bootstrap-Identitäten an diesen Host. Frühere, nur aufgrund von
    # Webserver-Probes erzeugte v1-Einträge werden dabei nicht blind vertraut;
    # sie wandern nur dann in die Historie, wenn Windows sie exakt bestätigt.
    host_data["mavi_bootstrap"] = {
        "version": 2,
        "remote_verified": True,
        "instance_id": bootstrap["instance_id"],
        "root_thumbprint": bootstrap_probe_result["current_root_thumbprint"],
        "root_thumbprints": bootstrap_probe_result["present_root_thumbprints"],
        "ca_sha256": current_bootstrap_ca_sha256,
        "verified_at": _utc_now_iso(),
    }
    _remember_winrm_https_state(
        host_data,
        settings=settings,
        fqdn=identity["fqdn"],
        ca_cert=Path(issued["ca_cert"]),
        kerberos_principal=kerberos_principal,
        certificate_thumbprint=install_result["thumbprint"],
        certificate_not_after=install_result["certificate_not_after"],
        root_thumbprint=install_result["root_thumbprint"],
        root_not_after=install_result["root_not_after"],
        pruned_server_certificates=install_result["pruned_server_certificates"],
    )
    _apply_psrp_https_transport(
        host_data,
        settings=settings,
        fqdn=identity["fqdn"],
        ca_cert=Path(issued["ca_cert"]),
        kerberos_principal=kerberos_principal,
    )
    atomic_write_yaml(project_paths(args.project)["inventory"], inv)

    print("\n✓ WinRM-HTTPS/Kerberos-only ist einsatzbereit.")
    print("  HTTP/5985:        entfernt und zugehörige TCP/5985-Freigaben deaktiviert")
    print("  PSRP:             HTTPS:5986, Zertifikat validiert, Kerberos-only")
    print(f"  Inventory-Host:   {args.host} wurde dauerhaft auf sicheren PSRP umgestellt")
    print(f"  SSH:              bleibt installiert und aktiv als separater Verwaltungsweg")
    print(f"  Leaf-Thumbprint:  {install_result['thumbprint']}")
    print(f"  Leaf-Ablauf:      {install_result['certificate_not_after']}")
    print(f"  Alte Leaf-Zertifikate auf Windows: {install_result['pruned_server_certificates']} entfernt")
    print(f"  Alte Host-PKI-Dateien auf Controller: {removed_controller_artifacts} entfernt")
    for warning in artifact_warnings:
        print(f"! {warning}")


def _winrm_reset_root_identity(
    winrm_state: Any,
    *,
    ca_cert: Path,
    ca_der: Path,
) -> tuple[str, str]:
    """Exakte Root-Identität für den Rückbau bestimmen, v1-Hashes inklusive."""
    from .openssh import (
        _sha256_file,
    )

    from .remote import (
        _certificate_der_base64_from_file,
        _certificate_thumbprint_from_file,
        _normalized_certificate_thumbprint,
    )

    state = winrm_state if isinstance(winrm_state, dict) else None
    stored_root_thumbprint = (
        _normalized_certificate_thumbprint(state.get("root_thumbprint"))
        if state is not None
        else ""
    )
    if not ca_der.is_file():
        if stored_root_thumbprint:
            raise ValueError(
                "Für die gespeicherte Mavi-WinRM-Root fehlt das controllerseitige DER; "
                "ein Inventory-Thumbprint allein ist keine Löschberechtigung."
            )
        return "", ""

    controller_root_thumbprint = _certificate_thumbprint_from_file(ca_der)
    if stored_root_thumbprint and controller_root_thumbprint != stored_root_thumbprint:
        raise ValueError(
            "Die gespeicherte historische Mavi-WinRM-Root stimmt nicht mit dem "
            "controllerseitigen DER überein; ein Thumbprint allein darf keine Root löschen."
        )

    if state is not None and not stored_root_thumbprint:
        # v1 kannte noch keinen Root-Thumbprint. Sein Hash bezog sich auf die
        # PEM-Datei der Controller-CA. Nur ein exakter Hash-Treffer darf diese
        # alte Aufzeichnung auf die heutige Thumbprint-Identität hochstufen.
        expected_hash = str(state.get("ca_sha256", "") or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or not ca_cert.is_file():
            raise ValueError(
                "Der alte Mavi-WinRM-Status enthält keine prüfbare Root-CA-Identität; "
                "der sichere Rückbau wird verweigert."
            )
        actual_hash = _sha256_file(ca_cert).lower()
        if not secrets.compare_digest(expected_hash, actual_hash):
            raise ValueError(
                "Die lokale Mavi-WinRM-CA stimmt nicht mit dem gespeicherten v1-CA-Hash "
                "dieses Hosts überein; der sichere Rückbau wird verweigert."
            )
        if _certificate_thumbprint_from_file(ca_cert) != controller_root_thumbprint:
            raise ValueError(
                "PEM- und DER-Datei der lokalen Mavi-WinRM-CA bezeichnen nicht dieselbe Root; "
                "der sichere Rückbau wird verweigert."
            )

    return (
        controller_root_thumbprint,
        _certificate_der_base64_from_file(ca_der),
    )


def _winrm_leaf_fqdn_for_host(
    project: Path,
    host: str,
    host_data: dict[str, Any],
) -> str:
    """Den hostgebundenen FQDN für Mavi-WinRM-Leaves bestimmen.

    Ein gespeicherter, bereits geprüfter Endpunkt hat beim Rückbau Vorrang:
    Eine zwischenzeitlich geänderte globale Domänenkonfiguration darf den
    Lösch-Scope nicht auf einen anderen Hostnamen verschieben.
    """
    from .remote import (
        _normalize_winrm_dns_name,
        _winrm_https_settings,
        _winrm_https_target_identity,
    )

    state = host_data.get("mavi_winrm_https")
    if isinstance(state, dict):
        saved_fqdn = str(state.get("fqdn", "") or "").strip()
        if saved_fqdn:
            return _normalize_winrm_dns_name(
                saved_fqdn,
                label="gespeicherter WinRM-FQDN",
            )

    settings = _winrm_https_settings(project)
    identity = _winrm_https_target_identity(host, host_data, settings)
    return str(identity["fqdn"])


def _bootstrap_state_thumbprints(state: Any) -> tuple[str, ...]:
    """Exakte, deduplizierte Thumbprints aus einem Bootstrap-Status lesen."""
    from .remote import _normalized_certificate_thumbprint

    if not isinstance(state, dict):
        return ()
    raw_values = state.get("root_thumbprints")
    if not isinstance(raw_values, list):
        raw_values = []
    values = [state.get("root_thumbprint"), *raw_values]
    normalized: list[str] = []
    for value in values:
        thumbprint = _normalized_certificate_thumbprint(value)
        if thumbprint and thumbprint not in normalized:
            normalized.append(thumbprint)
    return tuple(normalized)


def _verified_bootstrap_root_thumbprints(host_data: dict[str, Any]) -> tuple[str, ...]:
    """Nur vom Zielhost selbst bestätigte Bootstrap-Identitäten akzeptieren."""

    from .openssh import (
        _bootstrap_state_thumbprints,
    )

    state = host_data.get("mavi_bootstrap")
    if not isinstance(state, dict):
        return ()
    try:
        version = int(state.get("version", 1))
    except (TypeError, ValueError):
        version = 1
    if version < 2 or state.get("remote_verified") is not True:
        return ()
    return _bootstrap_state_thumbprints(state)


def cmd_ssh_winrm_reset(args: argparse.Namespace) -> None:
    """WinRM auf Stand 0 setzen und OpenSSH auf Wunsch als letzten Kanal abschalten."""

    from .openssh import (
        _openssh_artifact_instance_id,
        _openssh_config_backup_relative_path,
        _openssh_firewall_rule_name,
    )
    from .openssh import (
        _bootstrap_state_thumbprints,
        _controller_bound_bootstrap_root_certificates,
        _public_key_prefix_for_private_key,
        _ssh_host_key_port,
        _ssh_private_key_path_for_host,
        _verified_bootstrap_root_thumbprints,
        _winrm_leaf_fqdn_for_host,
        _winrm_reset_root_identity,
        cmd_ssh_use,
    )


    from .catalogs import yes_no
    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )
    from .execution import create_temporary_vault_password_file
    from .remote import (
        _apply_remote_management_disabled_transport,
        _apply_ssh_transport,
        _bootstrap_ca_probe_play,
        _effective_host_var,
        _extract_bootstrap_ca_probe_result,
        _extract_winrm_reset_result,
        _host_inventory_entry,
        _remove_host_bootstrap_artifacts,
        _remove_host_winrm_certificate_artifacts,
        _run_winrm_temporary_play,
        _ssh_environment_marker,
        _utc_now_iso,
        _winrm_pki_paths,
        _winrm_reset_play,
        get_ssh_settings,
    )
    from .reports import redact_sensitive_text
    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    disable_openssh = bool(getattr(args, "disable_openssh", False))
    had_winrm_https_state = isinstance(host_data.get("mavi_winrm_https"), dict)
    connection = str(
        _effective_host_var(windows, host_data, "ansible_connection", "") or ""
    ).lower()

    if not bool(getattr(args, "yes", False)):
        print("\nMavi REMOTE-VERWALTUNG ZURÜCKSETZEN")
        print("====================================")
        print(f"PC:       {args.host}")
        print("WinRM:    nur eindeutig Mavi-Listener, -Regeln, -Zertifikate und Arbeitsdateien entfernen")
        print("           Dienst anschließend stoppen und deaktivieren")
        if disable_openssh:
            print("OpenSSH:  Mavi-Key entfernen, Mavi-Firewallregel entfernen, sshd stoppen/deaktivieren")
            print("CA:       Mavi Bootstrap Root CA nur bei bytegleichem Controller-DER entfernen")
            print("! Danach gibt es keinen Mavi-Fernzugang mehr. Neueinrichtung nur lokal per Starter.")
        else:
            print("OpenSSH:  bleibt als sofortiger Weg für eine neue WinRM-Einrichtung aktiv")
        if not yes_no("Diesen Stand-0-Rückbau wirklich ausführen?", default=False):
            print("Abgebrochen.")
            return

    requested_key = getattr(args, "key", None)
    requested_port = getattr(args, "port", None)
    if connection != "ssh" and not str(requested_key or "").strip():
        remembered_key = str(
            host_data.get("mavi_ssh_private_key_file", "") or ""
        ).strip()
        if remembered_key:
            requested_key = remembered_key
    if connection != "ssh" and requested_port is None:
        remembered_port = host_data.get("mavi_ssh_port")
        try:
            remembered_port = int(remembered_port)
        except (TypeError, ValueError):
            remembered_port = 0
        if not 1 <= remembered_port <= 65535:
            die(
                f"Für den bestehenden PSRP-/WinRM-Host {args.host} ist kein verlässlicher "
                "historischer SSH-Port gespeichert. Bitte den tatsächlich erreichbaren Port "
                "einmal explizit mit --port angeben; Mavi rät nicht den globalen Standard: "
                f"mavi-provisioner ssh winrm-reset {args.host} --port PORT"
            )
        requested_port = remembered_port
    if connection != "ssh" or requested_key is not None or requested_port is not None:
        resolved_port = requested_port
        if resolved_port is None:
            resolved_port = _ssh_host_key_port(
                windows,
                host_data,
                get_ssh_settings(args.project)["port"],
            )
        if connection != "ssh":
            print(f"\n{args.host} wird zuerst über den vorhandenen Mavi-Key auf OpenSSH umgestellt.")
        cmd_ssh_use(
            argparse.Namespace(
                project=args.project,
                host=args.host,
                key=requested_key,
                port=resolved_port,
                yes=bool(getattr(args, "yes", False)),
            )
        )
        inv, windows, host_data = _host_inventory_entry(args.project, args.host)

    reset_public_key_prefix = ""
    reset_key_marker = ""
    openssh_firewall_rule = ""
    openssh_config_backup = ""
    bootstrap_root_thumbprints: tuple[str, ...] = ()
    bootstrap_root_certificates: tuple[str, ...] = ()
    bootstrap_probe_current_certificate = ""
    bootstrap_probe_candidates: tuple[str, ...] = ()
    controller_bootstrap_certificates: dict[str, str] = {}
    current_bootstrap_thumbprint = ""
    if disable_openssh:
        try:
            (
                current_bootstrap_thumbprint,
                controller_bootstrap_certificates,
            ) = _controller_bound_bootstrap_root_certificates(project=args.project)
        except (OSError, ValueError) as exc:
            die(
                "Für den vollständigen Rückbau ist kein vertrauenswürdiger controllerseitiger "
                "Bootstrap-CA-Satz verfügbar: " + redact_sensitive_text(exc)
            )
        bootstrap_probe_current_certificate = controller_bootstrap_certificates[
            current_bootstrap_thumbprint
        ]
        bootstrap_probe_candidates = tuple(
            controller_bootstrap_certificates.values()
        )
        stored_bootstrap_thumbprints = _bootstrap_state_thumbprints(
            host_data.get("mavi_bootstrap")
        )
        verified_bootstrap_thumbprints = _verified_bootstrap_root_thumbprints(
            host_data
        )
        if (
            stored_bootstrap_thumbprints
            and verified_bootstrap_thumbprints != stored_bootstrap_thumbprints
        ):
            die(
                "Der gespeicherte Bootstrap-CA-Verlauf ist nicht als v2-Remote-Nachweis "
                "verifiziert und kann keinen vollständigen Lösch-Scope belegen."
            )
        unbound_bootstrap_thumbprints = set(
            verified_bootstrap_thumbprints
        ) - set(controller_bootstrap_certificates)
        if unbound_bootstrap_thumbprints:
            die(
                "Für mindestens eine vom Host bestätigte historische Bootstrap-CA fehlt "
                "das exakte DER im root-kontrollierten Controller-Archiv; Option 11 "
                "schreibt deshalb keinen unvollständigen Rückbau-Nachweis."
            )

    if disable_openssh:
        active_key_path = _ssh_private_key_path_for_host(
            args.project,
            windows,
            host_data,
        )
        reset_public_key_prefix = _public_key_prefix_for_private_key(active_key_path)
        if not reset_public_key_prefix:
            die(
                "Der aktive SSH-Public-Key kann weder aus der Companion-.pub-Datei "
                "gelesen noch mit ssh-keygen -y aus dem privaten Key abgeleitet werden. "
                "Der vollständige Remote-Rückbau wird ohne exakte Key-Identität nicht attestiert."
            )
        reset_key_marker = _ssh_environment_marker(args.project)
        try:
            openssh_artifact_instance_id = _openssh_artifact_instance_id(
                args.project,
                host_data,
            )
            openssh_firewall_rule = _openssh_firewall_rule_name(
                args.project,
                instance_id=openssh_artifact_instance_id,
            )
            openssh_config_backup = _openssh_config_backup_relative_path(
                args.project,
                instance_id=openssh_artifact_instance_id,
            )
        except ValueError as exc:
            die(
                "Der vollständige Rückbau kann den instanzgebundenen Mavi-OpenSSH-Scope "
                "nicht sicher bestimmen: " + redact_sensitive_text(exc)
            )

    winrm_state = host_data.get("mavi_winrm_https")
    pki_paths = _winrm_pki_paths(args.project)
    try:
        root_thumbprint, root_certificate_der_base64 = _winrm_reset_root_identity(
            winrm_state,
            ca_cert=pki_paths["ca_cert"],
            ca_der=pki_paths["ca_der"],
        )
    except (OSError, ValueError) as exc:
        die(
            "Die lokale Mavi-WinRM-CA konnte nicht sicher dem gespeicherten Host-Status "
            f"zugeordnet werden: {redact_sensitive_text(exc)}"
        )
    if had_winrm_https_state and not root_thumbprint:
        die(
            "Die zu diesem PC gespeicherte Mavi-WinRM-Verwaltung kann ohne die exakte "
            "Mavi-WinRM-Root-CA nicht sicher zurückgebaut werden. "
            "Mavi rät hier weder per Subject noch löscht es pauschal Zertifikate."
        )
    if disable_openssh and not root_thumbprint:
        die(
            "Der vollständige Option-11-Rückbau benötigt die exakte Mavi-WinRM-Root-Identität. "
            "Ein leerer WinRM-Listener-Bestand beweist nicht, dass keine verwaisten Mavi-"
            "Zertifikate mehr vorhanden sind; deshalb wird kein v3-Vollnachweis erzeugt."
        )
    expected_winrm_fqdn = ""
    if root_thumbprint:
        try:
            expected_winrm_fqdn = _winrm_leaf_fqdn_for_host(
                args.project,
                args.host,
                host_data,
            )
        except (OSError, ValueError) as exc:
            die(
                "Der Mavi-WinRM-Ziel-FQDN für den Zertifikats-Rückbau ist nicht "
                f"verlässlich bestimmbar: {redact_sensitive_text(exc)}"
            )

    vault_file: Path | None = None
    vault_password = getpass.getpass("Vault password: ")
    try:
        vault_file = create_temporary_vault_password_file(vault_password)
    except OSError as exc:
        die(f"Temporäre Vault-Datei konnte nicht sicher angelegt werden: {exc}")
    finally:
        vault_password = ""

    try:
        print("\nRückbau läuft über OpenSSH; das Ergebnis erscheint nach Abschluss (maximal 180 Sekunden).")
        if disable_openssh:
            bootstrap_probe_output = _run_winrm_temporary_play(
                args.project,
                host=args.host,
                play=_bootstrap_ca_probe_play(
                    current_root_certificate_der_base64=(
                        bootstrap_probe_current_certificate
                    ),
                    candidate_root_certificates_der_base64=list(
                        bootstrap_probe_candidates
                    ),
                    require_current_root=False,
                ),
                vault_password_file=vault_file,
                description="Live-Nachweis des Bootstrap-Lösch-Scope über SSH",
            )
            bootstrap_probe_result = _extract_bootstrap_ca_probe_result(
                bootstrap_probe_output,
                require_current_root=False,
            )
            if (
                bootstrap_probe_result["current_root_thumbprint"]
                != current_bootstrap_thumbprint
            ):
                raise RuntimeError(
                    "Der Bootstrap-Nachweis gehört nicht zur aktuellen controllerseitigen CA."
                )
            bootstrap_root_thumbprints = tuple(
                bootstrap_probe_result["present_root_thumbprints"]
            )
            unexpected_bootstrap_roots = set(bootstrap_root_thumbprints) - set(
                controller_bootstrap_certificates
            )
            if unexpected_bootstrap_roots:
                raise RuntimeError(
                    "Der Bootstrap-Nachweis enthält eine nicht durch Controller-DER "
                    "gebundene Root-CA."
                )
            bootstrap_root_certificates = tuple(
                controller_bootstrap_certificates[thumbprint]
                for thumbprint in bootstrap_root_thumbprints
            )
        reset_output = _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_winrm_reset_play(
                root_thumbprint=root_thumbprint,
                root_certificate_der_base64=root_certificate_der_base64,
                expected_fqdn=expected_winrm_fqdn,
                bootstrap_root_certificates_der_base64=list(
                    bootstrap_root_certificates
                ),
                disable_openssh=disable_openssh,
                public_key_prefix=reset_public_key_prefix,
                key_marker=reset_key_marker,
                openssh_firewall_rule=openssh_firewall_rule,
                openssh_config_backup=openssh_config_backup,
            ),
            vault_password_file=vault_file,
            description=(
                "WinRM/Kerberos- und OpenSSH-Rückbau über SSH"
                if disable_openssh
                else "WinRM/Kerberos-Stand-0-Rückbau über SSH"
            ),
            timeout=180.0,
        )
        reset_result = _extract_winrm_reset_result(reset_output)
        if root_thumbprint and reset_result["winrm_root_thumbprint"] != root_thumbprint:
            raise RuntimeError(
                "Der Mavi-Rückbau-Nachweis bestätigt nicht die erwartete Mavi-WinRM-Root-CA."
            )
        if disable_openssh:
            if (
                tuple(reset_result["bootstrap_root_thumbprints"])
                != bootstrap_root_thumbprints
                or not reset_result["bootstrap_scope_verified"]
                or not reset_result["openssh_startup_disabled"]
                or not reset_result["openssh_disable_scheduled"]
                or not reset_result["openssh_stopped_verified"]
                or reset_result["openssh_state"].casefold() != "stopped"
                or reset_result["openssh_start_mode"].casefold() != "disabled"
                or not reset_result["winrm_scope_verified"]
                or not reset_result["winrm_listeners_cleared"]
            ):
                raise RuntimeError(
                    "Der Mavi-Rückbau-Nachweis bestätigt Bootstrap-CA, leeren WinRM-Listener-"
                    "Bestand oder den gestoppten/deaktivierten sshd nicht vollständig."
                )
    except (OSError, RuntimeError, ValueError) as exc:
        print("\nFEHLER: Der Remote-Rückbau wurde nicht vollständig bestätigt.")
        print(redact_sensitive_text(exc))
        print(f"Der Inventory-Host {args.host} bleibt für die Reparatur auf OpenSSH eingestellt.")
        raise SystemExit(2)
    finally:
        if vault_file is not None:
            vault_file.unlink(missing_ok=True)

    removed_artifacts, artifact_warnings = _remove_host_winrm_certificate_artifacts(
        args.project,
        args.host,
        known_hosts=(windows.get("hosts", {}) or {}).keys(),
    )
    removed_bootstrap_artifacts = 0
    bootstrap_artifact_warnings: list[str] = []
    if disable_openssh:
        removed_bootstrap_artifacts, bootstrap_artifact_warnings = _remove_host_bootstrap_artifacts(
            args.project,
            args.host,
            known_hosts=(windows.get("hosts", {}) or {}).keys(),
        )

    # Der Inventory-Nachweis wird bewusst erst nach dem vollständigen Remote-
    # Ergebnis und den ausschließlich hostbezogenen Controller-Bereinigungen
    # geschrieben. Ein unterbrochener Rückbau erhält daher nie den Status
    # "vollständig aus".
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    current_key_raw = str(
        _effective_host_var(windows, host_data, "ansible_ssh_private_key_file", "") or ""
    ).strip()
    current_port_raw = _effective_host_var(windows, host_data, "ansible_port", None)
    try:
        current_port = int(current_port_raw) if current_port_raw is not None else None
    except (TypeError, ValueError):
        current_port = None
    host_data.pop("mavi_winrm_https", None)
    host_data.pop("mavi_winrm_fqdn", None)
    if disable_openssh:
        # Nur die historischen Werte für einen späteren, expliziten
        # `ssh use`-Schritt behalten. Sie sind keine aktiven Ansible-Variablen.
        if current_key_raw:
            host_data["mavi_ssh_private_key_file"] = str(
                Path(current_key_raw).expanduser().resolve()
            )
        if current_port is not None and 1 <= current_port <= 65535:
            host_data["mavi_ssh_port"] = current_port
        _apply_remote_management_disabled_transport(host_data)

        all_controller_warnings = [*artifact_warnings, *bootstrap_artifact_warnings]
        remote_cleanup_verified = (
            reset_result["winrm_scope_verified"]
            and reset_result["winrm_listeners_cleared"]
            and reset_result["bootstrap_scope_verified"]
            and reset_result["openssh_startup_disabled"]
            and reset_result["openssh_stopped_verified"]
            and reset_result["openssh_state"].casefold() == "stopped"
            and reset_result["openssh_start_mode"].casefold() == "disabled"
        )
        host_data["mavi_remote_management_disabled"] = {
            "version": 3,
            "recorded_at": _utc_now_iso(),
            "winrm": True,
            "openssh": True,
            "remote_cleanup_verified": remote_cleanup_verified,
            "winrm_scope_verified": reset_result["winrm_scope_verified"],
            "winrm_listeners_cleared": reset_result["winrm_listeners_cleared"],
            "bootstrap_scope_verified": reset_result["bootstrap_scope_verified"],
            "openssh_stopped_verified": reset_result["openssh_stopped_verified"],
            "controller_cleanup_complete": not all_controller_warnings,
            "bootstrap_ca_thumbprint": bootstrap_root_thumbprints[0],
            "bootstrap_ca_thumbprints": list(bootstrap_root_thumbprints),
            "winrm_root_thumbprint": reset_result["winrm_root_thumbprint"] or root_thumbprint,
            "result": {
                "removed_listeners": reset_result["removed_listeners"],
                "removed_certificates": reset_result["removed_certificates"],
                "removed_firewall_rules": reset_result["removed_firewall_rules"],
                "removed_openssh_firewall_rules": reset_result["removed_openssh_firewall_rules"],
                "removed_openssh_keys": reset_result["removed_openssh_keys"],
                "removed_openssh_config_backups": reset_result[
                    "removed_openssh_config_backups"
                ],
                "removed_bootstrap_certificates": reset_result["removed_bootstrap_certificates"],
                "openssh_state": reset_result["openssh_state"],
                "openssh_start_mode": reset_result["openssh_start_mode"],
                "preserved_foreign_winrm_listeners": reset_result[
                    "preserved_foreign_winrm_listeners"
                ],
            },
        }
        if not bootstrap_artifact_warnings:
            host_data.pop("mavi_bootstrap", None)
    else:
        _apply_ssh_transport(
            args.project,
            host_data,
            key_path=Path(current_key_raw).expanduser() if current_key_raw else None,
            port=current_port,
        )
    atomic_write_yaml(project_paths(args.project)["inventory"], inv)

    print("\n✓ Remote-Verwaltungszustand wurde zurückgesetzt.")
    if reset_result["winrm_scope_verified"]:
        print("  WinRM:            Mavi-Listener entfernt, Dienst gestoppt und deaktiviert")
    else:
        print("  WinRM:            Dienst gestoppt und deaktiviert; Mavi-CA war nicht exakt belegbar")
        print("! Mavi hat deshalb keine Zertifikate oder Listener nur anhand ihres Namens gelöscht.")
    if reset_result["preserved_foreign_winrm_listeners"]:
        print(
            "  Fremde WinRM-Listener: "
            f"{reset_result['preserved_foreign_winrm_listeners']} erhalten (WinRM bleibt deaktiviert)"
        )
    print("  Kerberos/PSRP:    gespeicherter Hoststatus entfernt; kein persistenter Mavi-Ticketcache")
    print(f"  Host-PKI-Dateien: {removed_artifacts} Datei(en) auf dem Controller entfernt")
    print("  Gemeinsame CAs:   bleiben auf dem Controller für andere Windows-PCs erhalten")
    if disable_openssh:
        print(
            "  Bootstrap-CA:     "
            f"{reset_result['removed_bootstrap_certificates']} exakt passende CA-Kopie(n) auf Windows entfernt"
        )
        print(f"  Bootstrap-Dateien:{removed_bootstrap_artifacts} hostbezogene Datei(en) auf dem Controller entfernt")
        print(
            "  OpenSSH:          Mavi-Key/-Regel und Mavi-Konfigurationssicherung entfernt; "
            "sshd ist nachweislich gestoppt und deaktiviert"
        )
        print("  Fernzugang:       vollständig aus; OpenSSH bleibt lediglich installiert")
        print("\nFür eine spätere Neueinrichtung zuerst den Mavi-OpenSSH-Starter lokal am PC ausführen.")
        print(f"Danach: mavi-provisioner ssh use {args.host}")
    else:
        print("  OpenSSH:          bleibt installiert und aktiv")
        print(f"\nWinRM neu einrichten mit: mavi-provisioner ssh winrm-https {args.host}")
    for warning in artifact_warnings:
        print(f"! {warning}")
    for warning in bootstrap_artifact_warnings:
        print(f"! {warning}")


def cmd_ssh_use_psrp(args: argparse.Namespace) -> None:
    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )
    from .remote import (
        _apply_saved_winrm_https_transport,
        _effective_host_var,
        _host_inventory_entry,
    )

    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    try:
        _apply_saved_winrm_https_transport(args.project, host_data)
    except ValueError as exc:
        die(str(exc))
    atomic_write_yaml(project_paths(args.project)["inventory"], inv)
    user = _effective_host_var(windows, host_data, "ansible_user", "(geerbt)")
    print(f"✓ {args.host} auf gespeichertes PSRP/WinRM HTTPS/Kerberos zurückgestellt.")
    print("  Verbindung: psrp:5986 / HTTPS / Kerberos-only")
    print(f"  Benutzer:   {user}")
