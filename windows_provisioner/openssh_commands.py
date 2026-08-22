# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""OpenSSH-Prüf- und Aktivierungsbefehle.

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



# Der alte temporäre Share-/HTTP-Bootstrap bleibt vollständig entfernt. Der
# geprüfte Nutzinhalt liegt im festen HTTPS-Webroot. Der All-in-one-Erststarter
# wird immer als lokale Datei erzeugt, damit ein Administrator ihn gezielt in
# einen Mavi-Release-Ordner legen kann. Er enthält nur die öffentliche CA und
# feste Hashes, kopiert sich vor UAC nach TEMP und benötigt im Admin-Kontext
# kein SMB oder WinRM.


def _local_windows_authenticode_status(
    msi_path: Path,
    *,
    expected_signer: str = "",
) -> tuple[str, str]:
    """Best-effort-Diagnose; der Windows-Bootstrap erzwingt die definitive Prüfung."""
    from .openssh import (
        _powershell_single_quote,
    )

    from .reports import redact_sensitive_text

    if os.name != "nt":
        return (
            "DEFERRED",
            "Definitive Windows-Authenticode-Prüfung erfolgt vor msiexec auf dem Ziel-PC.",
        )
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return "UNKNOWN", "Windows PowerShell wurde für die lokale Diagnose nicht gefunden."
    ps_path = _powershell_single_quote(str(msi_path.resolve()))
    script = (
        "$ErrorActionPreference='Stop';"
        f"$s=Get-AuthenticodeSignature -LiteralPath '{ps_path}';"
        "$subject=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''};"
        "$simple=if($s.SignerCertificate){[string]$s.SignerCertificate.GetNameInfo("
        "[System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)}else{''};"
        "[pscustomobject]@{Status=[string]$s.Status;Subject=$subject;SimpleName=$simple}|ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "UNKNOWN", redact_sensitive_text(str(exc))
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or f"Exit-Code {result.returncode}").strip()
        return "UNKNOWN", redact_sensitive_text(detail)
    try:
        data = json.loads(result.stdout.strip())
    except (ValueError, TypeError, json.JSONDecodeError):
        return "UNKNOWN", "Authenticode-Ausgabe war nicht lesbar."
    status = str(data.get("Status", "Unknown") or "Unknown")
    subject = str(data.get("Subject", "") or "")
    simple_name = str(data.get("SimpleName", "") or "")
    if status != "Valid":
        return status, f"Windows Authenticode ist {status}, erwartet wird Valid."
    if expected_signer and expected_signer.casefold() not in {subject.casefold(), simple_name.casefold()}:
        return "SIGNER_MISMATCH", f"Signer ist '{subject or simple_name}', erwartet '{expected_signer}'."
    return "Valid", f"Signer: {subject or simple_name}"


def cmd_ssh_setup_check(args: argparse.Namespace) -> None:
    """Fehlendes Server-Setup automatisch erledigen und danach diagnostizieren."""
    from .openssh import (
        _atomic_write_bytes,
        _bootstrap_pki_paths,
        _bootstrap_setup_instruction,
        _ensure_automatic_https_server,
        _local_windows_authenticode_status,
        _sha256_file,
        _software_local_and_windows_path,
        _strict_https_probe,
    )

    from .environment import ensure_initialized
    from .reports import redact_sensitive_text
    from .settings import VERSION

    ensure_initialized(args.project, quiet=True)
    print("\nMavi HTTPS-/OPENSSH-SETUP-CHECK")
    print("================================")
    try:
        settings = _ensure_automatic_https_server(args.project)
    except ValueError as exc:
        print(f"✗ Konfiguration: {redact_sensitive_text(exc)}")
        print(_bootstrap_setup_instruction(args.project, reason=str(exc)))
        raise SystemExit(2)

    print(f"✓ HTTPS-Basis-URL: {settings['base_url']}")
    print(f"✓ Webroot:         {settings['local_dir']}")
    print(f"✓ Ansible-IP:      {settings['ansible_server_ip']}")
    print(f"  Erwarteter MSI-Signer: {settings['expected_signer'] or '(nicht zusätzlich festgelegt)'}")

    webroot: Path = settings["local_dir"]
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    try:
        webroot.mkdir(parents=True, exist_ok=True)
        probe = webroot / ".mavi-setup-write-probe"
        _atomic_write_bytes(probe, b"write-ok\n", mode=0o600)
        probe.unlink()
        _atomic_write_bytes(webroot / "Mavi-SETUP-CHECK.txt", health_body)
        print("✓ Webroot ist schreibbar; Setup-Prüfdatei wurde veröffentlicht.")
    except OSError as exc:
        print(f"✗ Webroot ist nicht schreibbar: {redact_sensitive_text(exc)}")
        print(_bootstrap_setup_instruction(args.project, reason=str(exc)))
        raise SystemExit(2)

    health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
    https_ok, https_detail = _strict_https_probe(
        health_url,
        expected_body=health_body,
        trusted_ca=_bootstrap_pki_paths(args.project)["system_ca"],
    )
    print(f"{'✓' if https_ok else '✗'} HTTPS/Zertifikat: {redact_sensitive_text(https_detail)}")
    print(f"  Prüf-URL: {health_url}")

    msi_raw = str(getattr(args, "msi", None) or "").strip()
    msi_ok = True
    if msi_raw:
        local_msi, _, _ = _software_local_and_windows_path(args.project, msi_raw)
        if local_msi is None or not local_msi.is_file():
            msi_ok = False
            print(f"✗ MSI: lokal nicht erreichbar: {redact_sensitive_text(msi_raw)}")
        else:
            print(f"✓ MSI-Datei: {local_msi}")
            print(f"✓ MSI SHA-256: {_sha256_file(local_msi)}")
            auth_status, auth_detail = _local_windows_authenticode_status(
                local_msi,
                expected_signer=settings["expected_signer"],
            )
            marker = "✓" if auth_status in {"Valid", "DEFERRED"} else "✗"
            msi_ok = auth_status in {"Valid", "DEFERRED"}
            print(f"{marker} MSI Authenticode: {auth_status} — {redact_sensitive_text(auth_detail)}")
    else:
        print("- MSI: keine angegeben; Bootstrap nutzt Windows Capability/FoD.")

    if not https_ok or not msi_ok:
        print("\nSICHERHEITSABBRUCH: Das Setup ist noch nicht einsatzbereit; es gibt keinen unsicheren Fallback.")
        if not https_ok:
            print(_bootstrap_setup_instruction(args.project, reason=https_detail))
        raise SystemExit(2)
    print("\n✓ HTTPS-Bootstrap-Grundsetup ist einsatzbereit.")


def cmd_ssh_guide(args: argparse.Namespace) -> None:
    from .openssh import (
        _bootstrap_pki_paths,
        _bootstrap_setup_instruction,
        _ensure_automatic_https_server,
        _public_key_summary,
        _publish_https_ssh_bootstrap,
        _strict_https_probe,
        cmd_ssh_keygen,
    )

    from .environment import (
        die,
        ensure_initialized,
    )
    from .execution import shlex_quote
    from .remote import (
        _effective_host_var,
        _host_inventory_entry,
        get_ssh_settings,
    )
    from .reports import redact_sensitive_text

    ensure_initialized(args.project, quiet=True)
    try:
        _ensure_automatic_https_server(args.project)
    except ValueError as exc:
        print("\nSICHERHEITSABBRUCH: Die zentrale HTTPS-Konfiguration ist ungültig.")
        print(redact_sensitive_text(exc))
        raise SystemExit(2)

    settings = get_ssh_settings(args.project)
    key_path = Path(getattr(args, "key", None) or settings["private_key"]).expanduser().resolve()
    pub_path = Path(str(key_path) + ".pub")
    public_key, fingerprint = _public_key_summary(pub_path)

    if not public_key:
        print("\nMavi erzeugt den einmaligen SSH-Automationsschlüssel jetzt selbst.")
        cmd_ssh_keygen(
            argparse.Namespace(
                project=args.project,
                key=str(key_path),
                yes=True,
            )
        )
        public_key, fingerprint = _public_key_summary(pub_path)

    host = str(getattr(args, "host", None) or "WINDOWS").strip()
    host_ip = "<IP-DES-LAPTOPS>"
    ansible_user = r"<DOMÄNE\Provisioning-Admin>"
    if getattr(args, "host", None):
        _inventory, windows, host_data = _host_inventory_entry(args.project, host)
        host_ip = str(host_data.get("ansible_host", "") or host)
        ansible_user = str(
            _effective_host_var(windows, host_data, "ansible_user", ansible_user) or ansible_user
        )

    print("\nMavi OPENSSH-EINRICHTUNG FÜR WINDOWS")
    print("==================================")
    print(f"Host:         {host}")
    print(f"Ziel/IP:      {host_ip}")
    print(f"SSH-Benutzer: {ansible_user}")
    print(f"Private Key:  {key_path}")
    if fingerprint:
        print(f"Fingerprint:  {fingerprint}")
    if not public_key:
        die("Der automatisch erzeugte Mavi-Public-Key konnte nicht gelesen werden.")

    msi_raw = str(getattr(args, "msi", None) or "").strip()
    if bool(getattr(args, "prompt_msi", False)):
        print("\nOPENSSH-INSTALLATIONSQUELLE")
        print("===========================")
        print("Optional die OpenSSH-Win64-*.msi auf der Serverablage angeben.")
        print("Mavi veröffentlicht sie im festen HTTPS-Webroot und speichert ihren SHA-256.")
        print("Die vorhandene Herstellersignatur wird NICHT verändert; Windows verlangt Status Valid.")
        print("Enter = keine MSI, dann nutzt das Setup Windows Capability/FoD.")
        msi_raw = input("Pfad zur OpenSSH-Win64-*.msi [optional]: ").strip()

    try:
        package = _publish_https_ssh_bootstrap(
            args.project,
            host=host,
            public_key=public_key,
            msi_raw=msi_raw,
        )
    except (ValueError, FileNotFoundError, PermissionError, OSError, RuntimeError) as exc:
        print("\nSICHERHEITSABBRUCH: Die Vollautomatik konnte den Bootstrap nicht sicher veröffentlichen.")
        detail = redact_sensitive_text(exc)
        print(detail)
        raise SystemExit(2)

    trusted_ca = _bootstrap_pki_paths(args.project)["system_ca"]
    health_ok, health_detail = _strict_https_probe(
        package["health_url"],
        expected_body=package["health_body"].encode("ascii"),
        trusted_ca=trusted_ca,
    )
    launcher_path = Path(package["local_dir"]) / package["launcher"]
    launcher_ok, launcher_detail = _strict_https_probe(
        package["launcher_url"],
        expected_body=launcher_path.read_bytes(),
        trusted_ca=trusted_ca,
    )
    if not health_ok or not launcher_ok:
        failed_detail = health_detail if not health_ok else launcher_detail
        print("\nSICHERHEITSABBRUCH: HTTPS/Zertifikat oder veröffentlichter Inhalt ist nicht gültig.")
        print(_bootstrap_setup_instruction(args.project, reason=failed_detail))
        raise SystemExit(2)

    print("\n✓ Mavi OPENSSH-VOLLAUTOMATIK BEREIT")
    print("==================================")
    print("Starter-Datei:  " + package["offline_launcher"])
    print("Anzeigen:       cat " + shlex_quote(package["offline_launcher"]))
    print("Ablage:         Diese Datei einmal manuell in den Mavi-Release-Ordner kopieren.")
    print(f"HTTPS intern:   {package['launcher_url']}")
    print(f"Webroot:        {package['local_dir']}")
    print(f"Launcher SHA:   {package['launcher_sha256']}")
    print(f"Mavi-CA SHA:     {package['ca_der_sha256']} (im Starter fest eingebettet)")
    print(f"PS1 SHA-256:    {package['ps1_sha256']} (wird vor Ausführung geprüft)")
    print(f"Ansible-IP:     {package['ansible_server_ip']} (einzige erlaubte Quelle für TCP/22)")
    if package["msi_url"]:
        print(f"MSI über HTTPS: {package['msi_url']}")
        print(f"MSI SHA-256:    {package['msi_sha256']} (wird vor msiexec geprüft)")
        print(f"MSI Signatur:   Windows Authenticode muss Valid sein; Signer: {package['expected_signer'] or 'beliebiger gültiger Signer'}")
    else:
        print("MSI:             keine; Windows Capability/FoD wird verwendet.")

    print("\nAuf dem Laptop sind nur zwei Klicks nötig, nachdem die Datei im Release-Ordner liegt:")
    print(f"  1) {package['launcher']} doppelklicken")
    print("  2) UAC mit Ja bestätigen; CA, HTTPS und OpenSSH macht Mavi selbst")
    print("\nKein nginx-Setup, kein Zertifikatsimport und keine PSRP-/WinRM-Dateiverteilung.")
    print("Zertifikatsprüfung bleibt aktiv. Es gibt weder HTTP- noch Copy-Paste-Fallback.")
    print("Der private SSH-Key bleibt ausschließlich auf dem Ansible-Server.")
    print("sshd bleibt installiert und aktiv; nur die Mavi-Key-Entfernen-Funktion entfernt Keys.")
    print("\nDanach in Mavi: PC auf OpenSSH umstellen und Verbindung testen (win_ping).")

def cmd_ssh_use(args: argparse.Namespace) -> None:
    from .openssh import (
        _parse_ansible_core_version,
        ensure_ssh_host_key,
    )

    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )
    from .remote import (
        _apply_ssh_transport,
        _effective_host_var,
        _host_inventory_entry,
        get_ssh_settings,
    )

    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    settings = get_ssh_settings(args.project)
    key_path = Path(getattr(args, "key", None) or settings["private_key"]).expanduser().resolve()
    port = int(getattr(args, "port", None) or settings["port"] or 22)

    pub_path = Path(str(key_path) + ".pub")
    if not key_path.exists():
        die(
            f"SSH-Private-Key fehlt: {key_path}\n"
            "Zuerst 'mavi-provisioner ssh keygen' ausführen."
        )
    if not pub_path.exists():
        die(f"SSH-Public-Key fehlt: {pub_path}")

    target_host = str(host_data.get("ansible_host", "") or args.host)
    ensure_ssh_host_key(
        args.project,
        target_host,
        port=port,
        yes=bool(getattr(args, "yes", False)),
    )

    core_version = _parse_ansible_core_version()
    if core_version is not None and core_version < (2, 18, 0):
        print(
            f"! Hinweis: Ansible Core {'.'.join(map(str, core_version))} erkannt. "
            "Windows über SSH ist offiziell erst ab Ansible Core 2.18 unterstützt."
        )

    _apply_ssh_transport(args.project, host_data, key_path=key_path, port=port)
    atomic_write_yaml(project_paths(args.project)["inventory"], inv)

    user = _effective_host_var(windows, host_data, "ansible_user", "(geerbt)")
    print(f"✓ {args.host} auf OpenSSH umgestellt.")
    print(f"  Verbindung: ssh:{port}")
    print("  Shell:      powershell")
    print(f"  Benutzer:   {user}")
    print(f"  Key:        {key_path}")
    print(f"  known_hosts:{Path(settings['known_hosts']).expanduser().resolve()}")
    print("  Auth:       SSH-Key only (geerbtes PSRP-Passwort für SSH deaktiviert)")
    print("\nJetzt testen mit:")
    print(f"  mavi-provisioner ping {args.host}")
