# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""SSH-Schlüssel und known_hosts.

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


def _public_key_summary(pub_path: Path) -> tuple[str, str]:
    if not pub_path.exists():
        return "", ""
    public_key = pub_path.read_text(encoding="utf-8", errors="replace").strip()
    fingerprint = ""
    if public_key and shutil.which("ssh-keygen"):
        try:
            result = subprocess.run(
                ["ssh-keygen", "-lf", str(pub_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                fingerprint = result.stdout.strip()
        except OSError:
            pass
    return public_key, fingerprint


def _known_hosts_lookup_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def _known_host_present(known_hosts: Path, host: str, port: int) -> bool:
    from .openssh import (
        _known_hosts_lookup_name,
    )

    if not known_hosts.exists() or not shutil.which("ssh-keygen"):
        return False
    lookup = _known_hosts_lookup_name(host, port)
    try:
        result = subprocess.run(
            ["ssh-keygen", "-F", lookup, "-f", str(known_hosts)],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return result.returncode == 0 and bool((result.stdout or "").strip())


def _ssh_host_key_port(
    windows: dict[str, Any],
    host_data: dict[str, Any],
    configured_port: Any,
) -> int:
    """SSH-Port unabhängig vom derzeit aktiven Ansible-Transport bestimmen."""
    from .remote import _connection_label, _effective_host_var

    raw_port = host_data.get("mavi_ssh_port")
    if raw_port is None and _connection_label(windows, host_data) == "SSH":
        raw_port = _effective_host_var(windows, host_data, "ansible_port", None)
    if raw_port is None:
        raw_port = configured_port
    try:
        port = int(raw_port or 22)
    except (TypeError, ValueError):
        port = 22
    return port if 1 <= port <= 65535 else 22


def _fingerprint_known_host_line(line: str) -> str:
    if not shutil.which("ssh-keygen"):
        return ""
    fd, tmp_name = tempfile.mkstemp(prefix="mavi-hostkey-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(line.rstrip() + "\n")
        result = subprocess.run(
            ["ssh-keygen", "-lf", tmp_name],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return (result.stdout or "").strip()
        return ""
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def ensure_ssh_host_key(
    project: Path,
    host: str,
    *,
    port: int = 22,
    yes: bool = False,
) -> Path:
    """SSH-Host-Key einmalig scannen, anzeigen und in Mavi-known_hosts speichern."""

    from .openssh import (
        _fingerprint_known_host_line,
        _known_host_present,
    )

    from .environment import die
    from .remote import get_ssh_settings

    settings = get_ssh_settings(project)
    known_hosts = Path(settings["known_hosts"]).expanduser().resolve()
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(known_hosts.parent, 0o700)
    except OSError:
        pass

    if _known_host_present(known_hosts, host, port):
        return known_hosts

    if not shutil.which("ssh-keyscan"):
        die(
            "ssh-keyscan fehlt auf dem Ansible-Server. "
            "Auf Debian/Ubuntu: sudo apt install -y openssh-client"
        )
    if not shutil.which("ssh-keygen"):
        die(
            "ssh-keygen fehlt auf dem Ansible-Server. "
            "Auf Debian/Ubuntu: sudo apt install -y openssh-client"
        )

    cmd = ["ssh-keyscan", "-T", "7", "-p", str(port), "-t", "ed25519,rsa", host]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=12,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        die(f"SSH-Host-Key von {host}:{port} konnte nicht gelesen werden: {exc}")

    lines = [
        x.strip() for x in (result.stdout or "").splitlines()
        if x.strip() and not x.lstrip().startswith("#")
    ]
    if not lines:
        detail = (result.stderr or "").strip()
        die(
            f"Kein SSH-Host-Key von {host}:{port} erhalten. "
            "Läuft sshd und lässt ESET TCP/22 vom Ansible-Server durch?"
            + (f"\nssh-keyscan: {detail}" if detail else "")
        )

    # Ed25519 bevorzugen, RSA als Fallback. Einen Key bestätigen reicht für den
    # strikt konfigurierten Erstkontakt; weitere Keytypen müssen nicht blind
    # übernommen werden.
    chosen = next((x for x in lines if " ssh-ed25519 " in x), lines[0])
    fingerprint = _fingerprint_known_host_line(chosen)

    print("\nMavi SSH HOST-KEY")
    print("================")
    print(f"Ziel:        {host}:{port}")
    if fingerprint:
        print(f"Fingerprint: {fingerprint}")
    print(f"Datei:       {known_hosts}")
    print(
        "\nVergleiche den SHA256-Fingerprint idealerweise mit dem Fingerprint, "
        "den die Mavi-Windows-Einrichtungsanleitung direkt auf dem Laptop ausgibt."
    )

    if not yes:
        answer = input("Diesen SSH-Host-Key vertrauen und speichern? [j/N] ").strip().lower()
        if answer not in {"j", "ja", "y", "yes"}:
            die("SSH-Host-Key wurde nicht übernommen. Host bleibt unverändert.")

    with known_hosts.open("a", encoding="utf-8") as f:
        f.write(chosen.rstrip() + "\n")
    try:
        os.chmod(known_hosts, 0o600)
    except OSError:
        pass
    print("✓ SSH-Host-Key gespeichert.")
    return known_hosts


def cmd_ssh_keygen(args: argparse.Namespace) -> None:
    from .openssh import (
        _public_key_summary,
    )

    from .environment import (
        die,
        ensure_initialized,
    )
    from .remote import (
        _ssh_environment_marker,
        get_ssh_settings,
    )

    ensure_initialized(args.project, quiet=True)
    settings = get_ssh_settings(args.project)
    key_path = Path(getattr(args, "key", None) or settings["private_key"]).expanduser().resolve()
    pub_path = Path(str(key_path) + ".pub")

    if key_path.exists() or pub_path.exists():
        print(f"SSH-Key existiert bereits: {key_path}")
        public_key, fingerprint = _public_key_summary(pub_path)
        if fingerprint:
            print(f"Fingerprint: {fingerprint}")
        if public_key:
            print(f"Public Key:  {public_key}")
        print("\nBestehende Keys werden von Mavi absichtlich NICHT überschrieben.")
        return

    if not shutil.which("ssh-keygen"):
        die("ssh-keygen ist auf dem Ansible-Server nicht installiert. Auf Debian/Ubuntu: sudo apt install -y openssh-client")

    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(key_path.parent, 0o700)
    except OSError:
        pass

    print("\nMavi SSH-KEY")
    print("===========")
    print(f"Ziel: {key_path}")
    print(
        "Es wird ein eigener Ed25519-Automationsschlüssel ohne Passphrase erzeugt.\n"
        "Der private Key bleibt ausschließlich auf dem Ansible-Server und erhält Modus 600."
    )

    if not getattr(args, "yes", False):
        answer = input("Key erzeugen? [j/N] ").strip().lower()
        if answer not in {"j", "ja", "y", "yes"}:
            print("Abgebrochen.")
            return

    cmd = [
        "ssh-keygen",
        "-t", "ed25519",
        "-f", str(key_path),
        "-N", "",
        "-C", _ssh_environment_marker(args.project),
    ]
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        die(f"ssh-keygen wurde mit Code {result.returncode} beendet.")

    try:
        os.chmod(key_path, 0o600)
        os.chmod(pub_path, 0o644)
    except OSError:
        pass

    public_key, fingerprint = _public_key_summary(pub_path)
    print(f"\n✓ SSH-Key angelegt: {key_path}")
    if fingerprint:
        print(f"  Fingerprint: {fingerprint}")
    if public_key:
        print(f"  Public Key:  {public_key}")
    print("\nNächster Schritt: mavi-provisioner ssh auto <HOST>")
