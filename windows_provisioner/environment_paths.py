# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Konfiguration und Pfadauflösung.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

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

from .environment_files import die




def get_config(project: Path) -> dict[str, Any]:
    """
    Lädt die Konfiguration und ergänzt neue Standardwerte automatisch,
    ohne bestehende benutzerdefinierte Werte zu überschreiben.
    """
    from .environment import (
        load_yaml,
        project_paths,
    )

    from .settings import CONFIG_TEMPLATE

    path = project_paths(project)["config"]
    loaded = load_yaml(path, {}) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Mavi-Konfiguration muss ein YAML-Dictionary sein: {path}")

    result = dict(CONFIG_TEMPLATE)
    result.update(loaded)

    result["profile"] = dict(CONFIG_TEMPLATE.get("profile", {}))
    loaded_profile = loaded.get("profile", {}) or {}
    if not isinstance(loaded_profile, dict):
        raise ValueError("profile muss ein YAML-Dictionary sein.")
    result["profile"].update(loaded_profile)

    result["identity"] = dict(CONFIG_TEMPLATE.get("identity", {}))
    loaded_identity = loaded.get("identity", {}) or {}
    if not isinstance(loaded_identity, dict):
        raise ValueError("identity muss ein YAML-Dictionary sein.")
    result["identity"].update(loaded_identity)

    result["path_mappings"] = dict(CONFIG_TEMPLATE.get("path_mappings", {}))
    loaded_mappings = loaded.get("path_mappings", {}) or {}
    if not isinstance(loaded_mappings, dict):
        raise ValueError("path_mappings muss ein YAML-Dictionary sein.")
    result["path_mappings"].update(loaded_mappings)

    result["software_source"] = dict(CONFIG_TEMPLATE.get("software_source", {}))
    loaded_source = loaded.get("software_source", {}) or {}
    if not isinstance(loaded_source, dict):
        raise ValueError("software_source muss ein YAML-Dictionary sein.")
    result["software_source"].update(loaded_source)

    result["ssh"] = dict(CONFIG_TEMPLATE.get("ssh", {}))
    loaded_ssh = loaded.get("ssh", {}) or {}
    if not isinstance(loaded_ssh, dict):
        raise ValueError("ssh muss ein YAML-Dictionary sein.")
    result["ssh"].update(loaded_ssh)

    result["winrm_https"] = dict(CONFIG_TEMPLATE.get("winrm_https", {}))
    loaded_winrm = loaded.get("winrm_https", {}) or {}
    if not isinstance(loaded_winrm, dict):
        raise ValueError("winrm_https muss ein YAML-Dictionary sein.")
    result["winrm_https"].update(loaded_winrm)

    result["ui"] = dict(CONFIG_TEMPLATE.get("ui", {}))
    loaded_ui = loaded.get("ui", {}) or {}
    if not isinstance(loaded_ui, dict):
        raise ValueError("ui muss ein YAML-Dictionary sein.")
    result["ui"].update(loaded_ui)

    return result


def normalize_path(raw: str, config: dict[str, Any]) -> Path:
    from .environment import (
        die,
    )

    raw = raw.strip().strip('"').strip("'")

    if raw.startswith("/"):
        return Path(raw)

    mappings = config.get("path_mappings", {})
    for source, target in sorted(
        mappings.items(), key=lambda x: len(str(x[0])), reverse=True
    ):
        if raw.lower().startswith(str(source).lower()):
            remainder = raw[len(str(source)):]
            remainder = remainder.lstrip("\\/")
            target_path = Path(str(target))
            if remainder:
                parts = [x for x in re.split(r"[\\/]+", remainder) if x]
                return target_path.joinpath(*parts)
            return target_path

    # Beliebiger Windows-Laufwerksbuchstabe, z. B. S:\Install oder X:.
    # Der Setup-Assistent kann eine Zuordnung dafür anlegen. Ohne Zuordnung
    # verwenden wir nur dann die Softwarequelle, wenn deren Laufwerk passt.
    drive_match = re.match(r"^([A-Za-z]:)[\\/]*", raw)
    if drive_match:
        source = config.get("software_source", {}) or {}
        configured_drive = str(source.get("drive", "") or "").strip()
        configured_drive = configured_drive[:2].upper()
        requested_drive = drive_match.group(1).upper()
        local_root = str(source.get("local_root", "") or "").strip()
        if configured_drive == requested_drive and local_root:
            root = Path(local_root)
            remainder = raw[drive_match.end():]
            if remainder:
                parts = [x for x in re.split(r"[\\/]+", remainder) if x]
                return root.joinpath(*parts)
            return root
        die(
            f"Für das Laufwerk {requested_drive} ist kein lokales Mapping "
            "konfiguriert.\nBitte in der TUI Grundprofil & Softwarequelle -> "
            "Softwarequelle, UNC und Laufwerk einrichten öffnen."
        )

    if raw.startswith("\\\\"):
        die(
            f"Für diesen UNC-Pfad ist kein Mapping konfiguriert: {raw}\n"
            "Bitte in der TUI Grundprofil & Softwarequelle -> "
            "Softwarequelle, UNC und Laufwerk einrichten öffnen."
        )

    return Path(raw)



def _path_signature(value: str) -> str:
    """
    Vergleichssignatur für versehentlich gesetzte Backslashes,
    Unterstriche, Bindestriche usw.
    """
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _installer_candidates(root: Path, max_files: int = 10000) -> list[Path]:
    candidates: list[Path] = []
    if not root.exists():
        return candidates

    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for filename in filenames:
                if Path(filename).suffix.lower() not in {".msi", ".exe"}:
                    continue
                candidates.append(Path(dirpath) / filename)
                if len(candidates) >= max_files:
                    return candidates
    except (PermissionError, OSError):
        pass

    return candidates


def resolve_installer_path(path: Path, config: dict[str, Any]) -> Path:
    r"""
    Versucht typische Copy/Paste-Fehler automatisch zu reparieren.

    Beispiel:
      S:\Tools\setup-1.4.6-x86\_64.msi

    wird, falls die Datei existiert, automatisch zu:
      S:\Tools\setup-1.4.6-x86_64.msi
    """

    from .environment import (
        _mavi_source_root,
    )
    from .environment import (
        _installer_candidates,
        _path_signature,
    )

    if path.exists():
        return path

    root = _mavi_source_root(config)
    if root is None or not root.exists():
        return path

    # 1. Sichere Reparatur: zwei benachbarte Pfadbestandteile zusammenkleben.
    #    Das fängt genau x86\_64.msi -> x86_64.msi ab.
    try:
        rel = path.relative_to(root)
        parts = list(rel.parts)
    except ValueError:
        parts = []

    if len(parts) >= 2:
        for idx in range(len(parts) - 1):
            merged = parts[:idx] + [parts[idx] + parts[idx + 1]] + parts[idx + 2:]
            candidate = root.joinpath(*merged)
            if candidate.is_file() and candidate.suffix.lower() in {".msi", ".exe"}:
                print()
                print("✓ Pfad automatisch korrigiert:")
                print(f"  {path}")
                print("  →")
                print(f"  {candidate}")
                return candidate

    # 2. Signaturvergleich: Trenner ignorieren.
    #    Nur bei EINEM eindeutigen Treffer automatisch übernehmen.
    requested_rel = str(path)
    try:
        requested_rel = str(path.relative_to(root))
    except ValueError:
        pass

    requested_sig = _path_signature(requested_rel)
    exact_matches: list[Path] = []

    for candidate in _installer_candidates(root):
        try:
            rel_candidate = str(candidate.relative_to(root))
        except ValueError:
            rel_candidate = str(candidate)

        if _path_signature(rel_candidate) == requested_sig:
            exact_matches.append(candidate)

    if len(exact_matches) == 1:
        candidate = exact_matches[0]
        print()
        print("✓ Gemeinten Installer gefunden:")
        print(f"  Eingabe: {path}")
        print(f"  Datei:   {candidate}")
        return candidate

    # 3. Dateiname allein vergleichen, falls nur ein passender Installer existiert.
    filename_sig = _path_signature(path.name)
    same_name = [
        candidate
        for candidate in _installer_candidates(root)
        if _path_signature(candidate.name) == filename_sig
    ]

    if len(same_name) == 1:
        candidate = same_name[0]
        print()
        print("✓ Installer anhand des Dateinamens gefunden:")
        print(f"  Eingabe: {path}")
        print(f"  Datei:   {candidate}")
        return candidate

    return path

def display_share_path(path: Path, root: Path, drive: str = "") -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return str(path)

    if not drive:
        return str(path)

    if str(rel) == ".":
        return drive

    win_rel = str(rel).replace("/", "\\")
    return drive.rstrip("\\") + "\\" + win_rel


def browse_files(
    root: Path,
    drive: str = "",
    *,
    extensions: set[str] | None = None,
    title: str = "Datei auswählen",
    start_dir: Path | None = None,
) -> Path:
    from .environment import (
        die,
        display_share_path,
    )

    root = root.resolve()
    current = (start_dir or root).resolve()

    if not root.exists():
        die(f"Softwarequelle ist nicht gemountet/erreichbar: {root}")

    try:
        current.relative_to(root)
    except ValueError:
        current = root

    wanted = {x.lower() for x in (extensions or set())}

    while True:
        try:
            dirs = sorted(
                [
                    p for p in current.iterdir()
                    if p.is_dir() and not p.name.startswith(".")
                ],
                key=lambda p: p.name.lower(),
            )
            files = sorted(
                [
                    p for p in current.iterdir()
                    if p.is_file()
                    and (not wanted or p.suffix.lower() in wanted)
                ],
                key=lambda p: p.name.lower(),
            )
        except PermissionError:
            die(f"Keine Leserechte für: {current}")

        print()
        print(title)
        print("=" * len(title))
        print(f"Ordner: {display_share_path(current, root, drive)}")
        print(f"Linux:  {current}")
        print()

        entries: list[tuple[str, Path]] = []

        if current != root:
            entries.append(("..  (eine Ebene zurück)", current.parent))

        for p in dirs:
            entries.append((f"[ORDNER] {p.name}", p))

        for p in files:
            tag = p.suffix[1:].upper() if p.suffix else "DATEI"
            entries.append((f"[{tag}]    {p.name}", p))

        if not entries:
            ext_text = ", ".join(sorted(wanted)) if wanted else "Dateien"
            print(f"Keine passenden Einträge gefunden ({ext_text}).")

        for idx, (label, _) in enumerate(entries, start=1):
            print(f"  {idx:>3}) {label}")

        print("    0) Abbrechen")
        print()

        choice = input("> ").strip()
        if choice == "0":
            raise KeyboardInterrupt

        if not choice.isdigit():
            print("Bitte eine Nummer eingeben.")
            continue

        index = int(choice) - 1
        if index < 0 or index >= len(entries):
            print("Ungültige Auswahl.")
            continue

        selected = entries[index][1]

        if selected.is_dir():
            try:
                selected.resolve().relative_to(root)
            except ValueError:
                selected = root
            current = selected.resolve()
            continue

        return selected


def browse_installer(root: Path, drive: str = "") -> Path:

    from .environment import (
        browse_files,
    )

    return browse_files(
        root,
        drive,
        extensions={".msi", ".exe"},
        title="Software auswählen",
    )



def choose_installer_path(config: dict[str, Any]) -> Path:

    from .environment import (
        _mavi_drive_label,
        _mavi_mount_smb_source,
        _mavi_source_label,
        _mavi_source_root,
    )
    from .environment import (
        browse_installer,
        normalize_path,
    )

    from .catalogs import (
        prompt,
        yes_no,
    )

    source = config.get("software_source", {})
    unc_root = str(source.get("unc_root", "") or "")
    local_root = _mavi_source_root(config)
    drive = _mavi_drive_label(source.get("drive"))
    source_name = _mavi_source_label(config)

    if (
        str(source.get("kind", "") or "").lower() == "smb"
        and unc_root
        and local_root is not None
        and not os.path.ismount(local_root)
    ):
        print()
        if yes_no(f"{unc_root} ist noch nicht verbunden. Jetzt verbinden?", True):
            mounted, resolved_mount_host = _mavi_mount_smb_source(
                unc_root,
                local_root,
                str(source.get("mount_user", "") or ""),
                str(source.get("mount_host", "") or ""),
            )
            if not mounted:
                die(f"SMB-Freigabe ist nicht erreichbar: {unc_root}")
            source["mount_host"] = resolved_mount_host

    print()
    print("Softwarequelle")
    print("==============")
    print(f"Bezeichnung:           {source_name}")
    print(f"Windows-Laufwerk:      {drive or '(keins)'}")
    print(f"UNC:                   {unc_root or '(keine)'}")
    print(f"Auf Controller:        {local_root or '(nicht eingerichtet)'}")
    print()

    if local_root is not None and yes_no("Diese Quelle wieder verwenden?", True):
        if not local_root.exists():
            print(f"\n! {local_root} ist gerade nicht erreichbar.")
            print("  Ich frage deshalb nach dem vollständigen Pfad.\n")
        else:
            source_display = drive or str(local_root)
            print(
                "\nWie möchtest du den Installer auswählen?\n"
                f"  1) Durch {source_display} browsen (Standard)\n"
                f"  2) Pfad ab {source_display} eintippen\n"
            )
            mode = input("> ").strip() or "1"

            if mode == "1":
                return browse_installer(local_root, drive)

            if mode == "2":
                relative = prompt(
                    f"Pfad ab {source_display}, z. B. Tools\\setup.msi"
                )
                # Auch ein vollständiger Windows-Pfad darf eingefügt werden.
                if re.match(r"^[A-Za-z]:", relative):
                    return normalize_path(relative, config)
                parts = [x for x in re.split(r"[\\/]+", relative) if x]
                return local_root.joinpath(*parts)

            print("Ungültige Auswahl, vollständiger Pfad wird abgefragt.")

    raw = prompt("Vollständiger Installer-Pfad (Linux, UNC oder Windows-Laufwerk)")
    path = normalize_path(raw, config)

    # Nur ein Laufwerk oder ein Ordner eingegeben? Dann direkt darin browsen.
    if path.exists() and path.is_dir() and sys.stdin.isatty():
        print(f"\nOrdner erkannt: {path}")
        print("Ich öffne den Installer-Browser.")
        return browse_installer(path, drive)

    return path
