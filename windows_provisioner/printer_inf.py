# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""INF- und Treiberpaketanalyse.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    csv,
    ipaddress,
    json,
    re,
    sys,
    yaml,
)


def _read_inf_text(path: Path) -> str:
    raw = path.read_bytes()

    # Viele ältere Hersteller-INFs sind UTF-16LE ohne sauberen BOM. Wenn man
    # dort zuerst UTF-8 probiert, kann der Decode wegen der NUL-Bytes sogar
    # "erfolgreich" sein, liefert aber unbrauchbaren Text.
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass

    sample = raw[:512]
    if sample.count(b"\x00") >= max(4, len(sample) // 8):
        for encoding in ("utf-16-le", "utf-16-be"):
            try:
                text = raw.decode(encoding)
                if "[" in text and "]" in text:
                    return text
            except UnicodeDecodeError:
                pass

    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def _parse_inf_sections(path: Path) -> dict[str, list[str]]:
    from .printers import (
        _read_inf_text,
    )

    try:
        content = _read_inf_text(path)
    except OSError:
        return {}

    sections: dict[str, list[str]] = {}
    current = ""
    for raw_line in content.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and "]" in line:
            current = line[1:line.index("]")].strip().lower()
            sections.setdefault(current, [])
            continue
        if current:
            line = line.split(";", 1)[0].strip()
            if line:
                sections.setdefault(current, []).append(line)
    return sections


def _inf_strings(sections: dict[str, list[str]]) -> dict[str, str]:
    strings: dict[str, str] = {}

    # Neben [Strings] sind [Strings.0407], [Strings.0409] usw. üblich.
    # Genau daran scheiterten einige Canon-INFs in v0.8.17.
    string_sections = [
        name for name in sections
        if name == "strings" or name.startswith("strings.")
    ]
    # Basissektion zuerst, lokalisierte Werte dürfen sie überschreiben.
    string_sections.sort(key=lambda x: (x != "strings", x))

    for section_name in string_sections:
        for line in sections.get(section_name, []):
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            strings[key.strip().lower()] = value.strip().strip('"')
    return strings


def extract_inf_driver_names(path: Path) -> list[str]:
    """
    Best-Effort-Auswertung klassischer Windows-Drucker-INF-Dateien.
    Unterstützt auch lokalisierte [Strings.xxxx]-Sektionen und dekorierte
    Manufacturer-Modellsektionen wie Foo.NTamd64.*.
    """
    from .printers import (
        _inf_strings,
        _parse_inf_sections,
    )

    sections = _parse_inf_sections(path)
    if not sections:
        return []

    strings = _inf_strings(sections)

    def resolve(value: str) -> str:
        value = value.strip().strip('"')
        m = re.fullmatch(r"%([^%]+)%", value)
        if m:
            return strings.get(m.group(1).strip().lower(), value)
        return value

    model_bases: set[str] = set()
    for line in sections.get("manufacturer", []):
        if "=" not in line:
            continue
        _, right = line.split("=", 1)
        base = right.split(",", 1)[0].strip().strip('"')
        if base:
            model_bases.add(base.lower())

    model_sections: list[str] = []
    if model_bases:
        for section_name in sections:
            if any(
                section_name == base or section_name.startswith(base + ".")
                for base in model_bases
            ):
                model_sections.append(section_name)
    else:
        model_sections = [
            name for name in sections
            if "model" in name and name != "manufacturer"
        ]

    names: list[str] = []
    seen: set[str] = set()

    def add_name(raw_name: str) -> None:
        name = resolve(raw_name).strip()
        if not name or name.startswith("%"):
            return
        key = name.casefold()
        if key not in seen:
            seen.add(key)
            names.append(name)

    for section_name in model_sections:
        for line in sections.get(section_name, []):
            if "=" not in line:
                continue
            left, _ = line.split("=", 1)
            add_name(left)

    # Fallback für Hersteller-INFs mit ungewöhnlicher Manufacturer-Struktur:
    # aufgelöste Modellbeschreibungen aus plausiblen Install-Sektionen nehmen.
    if not names:
        ignored_prefixes = (
            "version", "strings", "sourcedisks", "destinationdirs",
            "controlflags", "printerpackageinstallation", "source",
        )
        for section_name, lines in sections.items():
            if section_name == "manufacturer" or section_name.startswith(ignored_prefixes):
                continue
            for line in lines:
                if "=" not in line:
                    continue
                left, right = line.split("=", 1)
                if not left.strip().startswith("%") or "," not in right:
                    continue
                resolved = resolve(left).strip()
                # Menschliche Modellnamen sind typischerweise länger und
                # enthalten Buchstaben; interne Tokens herausfiltern.
                if len(resolved) >= 5 and re.search(r"[A-Za-z]", resolved):
                    add_name(left)

    return names


def find_inf_driver_name_candidates(path: Path, hint: str = "") -> list[str]:
    """Sucht plausible Treibernamen aus Modellsektionen und INF-Strings."""
    from .printers import (
        _inf_strings,
        _parse_inf_sections,
        extract_inf_driver_names,
    )

    sections = _parse_inf_sections(path)
    strings = _inf_strings(sections)
    values = list(extract_inf_driver_names(path))

    hint_tokens = [x.casefold() for x in re.findall(r"[A-Za-z0-9]+", hint) if len(x) >= 2]
    for value in strings.values():
        candidate = value.strip().strip('"')
        if not (4 <= len(candidate) <= 120):
            continue
        low = candidate.casefold()
        if "\\" in candidate or "/" in candidate or candidate.lower().endswith((".dll", ".cab", ".cat", ".inf")):
            continue
        if hint_tokens and not all(token in low for token in hint_tokens):
            continue
        if re.search(r"(?i)(pcl|ufr|postscript|ps3|printer|canon|kyocera|ricoh|xerox|universal|generic|driver)", candidate):
            values.append(candidate)

    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def _inf_resolve_token(value: str, strings: dict[str, str]) -> str:
    value = value.strip().strip('"')
    match = re.fullmatch(r"%([^%]+)%", value)
    if match:
        return strings.get(match.group(1).strip().lower(), value)
    return value


def _inf_csv_fields(value: str) -> list[str]:
    """INF-Kommafelder lesen, ohne Kommas in Anführungszeichen zu zerlegen."""
    try:
        return [field.strip() for field in next(csv.reader([value], skipinitialspace=True))]
    except (csv.Error, StopIteration):
        return [field.strip() for field in value.split(",")]


def extract_inf_package_layout(path: Path) -> dict[str, Any]:
    """
    Liest die für ein Treiberpaket relevanten SourceDisks*-Informationen.

    Wichtig für Canon & Co.: SourceDisksFiles kann hunderte DLL/GPD-Dateien
    nennen, obwohl diese nicht lose neben der INF liegen. Wenn die zugehörige
    SourceDisksNames-Zeile eine CAB-Datei angibt, liegen diese Payload-Dateien
    regulär in genau diesem CAB. v0.8.18 hat solche Dateien fälschlich als
    "fehlend" gewertet.
    """
    from .printers import (
        _inf_csv_fields,
        _inf_resolve_token,
        _inf_strings,
        _parse_inf_sections,
    )

    sections = _parse_inf_sections(path)
    strings = _inf_strings(sections)

    disk_cabs: dict[str, str] = {}
    refs: list[str] = []
    seen: set[str] = set()
    source_file_cabs: dict[str, set[str]] = {}

    def add_ref(raw: str) -> str:
        value = _inf_resolve_token(raw, strings).strip().strip('"')
        if not value or value.startswith("%"):
            return ""
        value = value.replace("/", "\\")
        name = value.rsplit("\\", 1)[-1]
        key = name.casefold()
        if name and key not in seen:
            seen.add(key)
            refs.append(name)
        return name

    # Syntax: diskid = description[,tag-or-cab-file[,unused[,path]]]
    # Bei Canon steht hier z. B. gppcl6.cab. Alle SourceDisksFiles mit
    # diesem diskid dürfen dann innerhalb des CAB liegen.
    for section_name, lines in sections.items():
        if not section_name.startswith("sourcedisksnames"):
            continue
        for line in lines:
            if "=" not in line:
                continue
            disk_id, right = line.split("=", 1)
            fields = _inf_csv_fields(right)
            if len(fields) < 2:
                continue
            cab = _inf_resolve_token(fields[1], strings).strip().strip('"')
            if not cab or cab.startswith("%"):
                continue
            cab = cab.replace("/", "\\").rsplit("\\", 1)[-1]
            if cab.lower().endswith(".cab"):
                disk_cabs[disk_id.strip().casefold()] = cab
                add_ref(cab)

    for section_name, lines in sections.items():
        if not section_name.startswith("sourcedisksfiles"):
            continue
        for line in lines:
            if "=" not in line:
                continue
            left, right = line.split("=", 1)
            name = add_ref(left)
            if not name:
                continue
            fields = _inf_csv_fields(right)
            disk_id = fields[0].strip().casefold() if fields else ""
            cab = disk_cabs.get(disk_id, "")
            if cab:
                source_file_cabs.setdefault(name.casefold(), set()).add(cab)

    # Signaturkatalog muss weiterhin real als Datei vorhanden sein.
    for line in sections.get("version", []):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip().lower().startswith("catalogfile"):
            fields = _inf_csv_fields(value)
            if fields:
                add_ref(fields[0])

    return {
        "refs": refs,
        "source_file_cabs": source_file_cabs,
        "cabs": sorted(set(disk_cabs.values()), key=str.casefold),
    }


def extract_inf_referenced_files(path: Path) -> list[str]:
    """Kompatibilitätswrapper für ältere Aufrufer."""
    from .printers import (
        extract_inf_package_layout,
    )

    return list(extract_inf_package_layout(path).get("refs", []))


def _driver_package_inventory(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    try:
        for item in root.rglob("*"):
            if item.is_file():
                files.setdefault(item.name.casefold(), item)
    except OSError:
        pass
    return files


def _driver_package_resolution(
    inf_path: Path,
    root: Path,
) -> tuple[list[str], list[str], list[str]]:
    """
    Liefert (missing, packed, refs).

    `packed` sind referenzierte Payload-Dateien, die nicht lose vorhanden sein
    müssen, weil SourceDisksNames für ihren Disk-ID ein vorhandenes CAB angibt.
    """
    from .printers import (
        _driver_package_inventory,
        extract_inf_package_layout,
    )

    layout = extract_inf_package_layout(inf_path)
    refs = list(layout.get("refs", []))
    source_file_cabs: dict[str, set[str]] = layout.get("source_file_cabs", {}) or {}
    inventory = _driver_package_inventory(root)

    missing: list[str] = []
    packed: list[str] = []
    for name in refs:
        key = name.casefold()
        if key in inventory:
            continue

        possible_cabs = source_file_cabs.get(key, set())
        if possible_cabs and any(cab.casefold() in inventory for cab in possible_cabs):
            packed.append(name)
            continue

        missing.append(name)

    return missing, packed, refs


def choose_driver_package_root(
    inf_path: Path,
    config: dict[str, Any],
) -> tuple[Path, list[str], list[str], list[str]]:
    """
    Sucht den kleinsten sinnvollen Paket-Root.

    Seit v0.8.19 werden Payload-Dateien korrekt als durch CAB abgedeckt erkannt,
    wenn SourceDisksNames/SourceDisksFiles diese Zuordnung in der INF vorgeben.
    """

    from .printers import (
        _driver_package_resolution,
        extract_inf_package_layout,
    )

    from .environment import _mavi_source_root

    layout = extract_inf_package_layout(inf_path)
    refs = list(layout.get("refs", []))
    configured_root = _mavi_source_root(config)
    local_root = (
        configured_root.resolve()
        if configured_root is not None
        else inf_path.parent.resolve()
    )

    candidates: list[Path] = []
    current = inf_path.parent.resolve()
    for _ in range(5):
        candidates.append(current)
        if current == local_root or current.parent == current:
            break
        try:
            current.relative_to(local_root)
        except ValueError:
            break
        parent = current.parent
        try:
            parent.relative_to(local_root)
        except ValueError:
            break
        current = parent

    if not refs:
        return inf_path.parent, [], [], []

    best = inf_path.parent.resolve()
    best_score = (-1, -1)
    best_missing: list[str] = list(refs)
    best_packed: list[str] = []

    for candidate in candidates:
        missing, packed, current_refs = _driver_package_resolution(inf_path, candidate)
        resolved = len(current_refs) - len(missing)
        # Bei gleicher Auflösung gewinnt der kleinere/nähere Root.
        score = (resolved, -len(candidate.parts))
        if score > best_score:
            best = candidate
            best_score = score
            best_missing = missing
            best_packed = packed
        if not missing:
            best = candidate
            best_missing = []
            best_packed = packed
            break

    return best, best_missing, best_packed, refs

def _choose_driver_name_from_inf(path: Path) -> str:
    from .printers import (
        extract_inf_driver_names,
    )

    from .catalogs import prompt

    names = extract_inf_driver_names(path)
    if not names:
        print()
        print("! Aus der INF konnten keine eindeutigen Druckertreibernamen gelesen werden.")
        return prompt("Exakter Windows-Treibername")

    print()
    print(f"INF-Analyse: {len(names)} mögliche Druckertreiber/Modelle gefunden.")

    candidates = names
    if len(candidates) > 25:
        search = prompt(
            "Optional nach Modell/Treiber filtern (Enter = erste 25 anzeigen)",
            "",
        ).strip()
        if search:
            filtered = [x for x in names if search.casefold() in x.casefold()]
            if filtered:
                candidates = filtered
            else:
                print("Keine Treffer für Filter; zeige erste Einträge.")

    shown = candidates[:25]
    items = [(str(i), name) for i, name in enumerate(shown, 1)]
    items.append(("m", "Treibername manuell eingeben"))

    print()
    print("Treiber aus INF auswählen:")
    for key, label in items:
        print(f"  {key}) {label}")

    while True:
        value = input("> ").strip().lower()
        if value == "m":
            return prompt("Exakter Windows-Treibername")
        if value.isdigit() and 1 <= int(value) <= len(shown):
            return shown[int(value) - 1]
        print("Ungültige Auswahl.")


def _inf_section_values(
    sections: dict[str, list[str]],
    section_name: str,
) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in sections.get(section_name.lower(), []):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip().lower()] = value.strip().strip('"')
    return values


def inspect_printer_inf(path: Path) -> dict[str, Any]:
    """Bewertet eine INF danach, ob sie als eigentlicher Druckertreiber taugt."""
    from .printers import (
        _inf_resolve_token,
        _inf_section_values,
        _inf_strings,
        _parse_inf_sections,
        extract_inf_driver_names,
    )

    sections = _parse_inf_sections(path)
    strings = _inf_strings(sections)
    version = _inf_section_values(sections, "version")

    def resolve(value: str) -> str:
        return _inf_resolve_token(value, strings).strip().strip('"')

    class_name = resolve(version.get("class", ""))
    provider = resolve(version.get("provider", ""))
    driver_ver = resolve(version.get("driverver", ""))
    catalog_file = ""
    for key, value in version.items():
        if key.startswith("catalogfile"):
            catalog_file = resolve(value)
            break

    names = extract_inf_driver_names(path)
    manufacturer_entries = sum(
        1 for line in sections.get("manufacturer", []) if "=" in line
    )
    printer_package = any(
        section == "printerpackageinstallation"
        or section.startswith("printerpackageinstallation.")
        for section in sections
    )

    score = 0
    reasons: list[str] = []
    if class_name.casefold() in {"printer", "printqueue"}:
        score += 100
        reasons.append(f"Class={class_name}")
    elif class_name:
        score -= 25
        reasons.append(f"Class={class_name}")

    if manufacturer_entries:
        score += 30
        reasons.append(f"Manufacturer={manufacturer_entries}")
    if names:
        score += 40 + min(len(names), 60)
        reasons.append(f"{len(names)} Modellname(n)")
    if printer_package:
        score += 25
        reasons.append("PrinterPackageInstallation")
    if catalog_file:
        score += 5

    # Eine INF ohne Printer-Klasse und ohne auswertbare Modelle ist fast immer
    # Zusatzkomponente, UI, Monitor, USB-Helfer o. Ä.
    plausible = bool(
        names
        or class_name.casefold() in {"printer", "printqueue"}
        or printer_package
    )

    return {
        "path": path,
        "class": class_name,
        "provider": provider,
        "driver_ver": driver_ver,
        "catalog_file": catalog_file,
        "driver_names": names,
        "manufacturer_entries": manufacturer_entries,
        "printer_package": printer_package,
        "score": score,
        "reasons": reasons,
        "plausible": plausible,
    }


def scan_printer_driver_folder(root: Path) -> list[dict[str, Any]]:
    """Rekursiv alle INFs scannen und plausible Haupt-Druckertreiber ranken."""
    from .printers import (
        inspect_printer_inf,
    )

    from .environment import die

    if not root.exists() or not root.is_dir():
        die(f"Treiberordner nicht gefunden: {root}")

    inf_paths: list[Path] = []
    try:
        for item in root.rglob("*"):
            if item.is_file() and item.suffix.casefold() == ".inf":
                inf_paths.append(item)
                if len(inf_paths) > 500:
                    die(
                        "Mehr als 500 INF-Dateien gefunden. Bitte einen kleineren "
                        "entpackten Treiberordner auswählen."
                    )
    except OSError as exc:
        die(f"Treiberordner konnte nicht gelesen werden: {root} ({exc})")

    if not inf_paths:
        die(f"Keine .inf-Dateien unter '{root}' gefunden.")

    inspected: list[dict[str, Any]] = []
    for inf_path in sorted(inf_paths, key=lambda p: str(p).casefold()):
        info = inspect_printer_inf(inf_path)
        if info.get("plausible"):
            inspected.append(info)

    if not inspected:
        die(
            f"{len(inf_paths)} INF-Datei(en) gefunden, aber keine davon sieht "
            "wie ein Windows-Druckertreiber aus."
        )

    inspected.sort(
        key=lambda x: (
            -int(x.get("score", 0)),
            str(x.get("path", "")).casefold(),
        )
    )
    return inspected


def _printer_inf_label(info: dict[str, Any], root: Path) -> str:
    path = Path(info["path"])
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path

    class_name = str(info.get("class") or "?")
    names = list(info.get("driver_names") or [])
    model_text = f"{len(names)} Modell(e)" if names else "keine Modellnamen"
    return f"{relative}  [{class_name}, {model_text}]"


def choose_printer_inf_from_folder(root: Path) -> Path:
    from .printers import (
        _printer_inf_label,
        scan_printer_driver_folder,
    )

    from .catalogs import prompt

    candidates = scan_printer_driver_folder(root)

    # Sobald INFs mit echten Modellnamen vorhanden sind, verstecken wir reine
    # UI-/Hilfs-INFs aus der normalen Auswahl. Genau das räumt HP-Pakete auf.
    with_models = [x for x in candidates if x.get("driver_names")]
    with_manufacturer = [
        x for x in candidates if int(x.get("manufacturer_entries", 0)) > 0
    ]
    shown_candidates = (
        with_models
        if with_models
        else (with_manufacturer if with_manufacturer else candidates)
    )
    hidden_count = len(candidates) - len(shown_candidates)

    print()
    print("Mavi DRUCKERTREIBER-SCAN")
    print("=======================")
    print(f"Ordner: {root}")
    print(
        f"Gefunden: {len(candidates)} plausible Drucker-INF(s); "
        f"{len(with_models)} mit auswertbaren Modellnamen."
    )
    if hidden_count:
        print(
            f"  {hidden_count} Zusatz-/Hilfs-INF(s) ohne Modellnamen "
            "werden ausgeblendet."
        )

    # Ein klarer Haupttreiber wird automatisch gewählt. Das ist bei Paketen
    # wie HP UPD typischerweise die große INF mit Manufacturer/Models.
    if len(shown_candidates) == 1:
        selected = shown_candidates[0]
        print()
        print("✓ Eindeutige Haupt-INF automatisch gewählt:")
        print(f"  {_printer_inf_label(selected, root)}")
        names = list(selected.get("driver_names") or [])
        for name in names[:3]:
            print(f"    - {name}")
        if len(names) > 3:
            print(f"    ... und {len(names) - 3} weitere")
        return Path(selected["path"])

    candidates_view = shown_candidates
    if len(candidates_view) > 25:
        print()
        search = prompt(
            "Optional INF/Modell filtern (Enter = beste 25 anzeigen)",
            "",
        ).strip().casefold()
        if search:
            filtered = []
            for info in candidates_view:
                haystack = " ".join(
                    [
                        str(info.get("path", "")),
                        str(info.get("provider", "")),
                        *[str(x) for x in info.get("driver_names", [])],
                    ]
                ).casefold()
                if search in haystack:
                    filtered.append(info)
            if filtered:
                candidates_view = filtered
            else:
                print("Keine Treffer für den Filter; zeige die bestbewerteten INFs.")

    candidates_view = candidates_view[:25]
    print()
    print("Welche INF enthält den gewünschten Druckertreiber?")
    for index, info in enumerate(candidates_view, 1):
        print(f"  {index}) {_printer_inf_label(info, root)}")
        names = list(info.get("driver_names") or [])
        if names:
            sample = "; ".join(names[:2])
            if len(names) > 2:
                sample += "; ..."
            print(f"     z. B. {sample}")

    while True:
        raw = input("> ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(candidates_view):
            return Path(candidates_view[int(raw) - 1]["path"])
        print("Ungültige Auswahl.")


def resolve_printer_driver_source(
    args: argparse.Namespace,
    config: dict[str, Any],
) -> tuple[Path, Path | None]:
    """Liefert (INF-Pfad, vom Benutzer gewählter Quellordner)."""
    from .printers import (
        choose_printer_inf_from_folder,
    )

    from .catalogs import prompt
    from .environment import (
        die,
        normalize_path,
    )

    raw_dir = str(getattr(args, "driver_dir", None) or "").strip()
    raw_inf = str(getattr(args, "driver_inf", None) or "").strip()

    if raw_dir and raw_inf:
        die("Bitte nur --driver-dir ODER --driver-inf angeben, nicht beides.")

    if raw_inf:
        inf_path = normalize_path(raw_inf, config).expanduser()
        if not inf_path.exists() or not inf_path.is_file():
            die(f"Treiber-INF nicht gefunden: {inf_path}")
        if inf_path.suffix.casefold() != ".inf":
            die(f"Treiberdatei ist keine .inf: {inf_path}")
        return inf_path, inf_path.parent

    if not raw_dir:
        raw_dir = prompt(
            "Entpackter Druckertreiber-Ordner, z. B. S:\\Drucker\\Treiberpaket"
        )

    source = normalize_path(raw_dir, config).expanduser()

    # Komfort/Abwärtskompatibilität: Wer hier trotzdem direkt eine INF einfügt,
    # bekommt keinen Fehler, sondern dieselbe Verarbeitung wie früher.
    if source.exists() and source.is_file():
        if source.suffix.casefold() != ".inf":
            die(f"Treiberquelle ist weder Ordner noch .inf: {source}")
        print("! Direkt eine INF angegeben. Das funktioniert weiterhin; empfohlen ist der Treiberordner.")
        return source, source.parent

    if not source.exists() or not source.is_dir():
        die(f"Treiberordner nicht gefunden: {source}")

    return choose_printer_inf_from_folder(source), source
