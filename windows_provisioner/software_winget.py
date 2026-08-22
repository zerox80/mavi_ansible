# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""WinGet- und Microsoft-Store-Workflows.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    ET,
    Path,
    argparse,
    base64,
    getpass,
    json,
    os,
    re,
    subprocess,
    sys,
    tempfile,
    yaml,
)






WINGET_PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{1,200}$")
WINGET_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
WINGET_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+~-]{0,100}$")


def _is_msstore_app(app: dict[str, Any]) -> bool:
    """True für Mavi-WinGet-Einträge aus dem Microsoft Store (msstore)."""
    return (
        str(app.get("type", "")).lower() == "winget"
        and str(app.get("winget_source", "winget")).strip().lower() == "msstore"
    )


def _software_type_label(app: dict[str, Any]) -> str:
    """Menschenlesbarer Typ; Store bleibt intern kompatibel type=winget."""
    from .software import (
        _is_msstore_app,
    )

    if _is_msstore_app(app):
        return "STORE"
    return str(app.get("type", "?") or "?").upper()


def _winget_validate_identifier(value: str, *, label: str = "Paket-ID") -> str:
    from .software import (
        WINGET_PACKAGE_ID_RE,
    )

    from .environment import die

    value = str(value or "").strip()
    if not WINGET_PACKAGE_ID_RE.fullmatch(value):
        die(
            f"Ungültige WinGet-{label}: {value!r}. "
            "Erlaubt sind Buchstaben, Zahlen sowie . _ + - ohne Leerzeichen."
        )
    return value


def _winget_validate_source(value: str) -> str:
    from .software import (
        WINGET_SOURCE_RE,
    )

    from .environment import die

    value = str(value or "winget").strip() or "winget"
    if not WINGET_SOURCE_RE.fullmatch(value):
        die(f"Ungültige WinGet-Quelle: {value!r}")
    return value


def _winget_validate_version(value: str) -> str:
    from .software import (
        WINGET_VERSION_RE,
    )

    from .environment import die

    value = str(value or "").strip()
    if value and not WINGET_VERSION_RE.fullmatch(value):
        die(f"Ungültige WinGet-Version: {value!r}")
    return value


def _parse_winget_search_table(output: str) -> list[dict[str, str]]:
    """
    WinGet search liefert eine menschenlesbare Tabelle. Neuere Store-Ausgaben
    können die Spalten sehr kompakt mit nur EINEM Leerzeichen ausgeben, z. B.::

        Name      ID           Version
        ------------------------------
        OpenCloud 9PBX43HCMLDQ Unknown

    Daher wird zuerst anhand der Header-Spaltenpositionen (ID/Version) geparst.
    Falls das nicht möglich ist, greift ein defensiver Token-Fallback. "Unknown"
    ist bei msstore eine gültige Versionsanzeige und darf den Treffer nicht
    verwerfen.
    """
    from .software import (
        WINGET_PACKAGE_ID_RE,
    )

    from .execution import strip_ansi

    lines = [strip_ansi(line.rstrip("\r")) for line in str(output or "").splitlines()]
    separator_index = None

    for index, line in enumerate(lines):
        compact = line.strip()
        if len(compact) >= 8 and set(compact) <= {"-", " "} and "-" in compact:
            separator_index = index
            break

    if separator_index is None:
        return []

    header = ""
    for index in range(separator_index - 1, -1, -1):
        if lines[index].strip():
            header = lines[index]
            break

    # ID und Version sind in der WinGet-Ausgabe sprachstabil genug, um ihre
    # Startpositionen als primäre Spaltengrenzen zu verwenden. Zusätzliche
    # Spalten rechts (Match/Source) werden nur best-effort übernommen.
    id_match = re.search(r"(?<!\S)ID(?!\S)", header, flags=re.IGNORECASE)
    version_match = re.search(r"(?<!\S)Version(?!\S)", header, flags=re.IGNORECASE)
    header_tokens = list(re.finditer(r"\S+", header))
    trailing_starts: list[int] = []
    if version_match:
        trailing_starts = [m.start() for m in header_tokens if m.start() > version_match.start()]

    def add_row(rows: list[dict[str, str]], *, name: str, package_id: str,
                version: str, source: str = "") -> None:
        name = name.strip()
        package_id = package_id.strip()
        version = version.strip()
        source = source.strip()
        if not package_id or " " in package_id:
            return
        if not WINGET_PACKAGE_ID_RE.fullmatch(package_id):
            return
        rows.append({
            "name": name or package_id,
            "id": package_id,
            "version": version or "Unknown",
            "source": source,
        })

    rows: list[dict[str, str]] = []
    for raw in lines[separator_index + 1:]:
        if not raw.strip():
            if rows:
                break
            continue

        parsed = False
        if id_match and version_match and id_match.start() < version_match.start():
            id_start = id_match.start()
            version_start = version_match.start()
            next_start = trailing_starts[0] if trailing_starts else None

            name = raw[:id_start].strip()
            package_id = raw[id_start:version_start].strip()
            if next_start is None:
                version = raw[version_start:].strip()
                source = ""
            else:
                version = raw[version_start:next_start].strip()
                tail = raw[next_start:].strip()
                source = tail.split()[-1] if tail else ""

            before = len(rows)
            add_row(rows, name=name, package_id=package_id, version=version, source=source)
            parsed = len(rows) > before

        if parsed:
            continue

        # Fallback für ungewöhnliche/lokalisierte Header. Wir suchen von rechts
        # nach einem Versions-Token und nehmen das direkt davorstehende Token als
        # Paket-ID. So funktioniert auch "OpenCloud 9PBX43HCMLDQ Unknown".
        tokens = raw.strip().split()
        if len(tokens) < 3:
            continue

        version_index = None
        for idx in range(len(tokens) - 1, 0, -1):
            token = tokens[idx]
            folded = token.casefold()
            if (
                folded in {"unknown", "unbekannt", "latest", "aktuell"}
                or re.fullmatch(r"[vV]?\d[0-9A-Za-z_.+~<>:=/-]*", token)
            ):
                if idx >= 1 and WINGET_PACKAGE_ID_RE.fullmatch(tokens[idx - 1]):
                    version_index = idx
                    break

        if version_index is None:
            continue

        package_id = tokens[version_index - 1]
        name = " ".join(tokens[:version_index - 1])
        version = tokens[version_index]
        source = tokens[-1] if version_index < len(tokens) - 1 and tokens[-1].casefold() in {"winget", "msstore"} else ""
        add_row(rows, name=name, package_id=package_id, version=version, source=source)

    unique: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        folded = row["id"].casefold()
        if folded in seen:
            continue
        seen.add(folded)
        unique.append(row)
    return unique

def _run_winget_search_remote(
    *,
    project: Path,
    host: str,
    query: str,
    source: str,
    interactive_user: bool = False,
) -> dict[str, Any]:
    """
    WinGet-Suche auf einem vorhandenen Windows-Referenzhost ausführen.

    Für Microsoft Store (msstore) wird die Suche bewusst über einen temporären
    Scheduled Task mit LogonType=Interactive/RunLevel=Limited im aktuell
    angemeldeten Benutzer ausgeführt. Damit werden WinGet/App-Installer und die
    Store-Quelle aus genau demselben USER-Kontext verwendet wie später bei der
    Installation. Normale WinGet-Suchen können weiterhin direkt im
    Provisioning-Kontext laufen.
    """
    from .environment import (
        atomic_write_yaml,
        project_paths,
    )
    from .execution import (
        create_temporary_vault_password_file,
        strip_ansi,
    )

    powershell = r"""
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Query,
    [Parameter(Mandatory=$true)][string]$Source,
    [bool]$UseInteractiveUser = $false
)
$ErrorActionPreference = 'Stop'

function Invoke-MaviWingetSearch {
    param(
        [Parameter(Mandatory=$true)][string]$SearchQuery,
        [Parameter(Mandatory=$true)][string]$SearchSource
    )

    function Resolve-MaviWinget {
        $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { return [string]$cmd.Source }

        $aliasPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
        if (Test-Path -LiteralPath $aliasPath) { return $aliasPath }

        $pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending |
            Select-Object -First 1
        if ($pkg -and $pkg.InstallLocation) {
            $candidate = Join-Path $pkg.InstallLocation 'winget.exe'
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }

        throw 'winget.exe wurde für diesen Windows-Benutzer nicht gefunden. App Installer/WinGet prüfen.'
    }

    $winget = Resolve-MaviWinget
    $wingetVersion = (& $winget --version 2>&1 | Out-String).Trim()
    $wingetArgs = @(
        'search', '--query', $SearchQuery,
        '--source', $SearchSource,
        '--count', '25',
        '--accept-source-agreements',
        '--disable-interactivity',
        '--nowarn'
    )
    $output = (& $winget @wingetArgs 2>&1 | Out-String)
    $rc = [int64]$LASTEXITCODE

    return [ordered]@{
        Rc = $rc
        Output = $output
        WingetPath = $winget
        WingetVersion = $wingetVersion
        ExecutionUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}

if (-not $UseInteractiveUser) {
    $payload = Invoke-MaviWingetSearch -SearchQuery $Query -SearchSource $Source
}
else {
    $currentUser = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $currentUser) {
        throw 'Kein interaktiv angemeldeter Benutzer gefunden. Microsoft-Store-Suche benötigt eine angemeldete Benutzersitzung.'
    }

    $account = New-Object Security.Principal.NTAccount($currentUser)
    $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    $profilePath = (Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
    $profilePath = [Environment]::ExpandEnvironmentVariables([string]$profilePath)
    $userTemp = Join-Path $profilePath 'AppData\Local\Temp'
    if (-not (Test-Path -LiteralPath $userTemp)) {
        throw "TEMP-Verzeichnis des angemeldeten Benutzers nicht gefunden: $userTemp"
    }

    $guid = [Guid]::NewGuid().ToString('N')
    $taskName = "Mavi_WinGet_Search_$guid"
    $resultFile = Join-Path $userTemp "Mavi-WinGet-Search-$guid.json"

    $queryB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Query))
    $sourceB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Source))
    $resultB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($resultFile))

    $childScript = @"
`$ErrorActionPreference = 'Stop'
function Resolve-MaviWinget {
    `$cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (`$cmd -and `$cmd.Source) { return [string]`$cmd.Source }
    `$aliasPath = Join-Path `$env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
    if (Test-Path -LiteralPath `$aliasPath) { return `$aliasPath }
    `$pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if (`$pkg -and `$pkg.InstallLocation) {
        `$candidate = Join-Path `$pkg.InstallLocation 'winget.exe'
        if (Test-Path -LiteralPath `$candidate) { return `$candidate }
    }
    throw 'winget.exe wurde fuer den angemeldeten Benutzer nicht gefunden. App Installer/WinGet pruefen.'
}
`$Query = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$queryB64'))
`$Source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$sourceB64'))
`$ResultFile = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$resultB64'))
try {
    `$winget = Resolve-MaviWinget
    `$wingetVersion = (& `$winget --version 2>&1 | Out-String).Trim()
    `$args = @('search','--query',`$Query,'--source',`$Source,'--count','25','--accept-source-agreements','--disable-interactivity','--nowarn')
    `$output = (& `$winget @args 2>&1 | Out-String)
    `$rc = [int64]`$LASTEXITCODE
    `$payload = [ordered]@{
        Rc = `$rc
        Output = `$output
        WingetPath = `$winget
        WingetVersion = `$wingetVersion
        ExecutionUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}
catch {
    `$payload = [ordered]@{
        Rc = -1
        Output = (`$_ | Out-String)
        WingetPath = ''
        WingetVersion = ''
        ExecutionUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Error = `$_.Exception.Message
    }
}
`$payload | ConvertTo-Json -Compress -Depth 5 | Set-Content -LiteralPath `$ResultFile -Encoding UTF8 -Force
"@

    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
    )
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    try {
        $before = (Get-ScheduledTaskInfo -TaskName $taskName).LastRunTime
        Start-ScheduledTask -TaskName $taskName
        $deadline = (Get-Date).AddSeconds(75)
        $started = $false
        do {
            Start-Sleep -Milliseconds 500
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
            if ($info.LastRunTime -gt $before) { $started = $true }
            if (Test-Path -LiteralPath $resultFile) { break }
            if ($started -and $task.State -ne 'Running') { break }
        } while ((Get-Date) -lt $deadline)

        if (-not $started) {
            throw "Microsoft-Store-Suchtask fuer '$currentUser' wurde nicht gestartet."
        }
        if (-not (Test-Path -LiteralPath $resultFile)) {
            $last = (Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue).LastTaskResult
            throw "Microsoft-Store-Suche im Benutzerkontext lieferte keine Ergebnisdatei. Task-Code=$last"
        }

        $payload = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
        if (-not $payload.ExecutionUser) {
            $payload | Add-Member -NotePropertyName ExecutionUser -NotePropertyValue $currentUser -Force
        }
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue
    }
}

$json = $payload | ConvertTo-Json -Compress -Depth 5
$marker = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
$Ansible.Result = @{ Marker = $marker }
$Ansible.Changed = $false
"""

    play = [{
        "name": "Mavi WinGet Suche",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "WinGet Paket suchen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "Query": query,
                        "Source": source,
                        "UseInteractiveUser": bool(interactive_user),
                    },
                },
                "register": "mavi_winget_search",
            },
            {
                "name": "Mavi WinGet Suchmarker",
                "ansible.builtin.debug": {
                    "msg": "Mavi_WINGET_SEARCH_B64={{ mavi_winget_search.result.Marker }}"
                },
            },
        ],
    }]

    fd, raw_playbook = tempfile.mkstemp(prefix=".mavi-winget-search-", suffix=".yml")
    os.close(fd)
    playbook_path = Path(raw_playbook)
    vault_password_file: Path | None = None

    try:
        atomic_write_yaml(playbook_path, play)
        vault_password = getpass.getpass("Vault password: ")
        vault_password_file = create_temporary_vault_password_file(vault_password)
        cmd = [
            "ansible-playbook", "-i", str(project_paths(project)["inventory"]),
            str(playbook_path), "--limit", host,
            "--vault-password-file", str(vault_password_file),
        ]
        result = subprocess.run(
            cmd, cwd=str(project), capture_output=True, text=True, timeout=110,
        )
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        match = re.search(r"Mavi_WINGET_SEARCH_B64=([A-Za-z0-9+/=]+)", combined)
        if result.returncode != 0 or not match:
            lines = [line.strip() for line in strip_ansi(combined).splitlines() if line.strip()]
            detail = " | ".join(lines[-10:])
            raise RuntimeError(detail or f"Ansible-Code {result.returncode}")

        decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
        payload = json.loads(decoded)
        if not isinstance(payload, dict):
            raise RuntimeError("WinGet-Suche lieferte unerwartete Daten.")
        return payload
    finally:
        playbook_path.unlink(missing_ok=True)
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)

def cmd_winget_add(args: argparse.Namespace) -> None:
    from .software import (
        _parse_winget_search_table,
        _run_winget_search_remote,
        _winget_validate_identifier,
        _winget_validate_source,
        _winget_validate_version,
        sanitize_catalog_data,
    )

    from .catalogs import (
        backup_parameter_profile,
        choose_catalog_interactive,
        choose_host_interactive,
        get_catalog,
        prompt,
        prompt_choice,
        save_catalog,
        select_from_list,
        slugify,
        validate_software_key,
        yes_no,
    )
    from .environment import (
        die,
        ensure_initialized,
    )
    from .reports import redact_sensitive_text
    from .settings import VERSION

    ensure_initialized(args.project, quiet=True)

    source = _winget_validate_source(getattr(args, "source", None) or "winget")
    is_store = source.lower() == "msstore"
    package_id = str(getattr(args, "package_id", None) or "").strip()
    selected_name = ""
    selected_version = ""

    if not package_id:
        host = getattr(args, "host", None) or choose_host_interactive(args.project)
        query = str(getattr(args, "query", None) or "").strip()
        if not query:
            query = prompt("WinGet-Suche, z. B. vlc")
        if not query:
            die("Kein WinGet-Suchbegriff angegeben.")

        print()
        print("Mavi MICROSOFT STORE-SUCHE" if is_store else "Mavi WINGET-SUCHE")
        print("==========================" if is_store else "=================")
        print(f"Referenz-PC: {host}")
        print(f"Suche:       {query}")
        print(f"Quelle:      {source}")
        print()

        try:
            payload = _run_winget_search_remote(
                project=args.project, host=host, query=query, source=source,
                interactive_user=is_store,
            )
        except Exception as exc:
            print(f"! WinGet-Suche fehlgeschlagen: {exc}")
            print("  Du kannst die exakte Paket-ID trotzdem manuell eingeben.")
            package_id = prompt(
                "Exakte Microsoft-Store-ID, z. B. XP9KHM4BK9FZ7Q"
                if is_store else
                "Exakte WinGet-Paket-ID, z. B. VideoLAN.VLC"
            )
        else:
            rc = int(payload.get("Rc", 1) or 0)
            output = str(payload.get("Output") or "")
            print(
                f"WinGet:      {payload.get('WingetVersion', '?')} "
                f"[{payload.get('WingetPath', '?')}]"
            )
            if payload.get("ExecutionUser"):
                print(f"Benutzer:    {payload.get('ExecutionUser')}")
            rows = _parse_winget_search_table(output)

            if rc != 0 or not rows:
                print()
                print("! Keine automatisch auswählbaren Treffer gefunden.")
                if output.strip():
                    print("WinGet-Ausgabe:")
                    print(output.strip())
                package_id = prompt(
                    "Exakte Microsoft-Store-ID" if is_store else "Exakte WinGet-Paket-ID"
                )
            else:
                print()
                print("Gefundene Microsoft-Store-Apps:" if is_store else "Gefundene Pakete:")
                items: list[tuple[str, str]] = []
                row_by_key: dict[str, dict[str, str]] = {}
                for index, row in enumerate(rows, 1):
                    k = str(index)
                    shown_version = row.get("version") or "?"
                    if is_store and shown_version.casefold() in {"unknown", "unbekannt", "?"}:
                        shown_version = "Store-aktuell"
                    label = f"{row['name']} | {row['id']} | {shown_version}"
                    items.append((k, label))
                    row_by_key[k] = row
                selected = select_from_list(
                    "Microsoft-Store-App auswählen" if is_store else "WinGet-Paket auswählen",
                    items, allow_name=False,
                )
                row = row_by_key[selected]
                package_id = row["id"]
                selected_name = row["name"]
                selected_version = row.get("version", "")

    package_id = _winget_validate_identifier(package_id)
    version = _winget_validate_version(getattr(args, "version", None) or "")

    scope = str(getattr(args, "scope", None) or "").strip().lower()
    if is_store:
        if scope and scope != "user":
            die(
                "Microsoft-Store-Apps werden in Mavi bewusst im USER-Kontext installiert. "
                "Für echtes geräteweites AppX/MSIX-Provisioning wäre ein separater Provisioning-Weg nötig."
            )
        scope = "user"
        version = ""
        if sys.stdin.isatty():
            print()
            print("Installationsbereich: USER / aktuell angemeldeter Benutzer")
            print("Mavi erzwingt für Microsoft-Store-Apps keinen SYSTEM/MACHINE-Scope.")
    else:
        if not scope:
            picked = prompt_choice(
                "WinGet-Installationsbereich:",
                [
                    ("1", "MACHINE / für den ganzen PC"),
                    ("2", "USER / für den aktuell angemeldeten Benutzer"),
                ],
                "1",
            )
            scope = "machine" if picked == "1" else "user"
        if scope not in {"machine", "user"}:
            die("WinGet-Scope muss 'machine' oder 'user' sein.")

        if not version and sys.stdin.isatty():
            print()
            if selected_version:
                print(f"Aktuell gefundene Version: {selected_version}")
            version = _winget_validate_version(
                prompt("Feste Version (Enter = immer aktuelle Version)", "")
            )

    catalog_name = choose_catalog_interactive(
        args.project, getattr(args, "catalog", None), purpose="verwenden", ask_other=True,
    )
    print(f"Zielkatalog: {catalog_name}")

    default_name = selected_name or package_id
    name = getattr(args, "name", None) or prompt("Anzeigename", default_name)
    key = validate_software_key(
        getattr(args, "key", None) or prompt("Katalog-Schlüssel", slugify(name))
    )
    context = "machine" if scope == "machine" else "user_interactive"

    install_timeout_minutes = 30
    if scope == "user":
        while True:
            raw_timeout = prompt("Timeout für USER-WinGet in Minuten", "30")
            try:
                install_timeout_minutes = int(raw_timeout)
            except ValueError:
                print("Bitte eine ganze Zahl in Minuten eingeben.")
                continue
            if install_timeout_minutes < 1:
                print("Timeout muss mindestens 1 Minute sein.")
                continue
            break

    app: dict[str, Any] = {
        "name": name,
        "installer": f"msstore://{package_id}" if is_store else f"winget://{package_id}",
        "type": "winget",
        "context": context,
        "winget_id": package_id,
        "winget_source": source,
        "winget_scope": scope,
        "analysis": {
            "mode": "microsoft_store_catalog" if is_store else "winget_catalog",
            "scanner_version": VERSION,
            "reasons": [
                "Microsoft-Store-ID explizit gespeichert; Installation über WinGet-Quelle msstore im USER-Kontext."
                if is_store else
                "WinGet-Paket-ID explizit gespeichert; Installation mit --id --exact."
            ],
        },
    }
    if is_store:
        app["package_kind"] = "microsoft_store"
    if version:
        app["winget_version"] = version
    if scope == "user":
        app["install_timeout_minutes"] = install_timeout_minutes

    catalog = get_catalog(args.project, catalog_name)
    sw = catalog["software_catalog"]
    existing = sw.get(key)
    if isinstance(existing, dict):
        print()
        print(f"! '{key}' existiert bereits.")
        if not yes_no("Vorhandenen Katalogeintrag überschreiben?", False):
            print("Abgebrochen.")
            return
        backup_parameter_profile(args.project, catalog_name, key, existing)
        print("✓ Vorhandener Eintrag vorher gesichert.")

    app = sanitize_catalog_data(app)
    print()
    print("Wird gespeichert:")
    print(redact_sensitive_text(yaml.safe_dump({key: app}, allow_unicode=True, sort_keys=False).rstrip()))
    if not yes_no("Zum Katalog hinzufügen?", True):
        print("Abgebrochen.")
        return

    sw[key] = app
    save_catalog(args.project, catalog, catalog_name)
    backup_parameter_profile(args.project, catalog_name, key, app)
    print()
    if is_store:
        print(f"✓ Microsoft-Store-App '{package_id}' als '{key}' gespeichert.")
        print("  Backend: WinGet | Quelle: msstore | Scope: USER | Version: Store-aktuell")
    else:
        print(f"✓ WinGet-Paket '{package_id}' als '{key}' gespeichert.")
        print(f"  Scope: {scope.upper()} | Quelle: {source} | Version: {version or 'aktuell'}")


def cmd_store_add(args: argparse.Namespace) -> None:
    """Microsoft-Store-App über den bestehenden WinGet-Unterbau hinzufügen."""
    from .software import (
        cmd_winget_add,
    )

    args.source = "msstore"
    args.scope = "user"
    args.version = None
    cmd_winget_add(args)
