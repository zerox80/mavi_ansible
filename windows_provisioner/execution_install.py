# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Installationsplanung und -ausführung.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    base64,
    getpass,
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



def selected_apps_need_user(
    project: Path,
    names: list[str],
    all_: bool,
    catalog_name: str | None = None,
) -> bool:
    from .catalogs import get_catalog

    catalog = get_catalog(project, catalog_name)["software_catalog"]
    selected = list(catalog.values()) if all_ else [
        catalog[x] for x in names if x in catalog
    ]
    interactive_contexts = {
        "user_non_elevated",
        "user_interactive",
        "machine_interactive",
        "user_uac",
    }
    return any(
        x.get("context") in interactive_contexts
        for x in selected
    )




def _existing_target_installer_processes(
    probe: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    # Nur TARGET zählt. CHILD/RELATED allein führen bewusst nicht zum Skip.
    targets: list[dict[str, Any]] = []

    for item in (probe or {}).get("Processes", []) or []:
        if str(item.get("Role") or "").upper() != "TARGET":
            continue

        try:
            pid = int(item.get("Pid"))
        except (TypeError, ValueError):
            continue

        if pid <= 0:
            continue

        targets.append(item)

    return targets


def _probe_pid_set(probe: dict[str, Any] | None) -> set[int]:
    pids: set[int] = set()
    for item in (probe or {}).get("Processes", []) or []:
        try:
            pids.add(int(item.get("Pid")))
        except (TypeError, ValueError):
            pass
    return pids


def _new_busy_installer_processes(
    probe: dict[str, Any] | None,
    baseline_pids: set[int],
) -> list[dict[str, Any]]:
    """
    Nachlauf-Schutz für Bootstrapper:
    Nur Prozesse berücksichtigen, die beim Start dieses Pakets noch nicht
    existierten. Alte Zombies blockieren dadurch nicht den ganzen Katalog.
    """
    busy: list[dict[str, Any]] = []

    for item in (probe or {}).get("Processes", []) or []:
        try:
            pid = int(item.get("Pid"))
        except (TypeError, ValueError):
            continue

        if pid in baseline_pids:
            continue

        role = str(item.get("Role") or "").upper()
        name = str(item.get("Name") or "").lower()
        command = str(item.get("CommandLine") or "").lower()

        obvious_installer = (
            role in {"TARGET", "CHILD"}
            or name in {
                "msiexec.exe",
                "cwainstaller.exe",
                "bootstrapperhelper.exe",
            }
            or re.match(
                r"^(setup|install|installer|update|updater|bootstrap).*\\.exe$",
                name,
            )
            is not None
            or "\\ctx-" in command
        )

        if obvious_installer:
            busy.append(item)

    return busy


def wait_for_post_install_settle(
    *,
    project: Path,
    host: str,
    app: dict[str, Any],
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    baseline_pids: set[int],
    max_wait_seconds: float = 90.0,
    poll_seconds: float = 5.0,
) -> tuple[bool, str]:
    """
    Verhindert, dass bei einer Katalogserie das nächste Paket startet,
    während ein vom Bootstrapper abgekoppelter Kindprozess noch arbeitet.
    """
    from .execution import (
        _new_busy_installer_processes,
        run_remote_live_probe,
    )

    deadline = time.monotonic() + max(0.0, max_wait_seconds)
    announced = False
    last_busy: list[dict[str, Any]] = []

    while True:
        probe, error = run_remote_live_probe(
            project=project,
            host=host,
            app=app,
            vault_password_file=vault_password_file,
            ansible_session=ansible_session,
            timeout=12.0,
        )

        if probe is None:
            return True, (
                "Nachlauf-Probe nicht verfügbar; fahre kontrolliert fort: "
                + str(error or "unbekannter Probe-Fehler")
            )

        busy = _new_busy_installer_processes(probe, baseline_pids)
        last_busy = busy

        if not busy:
            if announced:
                print("  Nachlauf beendet. Keine neuen Installer-Prozesse mehr aktiv.")
            return True, "Installer-Nachlauf ist ruhig."

        if time.monotonic() >= deadline:
            names = ", ".join(
                f"{item.get('Name', '?')} PID={item.get('Pid', '?')}"
                for item in last_busy[:6]
            )
            return False, (
                f"Nach {max_wait_seconds:g}s laufen noch neue Installer-Prozesse: "
                + (names or "unbekannt")
            )

        if not announced:
            print()
            print("[Mavi SMART] Installer hat noch Nachlaufprozesse.")
            print("  Das nächste Programm startet erst, wenn diese fertig sind")
            print(f"  oder nach maximal {max_wait_seconds:g}s Nachlauf-Wartezeit.")
            announced = True

        names = ", ".join(
            f"{item.get('Name', '?')} PID={item.get('Pid', '?')}"
            for item in busy[:6]
        )
        print(f"  Noch aktiv: {names}")
        time.sleep(max(1.0, poll_seconds))


def wait_for_host_ready(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    max_wait_seconds: float = 180.0,
) -> bool:
    """
    Vor dem nächsten Paket kurz win_ping prüfen. Wenn ein vorheriger Installer
    Windows neu gestartet hat, wartet die Serie auf die Rückkehr des PCs.
    """
    from .execution import (
        _bound_ansible_session_context,
    )

    (
        ansible_executable,
        ansible_python,
        inventory_path,
        runtime_environment,
        transport_vars,
    ) = _bound_ansible_session_context(
        host=host,
        ansible_session=ansible_session,
    )
    ansible_ad_hoc = ansible_executable.with_name("ansible")
    if not ansible_ad_hoc.is_file():
        raise RuntimeError(
            "Das ansible-Kommando fehlt in der erkannten Ansible-Umgebung."
        )

    cmd = [
        str(ansible_python),
        "-I",
        str(ansible_ad_hoc),
        "-i",
        str(inventory_path),
        host,
        "-m",
        "ansible.windows.win_ping",
        "--vault-password-file",
        str(vault_password_file),
    ]
    if transport_vars:
        cmd.extend([
            "--extra-vars",
            json.dumps(transport_vars, ensure_ascii=True, separators=(",", ":")),
        ])

    deadline = time.monotonic() + max(1.0, max_wait_seconds)
    first_failure = True

    while True:

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=20.0,
                env=runtime_environment,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            result = None

        if result is not None and result.returncode == 0:
            if not first_failure:
                print("[Mavi SMART] Windows-PC ist wieder per Ansible erreichbar.")
            return True

        if time.monotonic() >= deadline:
            return False

        if first_failure:
            print()
            print("[Mavi SMART] Ziel-PC antwortet gerade nicht auf win_ping.")
            print("  Falls ein Installer neu gestartet hat, wartet Mavi automatisch")
            print(f"  bis zu {max_wait_seconds:g}s auf die Rückkehr des PCs.")
            first_failure = False

        time.sleep(10.0)



def _installed_precheck_payload(
    catalog: dict[str, Any],
    selected_keys: list[str],
) -> list[dict[str, Any]]:
    # Metadaten fuer den einmaligen Remote-Installed-Check bei --all.
    payload: list[dict[str, Any]] = []

    for key in selected_keys:
        app = catalog.get(key, {})
        installer = str(app.get("installer") or "")
        installer_stem = Path(installer).stem if installer else ""

        aliases: list[str] = []
        for value in (
            str(app.get("name") or ""),
            key.replace("_", " "),
            installer_stem,
            str(app.get("winget_id") or ""),
        ):
            value = value.strip()
            if value and value.casefold() not in {x.casefold() for x in aliases}:
                aliases.append(value)

        payload.append({
            "key": key,
            "name": str(app.get("name") or key),
            "type": str(app.get("type") or ""),
            "creates_path": str(app.get("creates_path") or "").strip(),
            "aliases": aliases,
        })

    return payload


def precheck_installed_apps(
    *,
    project: Path,
    host: str,
    catalog: dict[str, Any],
    selected_keys: list[str],
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    timeout: float = 45.0,
) -> tuple[dict[str, dict[str, Any]], str | None]:
    # Sicherer Precheck vor "Alle Programme".
    #
    # 1) creates_path gesetzt: exakt Test-Path. Falls der Pfad fehlt, wird
    #    NICHT auf einen moeglicherweise alten Registry-Rest ausgewichen.
    # 2) kein creates_path: konservativer Match gegen Windows Uninstall Registry.
    # 3) bei technischem Fehler wird nichts uebersprungen.

    from .execution import (
        _bound_ansible_session_context,
        _installed_precheck_payload,
    )

    if not selected_keys:
        return {}, None

    payload = _installed_precheck_payload(catalog, selected_keys)
    apps_json = json.dumps(payload, ensure_ascii=False)

    powershell = r'''
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$AppsJson
)

function Normalize-Name {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }

    $v = $Value.ToLowerInvariant()
    $v = $v -replace '\.(exe|msi)$', ''
    $v = $v -replace '[^a-z0-9äöüß]+', ' '
    $v = $v -replace '\s+', ' '
    return $v.Trim()
}

function Get-CoreTokens {
    param([string]$Value)

    $normalized = Normalize-Name $Value
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return @()
    }

    $noise = @(
        'setup', 'installer', 'install', 'installation',
        'windows', 'win32', 'win64', 'x86', 'x64', 'amd64',
        '32bit', '64bit', '32', '64',
        'de', 'deu', 'german', 'en', 'eng'
    )

    $tokens = @()

    foreach ($token in ($normalized -split ' ')) {
        if ([string]::IsNullOrWhiteSpace($token)) {
            continue
        }

        if ($noise -contains $token) {
            continue
        }

        if ($token -match '^v?\d+([._-]\d+)*$') {
            continue
        }

        if ($token -match '^\d+$') {
            continue
        }

        $tokens += $token
    }

    return @($tokens)
}

function Test-DisplayNameMatch {
    param(
        [string]$DisplayName,
        [object[]]$Aliases
    )

    $displayNormalized = Normalize-Name $DisplayName
    if ([string]::IsNullOrWhiteSpace($displayNormalized)) {
        return $false
    }

    foreach ($aliasObj in $Aliases) {
        $alias = [string]$aliasObj
        $aliasNormalized = Normalize-Name $alias

        if ([string]::IsNullOrWhiteSpace($aliasNormalized)) {
            continue
        }

        if ($displayNormalized -eq $aliasNormalized) {
            return $true
        }

        $coreTokens = @(Get-CoreTokens $alias)
        if ($coreTokens.Count -eq 0) {
            continue
        }

        $displayTokens = @($displayNormalized -split ' ')

        if ($coreTokens.Count -eq 1) {
            $single = [string]$coreTokens[0]
            if ($single.Length -ge 3 -and
                $displayTokens.Count -gt 0 -and
                $displayTokens[0] -eq $single) {
                return $true
            }
            continue
        }

        $allPresent = $true
        foreach ($token in $coreTokens) {
            if (-not ($displayTokens -contains [string]$token)) {
                $allPresent = $false
                break
            }
        }

        if ($allPresent) {
            return $true
        }
    }

    return $false
}

$registryRows = @()

$machinePaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

foreach ($path in $machinePaths) {
    $scope = if ($path -like '*WOW6432Node*') { 'HKLM-32' } else { 'HKLM-64' }
    $items = @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)

    foreach ($item in $items) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item.DisplayName)) {
            $registryRows += [pscustomobject]@{
                DisplayName = [string]$item.DisplayName
                DisplayVersion = [string]$item.DisplayVersion
                Scope = $scope
            }
        }
    }
}

$userRoots = @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue)

foreach ($root in $userRoots) {
    $sid = [string]$root.PSChildName

    if ($sid -notmatch '^S-1-5-21-' -and $sid -notmatch '^S-1-12-1-') {
        continue
    }

    $userPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $items = @(Get-ItemProperty -Path $userPath -ErrorAction SilentlyContinue)

    foreach ($item in $items) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item.DisplayName)) {
            $registryRows += [pscustomobject]@{
                DisplayName = [string]$item.DisplayName
                DisplayVersion = [string]$item.DisplayVersion
                Scope = "HKU:$sid"
            }
        }
    }
}

$shortcutRows = @()

$shortcutRoots = @(
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'
)

foreach ($root in $userRoots) {
    $sid = [string]$root.PSChildName

    if ($sid -notmatch '^S-1-5-21-' -and $sid -notmatch '^S-1-12-1-') {
        continue
    }

    try {
        $profilePath = (Get-ItemProperty "Registry::HKEY_USERS\$sid\Volatile Environment" -ErrorAction SilentlyContinue).USERPROFILE
        if (-not [string]::IsNullOrWhiteSpace([string]$profilePath)) {
            $shortcutRoots += (Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs')
        }
    }
    catch {
    }
}

foreach ($shortcutRoot in ($shortcutRoots | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $shortcutRoot)) {
        continue
    }

    $shortcuts = @(Get-ChildItem -LiteralPath $shortcutRoot -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue)
    foreach ($shortcut in $shortcuts) {
        $shortcutRows += [pscustomobject]@{
            Name = [string]$shortcut.BaseName
            Path = [string]$shortcut.FullName
        }
    }
}

$programDirRows = @()

foreach ($programRoot in @('C:\Program Files', 'C:\Program Files (x86)')) {
    if (-not (Test-Path -LiteralPath $programRoot)) {
        continue
    }

    $dirs = @(Get-ChildItem -LiteralPath $programRoot -Directory -ErrorAction SilentlyContinue)
    foreach ($dir in $dirs) {
        $programDirRows += [pscustomobject]@{
            Name = [string]$dir.Name
            Path = [string]$dir.FullName
        }
    }
}

$apps = @($AppsJson | ConvertFrom-Json)
$result = @{}

foreach ($app in $apps) {
    $key = [string]$app.key
    $createsPath = [string]$app.creates_path

    $entry = [ordered]@{
        installed = $false
        method = 'none'
        reason = 'Kein sicherer Installed-Nachweis gefunden.'
        matched_name = ''
        matched_version = ''
        matched_scope = ''
    }

    if (-not [string]::IsNullOrWhiteSpace($createsPath)) {
        if (Test-Path -LiteralPath $createsPath) {
            $entry.installed = $true
            $entry.method = 'creates_path'
            $entry.reason = "creates_path existiert: $createsPath"
        }
        else {
            $entry.method = 'creates_path_missing'
            $entry.reason = "creates_path fehlt: $createsPath; Registry-Fallback absichtlich nicht verwendet."
        }
    }
    else {
        foreach ($row in $registryRows) {
            if (Test-DisplayNameMatch -DisplayName $row.DisplayName -Aliases @($app.aliases)) {
                $entry.installed = $true
                $entry.method = 'uninstall_registry'
                $entry.matched_name = [string]$row.DisplayName
                $entry.matched_version = [string]$row.DisplayVersion
                $entry.matched_scope = [string]$row.Scope

                $versionText = if ([string]::IsNullOrWhiteSpace([string]$row.DisplayVersion)) {
                    ''
                }
                else {
                    " Version $($row.DisplayVersion)"
                }

                $entry.reason = "Windows Uninstall-Registry: $($row.DisplayName)$versionText [$($row.Scope)]"
                break
            }
        }

        if (-not $entry.installed) {
            foreach ($shortcut in $shortcutRows) {
                if (Test-DisplayNameMatch -DisplayName $shortcut.Name -Aliases @($app.aliases)) {
                    $entry.installed = $true
                    $entry.method = 'start_menu'
                    $entry.matched_name = [string]$shortcut.Name
                    $entry.matched_scope = 'StartMenu'
                    $entry.reason = "Startmenü-Eintrag gefunden: $($shortcut.Path)"
                    break
                }
            }
        }

        if (-not $entry.installed) {
            foreach ($dir in $programDirRows) {
                if (Test-DisplayNameMatch -DisplayName $dir.Name -Aliases @($app.aliases)) {
                    $entry.installed = $true
                    $entry.method = 'program_files'
                    $entry.matched_name = [string]$dir.Name
                    $entry.matched_scope = 'ProgramFiles'
                    $entry.reason = "Programmordner gefunden: $($dir.Path)"
                    break
                }
            }
        }
    }

    $result[$key] = $entry
}

$json = $result | ConvertTo-Json -Compress -Depth 8
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$marker = [Convert]::ToBase64String($bytes)

$Ansible.Result = @{
    Marker = $marker
    CheckedApps = $apps.Count
}
$Ansible.Changed = $false
'''

    play = [{
        "name": "Mavi Installed-Precheck",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Installierte Programme vor Kataloglauf erkennen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "AppsJson": apps_json,
                    },
                },
                "register": "mavi_installed_precheck",
            },
            {
                "name": "Mavi Installed-Precheck Marker",
                "ansible.builtin.debug": {
                    "msg": "Mavi_INSTALLED_PRECHECK_B64={{ mavi_installed_precheck.result.Marker }}"
                },
            },
        ],
    }]

    tmp_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".yml",
            prefix="mavi-installed-precheck-",
            delete=False,
        ) as fh:
            yaml.safe_dump(
                play,
                fh,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
            tmp_path = Path(fh.name)

        (
            ansible_executable,
            ansible_python,
            inventory_path,
            runtime_environment,
            transport_vars,
        ) = _bound_ansible_session_context(
            host=host,
            ansible_session=ansible_session,
        )

        cmd = [
            str(ansible_python),
            "-I",
            str(ansible_executable),
            "-i",
            str(inventory_path),
            str(tmp_path),
            "--limit",
            host,
            "--vault-password-file",
            str(vault_password_file),
        ]
        if transport_vars:
            cmd.extend([
                "--extra-vars",
                json.dumps(transport_vars, ensure_ascii=True, separators=(",", ":")),
            ])

        try:
            completed = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=max(5.0, timeout),
                env=runtime_environment,
            )
        except subprocess.TimeoutExpired:
            return {}, (
                f"Installed-Precheck nach {timeout:g}s ohne Antwort. "
                "Aus Sicherheitsgruenden wird nichts uebersprungen."
            )
        except FileNotFoundError:
            return {}, (
                "ansible-playbook wurde nicht gefunden. "
                "Aus Sicherheitsgruenden wird nichts uebersprungen."
            )

        combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
        match = re.search(
            r"Mavi_INSTALLED_PRECHECK_B64=([A-Za-z0-9+/=]+)",
            combined,
        )

        if completed.returncode != 0 or not match:
            detail = ""
            meaningful = [
                line.strip()
                for line in combined.splitlines()
                if line.strip()
            ]
            if meaningful:
                detail = " Letzte Ausgabe: " + meaningful[-1][:240]

            return {}, (
                "Installed-Precheck konnte nicht sicher ausgewertet werden."
                + detail
                + " Es wird nichts uebersprungen."
            )

        try:
            raw = base64.b64decode(match.group(1)).decode("utf-8")
            decoded = json.loads(raw)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {}, (
                f"Installed-Precheck lieferte ungueltige Daten ({exc}). "
                "Es wird nichts uebersprungen."
            )

        if not isinstance(decoded, dict):
            return {}, (
                "Installed-Precheck lieferte kein Dictionary. "
                "Es wird nichts uebersprungen."
            )

        clean: dict[str, dict[str, Any]] = {}

        for key, value in decoded.items():
            if isinstance(value, dict):
                clean[str(key)] = value

        return clean, None

    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def _build_install_command(
    *,
    project: Path,
    playbook: Path,
    host: str,
    catalog_file: Path,
    software_names: list[str],
    target_user: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    check: bool,
) -> list[str]:
    from .execution import (
        _bound_ansible_session_context,
    )

    extra = {
        "catalog_file": str(catalog_file),
        "install_all": False,
        "software_names": software_names,
        "target_user": target_user,
    }
    (
        ansible_executable,
        ansible_python,
        inventory_path,
        _runtime_environment,
        transport_vars,
    ) = _bound_ansible_session_context(
        host=host,
        ansible_session=ansible_session,
    )
    extra.update(transport_vars)

    cmd = [
        str(ansible_python),
        "-I",
        str(ansible_executable),
        "-i",
        str(inventory_path),
        str(playbook),
        "--limit",
        host,
        "--vault-password-file",
        str(vault_password_file),
        "-e",
        json.dumps(extra, ensure_ascii=False),
    ]

    if check:
        cmd.append("--check")

    return cmd


def cmd_install(args: argparse.Namespace) -> None:
    from .execution import (
        _build_install_command,
        _existing_target_installer_processes,
        _probe_pid_set,
        create_temporary_vault_password_file,
        precheck_installed_apps,
        run_install_subprocess,
        run_remote_live_probe,
        selected_apps_need_user,
        wait_for_host_ready,
        wait_for_post_install_settle,
    )

    from .catalogs import (
        _validate_catalog_for_persistence,
        catalog_path,
        get_catalog,
        prompt,
        resolve_catalog_name,
    )
    from .environment import (
        die,
        ensure_initialized,
        project_paths,
    )
    from .remote import (
        _close_client_ansible_session,
        _host_inventory_entry,
        _open_client_ansible_session,
    )
    from .reports import redact_sensitive_text

    ensure_initialized(args.project, quiet=True)
    p = project_paths(args.project)

    # --limit darf hier niemals ein Ansible-Muster wie "all", "windows"
    # oder "PC-*" erhalten. Nur ein exakt vorhandener Windows-Host ist gültig.
    _inventory, _windows, _host_data = _host_inventory_entry(
        args.project,
        str(args.host),
    )
    del _inventory, _windows, _host_data

    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    selected_catalog_path = catalog_path(args.project, catalog_name)
    catalog = get_catalog(args.project, catalog_name)["software_catalog"]

    print(f"Katalog: {catalog_name}")

    if args.all:
        if not catalog:
            die(f"Katalog '{catalog_name}' ist leer.")
        names: list[str] = []
    else:
        names = args.software or []
        if not names:
            die("Software angeben oder --all verwenden.")
        missing = [x for x in names if x not in catalog]
        if missing:
            die(
                f"Nicht im Katalog '{catalog_name}': "
                + ", ".join(missing)
            )

    selected_keys = list(catalog.keys()) if args.all else names
    _validate_catalog_for_persistence(
        {
            "software_catalog": {
                key: catalog[key]
                for key in selected_keys
            }
        },
        require_installer_integrity=True,
    )

    target_user = args.target_user or ""
    if (
        selected_apps_need_user(
            args.project,
            names,
            args.all,
            catalog_name,
        )
        and not target_user
        and sys.stdin.isatty()
    ):
        print(
            "\nMindestens ein Paket benötigt einen sichtbaren INTERAKTIVEN Benutzerkontext.\n"
            "Enter = aktuell am Windows-PC angemeldeten Benutzer automatisch verwenden."
        )
        target_user = prompt(
            "Zielbenutzer, z. B. EXAMPLE\\Max.Mustermann",
            "",
        )

    live_apps = {
        key: catalog[key]
        for key in selected_keys
        if key in catalog
    }

    status_interval = float(
        getattr(args, "status_interval", 10.0)
    )
    live_probe_enabled = bool(getattr(args, "live_probe", True))
    sequence_mode = len(selected_keys) > 1

    print()
    print("Mavi INSTALLPLAN")
    print("===============")

    for index, key in enumerate(selected_keys, 1):
        app = catalog.get(key, {})
        app_name = app.get("name", key)
        context = app.get("context", "machine")
        installer = (
            f"WinGet:{app.get('winget_id', '?')}"
            if str(app.get("type") or "").lower() == "winget"
            else (Path(str(app.get("installer", ""))).name or "(unbekannt)")
        )
        arguments = app.get("arguments")

        if arguments in (None, ""):
            arguments = "(KEINE)"
        else:
            arguments = redact_sensitive_text(arguments)

        print(
            f"  {index:02d}. {key}: {app_name} | "
            f"{context} | {installer} | "
            f"Parameter: {arguments}"
        )

    print()
    print(
        f"Live-Status während laufender Installer: "
        f"alle {status_interval:g}s"
    )
    print(
        "Remote-Prozess-/Log-Probe: "
        + ("AKTIV" if live_probe_enabled else "AUS")
    )

    if sequence_mode:
        print()
        print("Mavi SMART-SEQUENZ: AKTIV")
        print("  Programme werden strikt NACHEINANDER installiert.")
        if args.all and not args.check:
            print("  Bereits installierte Programme werden VOR dem Installerstart erkannt und übersprungen.")
            print("  Läuft derselbe Setup-Installer bereits, wird KEINE Doppelinstanz gestartet.")
        print("  Das nächste startet erst nach Ende/Timeout des aktuellen Pakets.")
        print("  Ein einzelner Paketfehler beendet die restliche Liste NICHT.")
        if live_probe_enabled and not args.check:
            print("  Abgekoppelte neue Installer-Kindprozesse bekommen bis zu 90s Nachlauf.")
        print("  Nach einem möglichen Windows-Neustart wartet Mavi vor dem nächsten Paket auf win_ping.")

    vault_password = getpass.getpass("Vault password: ")
    vault_password_file = create_temporary_vault_password_file(vault_password)
    ansible_session: dict[str, Any] | None = None
    try:
        ansible_session = _open_client_ansible_session(
            project=args.project,
            host=args.host,
            vault_password_file=vault_password_file,
        )
    except RuntimeError as exc:
        vault_password_file.unlink(missing_ok=True)
        die(str(exc), code=2)

    results: list[dict[str, Any]] = []

    installed_precheck: dict[str, dict[str, Any]] = {}

    try:
        if args.all and not args.check:
            print()
            print("[Mavi SMART] Prüfe zuerst, welche Programme bereits installiert sind ...")

            installed_precheck, precheck_error = precheck_installed_apps(
                project=args.project,
                host=args.host,
                catalog=catalog,
                selected_keys=selected_keys,
                vault_password_file=vault_password_file,
                ansible_session=ansible_session,
                timeout=45.0,
            )

            if precheck_error:
                print("[Mavi SMART] WARNUNG: " + precheck_error)
                print("  Der Kataloglauf geht normal weiter; es wird nichts blind übersprungen.")
            else:
                installed_count = sum(
                    1
                    for value in installed_precheck.values()
                    if bool(value.get("installed"))
                )
                print(
                    f"[Mavi SMART] Installed-Precheck fertig: "
                    f"{installed_count} von {len(selected_keys)} Paket(en) "
                    "sicher als bereits installiert erkannt."
                )

        for index, key in enumerate(selected_keys, 1):
            app = catalog[key]
            app_name = str(app.get("name") or key)

            if index > 1 and sequence_mode and not args.check:
                if not wait_for_host_ready(
                    project=args.project,
                    host=args.host,
                    vault_password_file=vault_password_file,
                    ansible_session=ansible_session,
                    max_wait_seconds=180.0,
                ):
                    print()
                    print("[Mavi SMART] Ziel-PC ist nach 180s nicht erreichbar.")
                    print("  Die verbleibenden Pakete können ohne Verbindung nicht sicher gestartet werden.")
                    for remaining_key in selected_keys[index - 1:]:
                        results.append({
                            "key": remaining_key,
                            "rc": 4,
                            "status": "NICHT GESTARTET",
                            "note": "Ziel-PC nicht erreichbar",
                        })
                    break

            print()
            print("=" * 72)
            print(f"Mavi PAKET {index}/{len(selected_keys)}: {key} | {app_name}")
            print("=" * 72)

            detected = installed_precheck.get(key, {}) if args.all else {}

            if bool(detected.get("installed")):
                reason = str(
                    detected.get("reason")
                    or "Bereits installiert."
                )

                print("[Mavi SMART] BEREITS INSTALLIERT -> Installer wird NICHT gestartet.")
                print("  Nachweis: " + reason)

                results.append({
                    "key": key,
                    "rc": 0,
                    "status": "BEREITS DA",
                    "note": reason,
                })
                continue

            baseline_pids: set[int] = set()
            baseline_probe: dict[str, Any] | None = None

            if sequence_mode and live_probe_enabled and not args.check:
                baseline_probe, baseline_error = run_remote_live_probe(
                    project=args.project,
                    host=args.host,
                    app=app,
                    vault_password_file=vault_password_file,
                    ansible_session=ansible_session,
                    timeout=12.0,
                )

                if baseline_probe is not None:
                    baseline_pids = _probe_pid_set(baseline_probe)

                    already_running = _existing_target_installer_processes(
                        baseline_probe
                    )

                    if already_running:
                        details = ", ".join(
                            f"{item.get('Name', '?')} PID={item.get('Pid', '?')} "
                            f"Laufzeit={item.get('Runtime', '?')}"
                            for item in already_running[:6]
                        )

                        print(
                            "[Mavi SMART] INSTALLER LÄUFT BEREITS -> "
                            "kein zweites Exemplar wird gestartet."
                        )
                        print("  Gefunden: " + details)
                        print(
                            "  Paket wird übersprungen. So blockiert eine "
                            "alte/laufende Setup-Instanz nicht den Gesamtlauf."
                        )

                        results.append({
                            "key": key,
                            "rc": 0,
                            "status": "LÄUFT BEREITS",
                            "note": details,
                        })
                        continue

                elif baseline_error:
                    print(
                        "[Mavi SMART] Start-Baseline für Nachlauf nicht verfügbar: "
                        + baseline_error
                    )

            cmd = _build_install_command(
                project=args.project,
                playbook=p["playbook"],
                host=args.host,
                catalog_file=selected_catalog_path,
                software_names=[key],
                target_user=target_user,
                vault_password_file=vault_password_file,
                ansible_session=ansible_session,
                check=bool(args.check),
            )

            return_code = run_install_subprocess(
                cmd,
                args.project,
                host=args.host,
                apps={key: app},
                ansible_session=ansible_session,
                status_interval=status_interval,
                vault_password_file=vault_password_file,
                live_probe=live_probe_enabled,
            )

            if return_code == 130:
                results.append({
                    "key": key,
                    "rc": return_code,
                    "status": "ABGEBROCHEN",
                    "note": "Benutzerabbruch",
                })
                break

            settle_ok = True
            settle_note = ""
            if (
                sequence_mode
                and live_probe_enabled
                and not args.check
            ):
                settle_ok, settle_note = wait_for_post_install_settle(
                    project=args.project,
                    host=args.host,
                    app=app,
                    vault_password_file=vault_password_file,
                    ansible_session=ansible_session,
                    baseline_pids=baseline_pids,
                    max_wait_seconds=90.0,
                    poll_seconds=5.0,
                )

                if not settle_ok:
                    print()
                    print("[Mavi SMART] WARNUNG: " + settle_note)
                    print("  Die Serie läuft trotzdem weiter, damit ein Paket den gesamten Katalog nicht blockiert.")

            results.append({
                "key": key,
                "rc": return_code,
                "status": "OK" if return_code == 0 else "FEHLER",
                "note": settle_note if not settle_ok else "",
            })

            if return_code != 0 and sequence_mode:
                print()
                print(
                    f"[Mavi SMART] '{key}' endete mit Code {return_code}. "
                    "Das nächste Paket wird trotzdem versucht."
                )

    finally:
        _close_client_ansible_session(ansible_session)
        vault_password_file.unlink(missing_ok=True)

    print()
    print("Mavi INSTALL-ZUSAMMENFASSUNG")
    print("==========================")
    for item in results:
        note = f" | {item['note']}" if item.get("note") else ""
        print(
            f"  {item['status']:<15} {item['key']} "
            f"(Code {item['rc']}){note}"
        )

    if any(item.get("rc") == 130 for item in results):
        raise SystemExit(130)

    failed = [
        item for item in results
        if int(item.get("rc", 1)) != 0
    ]

    if failed:
        print()
        print(
            f"{len(failed)} von {len(results)} Paket(en) waren nicht erfolgreich. "
            "Alle sicher erreichbaren Pakete wurden trotzdem abgearbeitet."
        )
        raise SystemExit(2)

    print()
    print(f"Alle {len(results)} Paket(e) erfolgreich abgeschlossen.")
    raise SystemExit(0)
