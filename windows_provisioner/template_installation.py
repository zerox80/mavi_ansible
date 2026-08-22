# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Ansible-Vorlagen für Softwareinstallation und Diagnose.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations


PLAYBOOK_TEMPLATE = r"""---
- name: Software aus Mavi-Katalog installieren
  hosts: windows
  gather_facts: false

  vars_files:
    - "{{ catalog_file }}"

  pre_tasks:
    - name: Gewünschte Software bestimmen
      ansible.builtin.set_fact:
        requested_software: >-
          {{
            (software_catalog.keys() | list)
            if (install_all | default(false) | bool)
            else (software_names | default([]))
          }}

    - name: Prüfen, ob mindestens ein Paket gewählt wurde
      ansible.builtin.assert:
        that:
          - requested_software | length > 0
        fail_msg: "Keine Software ausgewählt."

    - name: Prüfen, ob alle Paketnamen im Katalog existieren
      ansible.builtin.assert:
        that:
          - item in software_catalog
        fail_msg: "Software '{{ item }}' ist nicht im Katalog vorhanden."
      loop: "{{ requested_software }}"

  tasks:
    - name: Gewählte Software installieren
      ansible.builtin.include_tasks: tasks/install_one.yml
      loop: "{{ requested_software }}"
      loop_control:
        loop_var: software_key
        label: "{{ software_key }}"
"""

TASK_TEMPLATE = r"""---
- name: "{{ software_key }} | Paketdaten laden"
  ansible.builtin.set_fact:
    app: "{{ software_catalog[software_key] }}"
  no_log: true

- name: "{{ software_key }} | Quelldatei auf dem Ansible-Server prüfen"
  ansible.builtin.stat:
    path: "{{ app.installer }}"
    get_checksum: true
    checksum_algorithm: sha256
  delegate_to: localhost
  register: source_installer
  become: false
  when: app.type | lower != 'winget'

- name: "{{ software_key }} | Abbrechen, wenn Installer fehlt"
  ansible.builtin.assert:
    that:
      - source_installer.stat.exists
      - source_installer.stat.isreg
    fail_msg: "Installer fehlt auf dem Ansible-Server: {{ app.installer }}"
  when: app.type | lower != 'winget'

- name: "{{ software_key }} | Erwarteten SHA-256 normalisieren"
  ansible.builtin.set_fact:
    mavi_expected_installer_sha256: >-
      {{ app.sha256 | default('') | string | trim | lower }}
    mavi_allow_unsafe_missing_sha256: >-
      {{ app.allow_unsafe_missing_sha256 | default(false) | bool }}
  when: app.type | lower != 'winget'

- name: "{{ software_key }} | Gespeicherten SHA-256 validieren"
  ansible.builtin.assert:
    that:
      - mavi_expected_installer_sha256 is match('^[0-9a-f]{64}$')
    fail_msg: >-
      SICHERHEITSABBRUCH: Der gespeicherte SHA-256 für
      '{{ software_key }}' ist ungültig. Erwartet werden exakt 64
      hexadezimale Zeichen.
  when:
    - app.type | lower != 'winget'
    - mavi_expected_installer_sha256 | length > 0

- name: "{{ software_key }} | Lokalen Installer-Hash erzwingen"
  ansible.builtin.assert:
    that:
      - source_installer.stat.checksum | default('') | lower == mavi_expected_installer_sha256
    fail_msg: >-
      SICHERHEITSABBRUCH: SHA-256 der lokalen Installer-Datei stimmt
      nicht mit dem Katalog überein. Erwartet={{ mavi_expected_installer_sha256 }},
      Ist={{ source_installer.stat.checksum | default('(fehlt)') }}.
  when:
    - app.type | lower != 'winget'
    - mavi_expected_installer_sha256 | length > 0

- name: "{{ software_key }} | Fehlenden Installer-Hash standardmäßig sperren"
  ansible.builtin.assert:
    that:
      - mavi_expected_installer_sha256 | length > 0 or mavi_allow_unsafe_missing_sha256
    fail_msg: >-
      SICHERHEITSABBRUCH: Für '{{ software_key }}' fehlt SHA-256.
      Lokale Installer sind standardmäßig fail-closed. Nur eine bewusst im
      Katalog gesetzte Legacy-Ausnahme allow_unsafe_missing_sha256: true
      darf ohne Hash fortfahren.
  when:
    - app.type | lower != 'winget'
    - mavi_expected_installer_sha256 | length == 0

- name: "{{ software_key }} | Explizite Legacy-Ausnahme anzeigen"
  ansible.builtin.debug:
    msg: >-
      UNSICHERE AUSNAHME AKTIV: '{{ software_key }}' wird ausdrücklich ohne
      SHA-256-Bindung installiert.
  when:
    - app.type | lower != 'winget'
    - mavi_expected_installer_sha256 | length == 0
    - mavi_allow_unsafe_missing_sha256

- name: "{{ software_key }} | Remote-Pfade bestimmen"
  ansible.builtin.set_fact:
    installer_filename: "{{ app.installer | basename }}"
    remote_installer: "C:\\Mavi-Provisioner\\Installers\\{{ app.installer | basename }}"

- name: "{{ software_key }} | Installer-Verzeichnis erstellen"
  ansible.windows.win_file:
    path: 'C:\Mavi-Provisioner\Installers'
    state: directory

- name: "{{ software_key }} | Installer auf Windows kopieren"
  ansible.windows.win_copy:
    src: "{{ app.installer }}"
    dest: "{{ remote_installer }}"
  when: app.type | lower != 'winget'

- name: "{{ software_key }} | Kopierten Installer auf Windows hashen"
  ansible.windows.win_stat:
    path: "{{ remote_installer }}"
    get_checksum: true
    checksum_algorithm: sha256
  register: mavi_remote_installer_hash
  when:
    - app.type | lower != 'winget'
    - mavi_expected_installer_sha256 | length > 0

- name: "{{ software_key }} | Remote-Installer-Hash erzwingen"
  ansible.builtin.assert:
    that:
      - mavi_remote_installer_hash.stat.exists | default(false)
      - mavi_remote_installer_hash.stat.checksum | default('') | lower == mavi_expected_installer_sha256
    fail_msg: >-
      SICHERHEITSABBRUCH: SHA-256 der auf Windows kopierten Datei stimmt
      nicht mit dem Katalog überein. Erwartet={{ mavi_expected_installer_sha256 }},
      Ist={{ mavi_remote_installer_hash.stat.checksum | default('(fehlt)') }}.
  when:
    - app.type | lower != 'winget'
    - mavi_expected_installer_sha256 | length > 0

- name: "{{ software_key }} | WinGet Laufdaten bestimmen"
  ansible.builtin.set_fact:
    winget_package_id: "{{ app.winget_id | default('') }}"
    winget_source: "{{ app.winget_source | default('winget') }}"
    winget_scope: "{{ app.winget_scope | default('machine') }}"
    winget_version: "{{ app.winget_version | default('') }}"
    winget_script_path: >-
      C:\Mavi-Provisioner\Installers\Mavi-WinGet-{{ software_key | regex_replace('[^A-Za-z0-9_-]', '_') }}.ps1
    winget_result_path: >-
      C:\Mavi-Provisioner\Installers\Mavi-WinGet-{{ software_key | regex_replace('[^A-Za-z0-9_-]', '_') }}.json
  when: app.type | lower == 'winget'

- name: "{{ software_key }} | WinGet Katalogdaten prüfen"
  ansible.builtin.assert:
    that:
      - winget_package_id | length > 0
      - winget_package_id is match('^[A-Za-z0-9][A-Za-z0-9_.+-]{1,200}$')
      - winget_scope in ['machine', 'user']
      - winget_source | length > 0
      - winget_source is match('^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$')
      - winget_version | length == 0 or winget_version is match('^[A-Za-z0-9][A-Za-z0-9_.+~-]{0,100}$')
    fail_msg: >-
      Ungültiger WinGet-Katalogeintrag. Erwartet werden winget_id,
      winget_scope=machine|user und winget_source.
  when: app.type | lower == 'winget'

- name: "{{ software_key }} | WinGet Hilfsskript bereitstellen"
  ansible.windows.win_copy:
    dest: "{{ winget_script_path }}"
    content: |
      [CmdletBinding()]
      param(
          [Parameter(Mandatory=$true)][string]$PackageId,
          [Parameter(Mandatory=$true)][ValidateSet('machine','user')][string]$Scope,
          [Parameter(Mandatory=$true)][string]$Source,
          [string]$Version = '',
          [Parameter(Mandatory=$true)][string]$ResultFile
      )

      $ErrorActionPreference = 'Stop'

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

          throw 'winget.exe wurde für diesen Benutzer nicht gefunden. Windows App Installer / WinGet prüfen.'
      }

      function Write-MaviResult {
          param(
              [bool]$Success,
              [bool]$Changed,
              [bool]$AlreadyInstalled,
              [Int64]$Rc,
              [string]$Output,
              [string]$WingetPath,
              [string]$WingetVersion,
              [string]$Action
          )
          $hex = ''
          try { $hex = ('0x{0:X8}' -f ([uint32]$Rc)) } catch {}
          [ordered]@{
              Success = $Success
              Changed = $Changed
              AlreadyInstalled = $AlreadyInstalled
              Rc = $Rc
              RcHex = $hex
              Output = $Output
              WingetPath = $WingetPath
              WingetVersion = $WingetVersion
              PackageId = $PackageId
              Scope = $Scope
              Source = $Source
              Version = $Version
              Action = $Action
          } | ConvertTo-Json -Compress -Depth 6 |
              Set-Content -LiteralPath $ResultFile -Encoding UTF8
      }

      Remove-Item -LiteralPath $ResultFile -Force -ErrorAction SilentlyContinue

      try {
          $winget = Resolve-MaviWinget
          $wingetVer = (& $winget --version 2>&1 | Out-String).Trim()

          $listArgs = @(
              'list', '--id', $PackageId, '--exact',
              '--source', $Source,
              '--accept-source-agreements',
              '--disable-interactivity'
          )
          $listOutput = (& $winget @listArgs 2>&1 | Out-String)
          $listRc = [Int64]$LASTEXITCODE
          $pattern = '(?im)(^|\s)' + [regex]::Escape($PackageId) + '(\s|$)'
          $alreadyInstalled = ($listOutput -match $pattern)

          if ($alreadyInstalled) {
              Write-MaviResult -Success $true -Changed $false -AlreadyInstalled $true `
                  -Rc 0 -Output $listOutput -WingetPath $winget `
                  -WingetVersion $wingetVer -Action 'already_installed'
              exit 0
          }

          $installArgs = @(
              'install', '--id', $PackageId, '--exact',
              '--source', $Source,
              '--scope', $Scope,
              '--silent',
              '--accept-source-agreements',
              '--accept-package-agreements',
              '--disable-interactivity',
              '--no-upgrade'
          )
          if (-not [string]::IsNullOrWhiteSpace($Version)) {
              $installArgs += @('--version', $Version)
          }

          $installOutput = (& $winget @installArgs 2>&1 | Out-String)
          $rc = [Int64]$LASTEXITCODE
          $success = ($rc -eq 0)
          Write-MaviResult -Success $success -Changed $success -AlreadyInstalled $false `
              -Rc $rc -Output $installOutput -WingetPath $winget `
              -WingetVersion $wingetVer -Action 'install'

          if (-not $success) { exit 1 }
          exit 0
      }
      catch {
          $message = $_.Exception.Message
          Write-MaviResult -Success $false -Changed $false -AlreadyInstalled $false `
              -Rc 1 -Output $message -WingetPath '' -WingetVersion '' -Action 'exception'
          exit 1
      }
  when: app.type | lower == 'winget'

- name: "{{ software_key }} | Alte WinGet Ergebnisdatei entfernen"
  ansible.windows.win_file:
    path: "{{ winget_result_path }}"
    state: absent
  when: app.type | lower == 'winget'

- name: "{{ software_key }} | WinGet MACHINE installieren"
  ansible.windows.win_command:
    cmd: >-
      powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
      -File "{{ winget_script_path }}"
      -PackageId "{{ winget_package_id }}"
      -Scope machine
      -Source "{{ winget_source }}"
      -Version "{{ winget_version }}"
      -ResultFile "{{ winget_result_path }}"
  register: mavi_winget_machine_command
  failed_when: false
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'machine'

- name: "{{ software_key }} | WinGet MACHINE Ergebnis lesen"
  ansible.windows.win_powershell:
    error_action: stop
    script: |
      param([Parameter(Mandatory=$true)][string]$ResultFile)
      if (-not (Test-Path -LiteralPath $ResultFile)) {
          throw "WinGet-Ergebnisdatei fehlt: $ResultFile"
      }
      $data = Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json
      $Ansible.Result = @{
          Success = [bool]$data.Success
          Changed = [bool]$data.Changed
          AlreadyInstalled = [bool]$data.AlreadyInstalled
          Rc = [Int64]$data.Rc
          RcHex = [string]$data.RcHex
          Output = [string]$data.Output
          WingetPath = [string]$data.WingetPath
          WingetVersion = [string]$data.WingetVersion
          PackageId = [string]$data.PackageId
          Scope = [string]$data.Scope
          Action = [string]$data.Action
      }
      $Ansible.Changed = [bool]$data.Changed
    parameters:
      ResultFile: "{{ winget_result_path }}"
  register: mavi_winget_machine_result
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'machine'

- name: "{{ software_key }} | WinGet MACHINE Hilfsdateien entfernen"
  ansible.windows.win_file:
    path: "{{ item }}"
    state: absent
  loop:
    - "{{ winget_script_path }}"
    - "{{ winget_result_path }}"
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'machine'

- name: "{{ software_key }} | WinGet MACHINE Erfolg prüfen"
  ansible.builtin.assert:
    that:
      - mavi_winget_machine_result.result.Success | default(false) | bool
    fail_msg: >-
      WinGet MACHINE fehlgeschlagen. Paket={{ winget_package_id }},
      Code={{ mavi_winget_machine_result.result.Rc | default('unbekannt') }}
      {{ mavi_winget_machine_result.result.RcHex | default('') }}.
      Ausgabe: {{ mavi_winget_machine_result.result.Output | default('(leer)') }}
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'machine'

- name: "{{ software_key }} | WinGet MACHINE Ergebnis anzeigen"
  ansible.builtin.debug:
    msg: >-
      WinGet {{ winget_package_id }} | Scope=MACHINE |
      {{ 'bereits installiert' if mavi_winget_machine_result.result.AlreadyInstalled | default(false) | bool else 'installiert' }} |
      WinGet={{ mavi_winget_machine_result.result.WingetVersion | default('?') }}
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'machine'

- name: "{{ software_key }} | Office-Konfigurationsdatei lokal prüfen"
  ansible.builtin.stat:
    path: "{{ app.configuration_file }}"
  delegate_to: localhost
  register: office_configuration_source
  become: false
  when: app.type | lower == 'office_odt'

- name: "{{ software_key }} | Office-Konfigurationsdatei muss existieren"
  ansible.builtin.assert:
    that:
      - office_configuration_source.stat.exists
      - office_configuration_source.stat.isreg
    fail_msg: "Office-XML fehlt: {{ app.configuration_file }}"
  when: app.type | lower == 'office_odt'

- name: "{{ software_key }} | Office Remote-Konfigurationspfad bestimmen"
  ansible.builtin.set_fact:
    remote_office_configuration: "C:\\Mavi-Provisioner\\Installers\\{{ app.configuration_file | basename }}"
  when: app.type | lower == 'office_odt'

- name: "{{ software_key }} | Office-XML auf Windows kopieren"
  ansible.windows.win_copy:
    src: "{{ app.configuration_file }}"
    dest: "{{ remote_office_configuration }}"
  when: app.type | lower == 'office_odt'

- name: "{{ software_key }} | Vorhandene Office-/Project-/Visio-Installation prüfen"
  ansible.windows.win_stat:
    path: "{{ app.creates_path }}"
  register: office_odt_existing_product
  when:
    - app.type | lower == 'office_odt'
    - app.creates_path | default('') | length > 0

- name: "{{ software_key }} | Bereits installiertes ODT-Produkt anzeigen"
  ansible.builtin.debug:
    msg: >-
      Erkennungspfad ist bereits vorhanden: {{ app.creates_path }}.
      ODT-Installation wird übersprungen.
  when:
    - app.type | lower == 'office_odt'
    - office_odt_existing_product.stat.exists | default(false)

- name: "{{ software_key }} | Microsoft Office / Project / Visio per ODT installieren"
  block:
    - name: "{{ software_key }} | ODT DETACHED Laufdaten bestimmen"
      ansible.builtin.set_fact:
        office_odt_task_name: >-
          Mavi_ODT_{{ software_key | regex_replace('[^A-Za-z0-9_-]', '_') }}
        office_odt_timeout_minutes: >-
          {{ app.install_timeout_minutes | default(30) | int }}

    - name: "{{ software_key }} | ODT als SYSTEM detached starten"
      ansible.windows.win_powershell:
        error_action: stop
        script: |
          [CmdletBinding()]
          param(
              [Parameter(Mandatory=$true)][string]$TaskName,
              [Parameter(Mandatory=$true)][string]$Executable,
              [Parameter(Mandatory=$true)][string]$ConfigurationFile,
              [int]$TimeoutMinutes = 30
          )

          if ($TimeoutMinutes -lt 1) {
              $TimeoutMinutes = 30
          }

          $workingDirectory = Split-Path -Parent $Executable
          $arguments = '/configure "' + $ConfigurationFile + '"'

          try {
              $oldTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
              if ($null -ne $oldTask) {
                  if ($oldTask.State -eq 'Running') {
                      Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                      Start-Sleep -Seconds 1
                  }
                  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
              }
          }
          catch {}

          $action = New-ScheduledTaskAction `
              -Execute $Executable `
              -Argument $arguments `
              -WorkingDirectory $workingDirectory

          $principal = New-ScheduledTaskPrincipal `
              -UserId 'SYSTEM' `
              -LogonType ServiceAccount `
              -RunLevel Highest

          $settings = New-ScheduledTaskSettingsSet `
              -AllowStartIfOnBatteries `
              -DontStopIfGoingOnBatteries `
              -StartWhenAvailable `
              -ExecutionTimeLimit (New-TimeSpan -Minutes $TimeoutMinutes)

          Register-ScheduledTask `
              -TaskName $TaskName `
              -Action $action `
              -Principal $principal `
              -Settings $settings `
              -Force | Out-Null

          $before = (Get-ScheduledTaskInfo -TaskName $TaskName).LastRunTime
          Start-ScheduledTask -TaskName $TaskName

          $deadline = (Get-Date).AddSeconds(15)
          $started = $false

          do {
              Start-Sleep -Milliseconds 500
              $task = Get-ScheduledTask -TaskName $TaskName
              $info = Get-ScheduledTaskInfo -TaskName $TaskName

              if ($info.LastRunTime -gt $before -or $task.State -eq 'Running') {
                  $started = $true
                  break
              }
          }
          while ((Get-Date) -lt $deadline)

          if (-not $started) {
              throw "ODT-Task wurde nicht gestartet. TaskName=$TaskName"
          }

          $Ansible.Result = @{
              TaskName = $TaskName
              RunAs = 'NT AUTHORITY\\SYSTEM'
              State = [string]$task.State
              LastRunTime = $info.LastRunTime.ToString('o')
              Executable = $Executable
              Arguments = $arguments
              TimeoutMinutes = $TimeoutMinutes
          }
          $Ansible.Changed = $true
        parameters:
          TaskName: "{{ office_odt_task_name }}"
          Executable: "{{ remote_installer }}"
          ConfigurationFile: "{{ remote_office_configuration }}"
          TimeoutMinutes: "{{ office_odt_timeout_minutes }}"
      register: office_odt_start

    - name: "{{ software_key }} | ODT-Task auf Abschluss warten"
      ansible.windows.win_powershell:
        error_action: stop
        script: |
          [CmdletBinding()]
          param(
              [Parameter(Mandatory=$true)][string]$TaskName,
              [string]$ProductPath = ""
          )

          $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
          if ($null -eq $task) {
              throw "ODT-Task '$TaskName' wurde nicht gefunden."
          }

          $info = Get-ScheduledTaskInfo -TaskName $TaskName
          $productExists = $false
          if (-not [string]::IsNullOrWhiteSpace($ProductPath)) {
              $productExists = Test-Path -LiteralPath $ProductPath
          }

          $Ansible.Result = @{
              TaskName = $TaskName
              State = [string]$task.State
              LastTaskResult = [int64]$info.LastTaskResult
              LastRunTime = $info.LastRunTime.ToString('o')
              ProductExists = $productExists
              ProductPath = $ProductPath
          }
          $Ansible.Changed = $false
        parameters:
          TaskName: "{{ office_odt_task_name }}"
          ProductPath: "{{ app.creates_path | default('') }}"
      register: office_odt_status
      until: >-
        office_odt_status.result is defined and
        office_odt_status.result.State | default('Running') not in ['Running', 'Queued']
      retries: "{{ [6, (office_odt_timeout_minutes | int) * 6] | max }}"
      delay: 10
      changed_when: false

    - name: "{{ software_key }} | ODT Exit-Code prüfen"
      ansible.builtin.assert:
        that:
          - office_odt_status.result.LastTaskResult | default(-1) | int in [0, 1641, 3010]
        fail_msg: >-
          ODT-Task meldete Exit-Code
          {{ office_odt_status.result.LastTaskResult | default('unbekannt') }}.

    - name: "{{ software_key }} | Auf Office-/Project-/Visio-EXE warten"
      ansible.windows.win_stat:
        path: "{{ app.creates_path }}"
      register: office_odt_product
      until: office_odt_product.stat.exists | default(false)
      retries: 60
      delay: 5
      when: app.creates_path | default('') | length > 0

    - name: "{{ software_key }} | ODT temporären Task entfernen"
      ansible.windows.win_powershell:
        error_action: continue
        script: |
          param([Parameter(Mandatory=$true)][string]$TaskName)
          $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
          if ($null -ne $task) {
              Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
              $Ansible.Changed = $true
          }
          else {
              $Ansible.Changed = $false
          }
        parameters:
          TaskName: "{{ office_odt_task_name }}"

  rescue:
    - name: "{{ software_key }} | ODT Taskstatus für Diagnose erfassen"
      ansible.windows.win_powershell:
        error_action: continue
        script: |
          param([string]$TaskName)

          $result = @{
              TaskName = $TaskName
              State = 'unbekannt'
              LastTaskResult = 'unbekannt'
          }

          if ($TaskName) {
              $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
              if ($null -ne $task) {
                  $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
                  $result.State = [string]$task.State
                  if ($null -ne $info) {
                      $result.LastTaskResult = [string]$info.LastTaskResult
                  }
              }
          }

          $Ansible.Result = $result
          $Ansible.Changed = $false
        parameters:
          TaskName: "{{ office_odt_task_name | default('') }}"
      register: office_odt_diag_status
      failed_when: false
      changed_when: false

    - name: "{{ software_key }} | ODT-Fehlerdaten für Diagnose übernehmen"
      ansible.builtin.set_fact:
        mavi_failure_result:
          rc: >-
            {{
              office_odt_diag_status.result.LastTaskResult
              | default(
                  office_odt_status.result.LastTaskResult
                  | default('unbekannt')
                )
            }}
          msg: >-
            ODT DETACHED fehlgeschlagen. Taskstatus={{
              office_odt_diag_status.result.State | default('unbekannt')
            }}. {{ ansible_failed_result.msg | default('') }}
          stdout: >-
            {{ office_odt_start.output | default([]) | join('\n') }}
          stderr: >-
            {{ office_odt_start.host_err | default('') }}
        mavi_failure_context: "office_odt_detached_system"
        mavi_failure_executable: "{{ remote_installer }}"
        mavi_failure_arguments: '/configure "{{ remote_office_configuration }}"'

    - name: "{{ software_key }} | ODT hängenden temporären Task stoppen"
      ansible.windows.win_powershell:
        error_action: continue
        script: |
          param([string]$TaskName)
          if (-not $TaskName) { return }
          $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
          if ($null -ne $task) {
              if ($task.State -eq 'Running') {
                  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                  Start-Sleep -Seconds 1
              }
              Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
          }
          $Ansible.Changed = $false
        parameters:
          TaskName: "{{ office_odt_task_name | default('') }}"
      failed_when: false
      changed_when: false

    - name: "{{ software_key }} | ODT-Diagnosebericht erzeugen"
      ansible.builtin.include_tasks: diagnose_install_failure.yml

  when:
    - app.type | lower == 'office_odt'
    - not (office_odt_existing_product.stat.exists | default(false))

- name: "{{ software_key }} | Systemweite Installation"
  block:
    - name: "{{ software_key }} | Systemweit installieren"
      ansible.windows.win_package:
        path: "{{ remote_installer }}"
        arguments: "{{ app.arguments | default(omit, true) }}"
        creates_path: "{{ app.creates_path | default(omit, true) }}"
        state: present
        expected_return_code:
          - 0
          - 1641
          - 3010
      register: mavi_machine_install_result
      no_log: true

  rescue:
    - name: "{{ software_key }} | Fehlerdaten für Diagnose übernehmen"
      ansible.builtin.set_fact:
        mavi_failure_result: "{{ mavi_machine_install_result }}"
        mavi_failure_context: "machine"
      no_log: true

    - name: "{{ software_key }} | Diagnosebericht erzeugen"
      ansible.builtin.include_tasks: diagnose_install_failure.yml

  when:
    - app.context | default('machine') == 'machine'
    - app.type | lower not in ['office_odt', 'winget']

- name: "{{ software_key }} | Neustart-Hinweis nach erfolgreicher Installation"
  ansible.builtin.debug:
    msg: >-
      Installation erfolgreich. Exit-Code {{ mavi_machine_install_result.rc }}:
      {{
        'Der Installer hat einen Neustart ausgelöst/angefordert (1641).'
        if mavi_machine_install_result.rc | int == 1641
        else 'Die Installation ist erfolgreich, ein Neustart ist erforderlich (3010).'
      }}
  when:
    - app.context | default('machine') == 'machine'
    - app.type | lower not in ['office_odt', 'winget']
    - mavi_machine_install_result is defined
    - mavi_machine_install_result.rc | default(0) | int in [1641, 3010]

- name: "{{ software_key }} | SYSTEM-Installation"
  block:
    - name: "{{ software_key }} | Als SYSTEM installieren"
      ansible.windows.win_package:
        path: "{{ remote_installer }}"
        arguments: "{{ app.arguments | default(omit, true) }}"
        creates_path: "{{ app.creates_path | default(omit, true) }}"
        state: present
        expected_return_code:
          - 0
          - 1641
          - 3010
      register: mavi_system_install_result
      no_log: true
      become: true
      become_method: runas
      become_user: SYSTEM

  rescue:
    - name: "{{ software_key }} | SYSTEM-Fehlerdaten für Diagnose übernehmen"
      ansible.builtin.set_fact:
        mavi_failure_result: "{{ mavi_system_install_result }}"
        mavi_failure_context: "system"
      no_log: true

    - name: "{{ software_key }} | SYSTEM-Diagnosebericht erzeugen"
      ansible.builtin.include_tasks: diagnose_install_failure.yml

  when:
    - app.context | default('machine') == 'system'
    - app.type | lower not in ['office_odt', 'winget']

- name: "{{ software_key }} | Neustart-Hinweis nach erfolgreicher SYSTEM-Installation"
  ansible.builtin.debug:
    msg: >-
      Installation erfolgreich. Exit-Code {{ mavi_system_install_result.rc }}:
      {{
        'Der Installer hat einen Neustart ausgelöst/angefordert (1641).'
        if mavi_system_install_result.rc | int == 1641
        else 'Die Installation ist erfolgreich, ein Neustart ist erforderlich (3010).'
      }}
  when:
    - app.context | default('machine') == 'system'
    - app.type | lower not in ['office_odt', 'winget']
    - mavi_system_install_result is defined
    - mavi_system_install_result.rc | default(0) | int in [1641, 3010]

- name: "{{ software_key }} | DETACHED-Startkommando bestimmen"
  ansible.builtin.set_fact:
    detached_installer_exe: >-
      {{
        'C:\Windows\System32\msiexec.exe'
        if (app.type | lower == 'msi')
        else remote_installer
      }}
    detached_installer_args: >-
      {{
        (
          '/i "' ~ remote_installer ~ '" /qn /norestart'
          ~ (
              ' ' ~ (app.arguments | string)
              if (app.arguments | default('') | trim | length > 0)
              else ''
            )
        )
        if (app.type | lower == 'msi')
        else (app.arguments | default(''))
      }}
    detached_timeout_minutes: >-
      {{
        app.install_timeout_minutes
        | default(30)
        | int
      }}
  when:
    - app.context | default('machine') == 'machine_detached'
    - app.type | lower not in ['office_odt', 'winget']
  no_log: true

- name: "{{ software_key }} | DETACHED systemweite Installation"
  block:
    - name: "{{ software_key }} | DETACHED Modus anzeigen"
      ansible.builtin.debug:
        msg: >-
          Starte Installer lokal über Windows Task Scheduler als
          NT AUTHORITY\SYSTEM. Timeout:
          {{ detached_timeout_minutes }} Minute(n).
          Parameter: {{ '(vorhanden; Ausgabe aus Sicherheitsgründen geschwärzt)' if detached_installer_args | default('') | length > 0 else '(KEINE)' }}

    - name: "{{ software_key }} | Detached systemweit installieren"
      ansible.windows.win_powershell:
        error_action: stop
        script: |
          [CmdletBinding()]
          param(
            [Parameter(Mandatory=$true)][string]$TaskName,
            [Parameter(Mandatory=$true)][string]$Executable,
            [string]$Arguments = "",
            [int]$TimeoutMinutes = 30
          )

          if ($TimeoutMinutes -lt 1) {
              $TimeoutMinutes = 30
          }

          try {
              $oldTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

              if ($null -ne $oldTask) {
                  if ($oldTask.State -eq 'Running') {
                      Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                      Start-Sleep -Seconds 1
                  }

                  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
              }
          }
          catch {
              # Alter/nicht vorhandener Task darf den neuen Lauf nicht blockieren.
          }

          if ([string]::IsNullOrWhiteSpace($Arguments)) {
              $action = New-ScheduledTaskAction -Execute $Executable
          }
          else {
              $action = New-ScheduledTaskAction -Execute $Executable -Argument $Arguments
          }

          $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
          $executionLimit = New-TimeSpan -Minutes $TimeoutMinutes

          $settings = New-ScheduledTaskSettingsSet `
              -AllowStartIfOnBatteries `
              -DontStopIfGoingOnBatteries `
              -StartWhenAvailable `
              -ExecutionTimeLimit $executionLimit

          Register-ScheduledTask `
              -TaskName $TaskName `
              -Action $action `
              -Principal $principal `
              -Settings $settings `
              -Force | Out-Null

          try {
              $before = (Get-ScheduledTaskInfo -TaskName $TaskName).LastRunTime

              Start-ScheduledTask -TaskName $TaskName

              $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
              $started = $false

              do {
                  Start-Sleep -Seconds 2

                  $task = Get-ScheduledTask -TaskName $TaskName
                  $info = Get-ScheduledTaskInfo -TaskName $TaskName

                  if ($info.LastRunTime -gt $before) {
                      $started = $true
                  }

                  if ($started -and $task.State -ne 'Running') {
                      break
                  }
              }
              while ((Get-Date) -lt $deadline)

              if (-not $started) {
                  throw "DETACHED-Task wurde nicht gestartet. TaskName=$TaskName"
              }

              if ((Get-Date) -ge $deadline) {
                  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                  throw "Zeitüberschreitung nach $TimeoutMinutes Minute(n) bei DETACHED-Installation."
              }

              $info = Get-ScheduledTaskInfo -TaskName $TaskName
              $exitCode = [int64]$info.LastTaskResult
              $successCodes = @(0, 1641, 3010)

              $argumentsUsed = -not [string]::IsNullOrWhiteSpace($Arguments)
              $rebootRequired = $exitCode -in @(1641, 3010)

              $Ansible.Result = @{
                  RunAs = 'NT AUTHORITY\SYSTEM'
                  Mode = 'machine_detached'
                  Executable = $Executable
                  Arguments = $Arguments
                  ArgumentsUsed = $argumentsUsed
                  LastTaskResult = $exitCode
                  RebootRequired = $rebootRequired
                  TimeoutMinutes = $TimeoutMinutes
              }

              $Ansible.Changed = $true
          }
          finally {
              Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
          }
        parameters:
          TaskName: >-
            Mavi_Detached_{{ software_key
            | regex_replace('[^A-Za-z0-9_-]', '_') }}
          Executable: "{{ detached_installer_exe }}"
          Arguments: "{{ detached_installer_args }}"
          TimeoutMinutes: "{{ detached_timeout_minutes }}"
      register: mavi_detached_install_result
      no_log: true

    - name: "{{ software_key }} | DETACHED Exit-Code prüfen"
      ansible.builtin.assert:
        that:
          - >-
            mavi_detached_install_result.result.LastTaskResult
            | default(-1)
            | int
            in [0, 1641, 3010]
        fail_msg: >-
          DETACHED-Installer meldete Exit-Code
          {{
            mavi_detached_install_result.result.LastTaskResult
            | default('unbekannt')
          }}.

    - name: "{{ software_key }} | DETACHED Neustart-Hinweis"
      ansible.builtin.debug:
        msg: >-
          Installation erfolgreich. Exit-Code
          {{ mavi_detached_install_result.result.LastTaskResult }}:
          {{
            'Der Installer hat einen Neustart ausgelöst/angefordert (1641).'
            if mavi_detached_install_result.result.LastTaskResult | int == 1641
            else 'Die Installation ist erfolgreich, ein Neustart ist erforderlich (3010).'
          }}
      when:
        - mavi_detached_install_result.result is defined
        - >-
          mavi_detached_install_result.result.LastTaskResult
          | default(0)
          | int
          in [1641, 3010]

  rescue:
    - name: "{{ software_key }} | DETACHED Fehlerdaten übernehmen"
      ansible.builtin.set_fact:
        mavi_failure_result:
          rc: >-
            {{
              mavi_detached_install_result.result.LastTaskResult
              | default('unbekannt')
            }}
          msg: >-
            {{
              ansible_failed_result.msg
              | default(
                  mavi_detached_install_result.msg
                  | default('DETACHED-Installation fehlgeschlagen.')
                )
            }}
          stdout: >-
            {{
              mavi_detached_install_result.output
              | default([])
              | join('\n')
            }}
          stderr: >-
            {{
              mavi_detached_install_result.host_err
              | default('')
            }}
          reboot_required: >-
            {{
              mavi_detached_install_result.result.RebootRequired
              | default(false)
            }}
        mavi_failure_context: "machine_detached"
        mavi_failure_executable: "{{ detached_installer_exe }}"
        mavi_failure_arguments: "{{ detached_installer_args }}"

    - name: "{{ software_key }} | DETACHED Diagnosebericht erzeugen"
      ansible.builtin.include_tasks: diagnose_install_failure.yml

  when:
    - app.context | default('machine') == 'machine_detached'
    - app.type | lower not in ['office_odt', 'winget']

- name: "{{ software_key }} | Aktuell angemeldeten Benutzer für INTERAKTIV ermitteln"
  ansible.windows.win_powershell:
    script: |
      $user = (Get-CimInstance Win32_ComputerSystem).UserName
      $Ansible.Result = $user
      $Ansible.Changed = $false
  register: interactive_user_result
  when:
    - app.context | default('machine') in ['machine_interactive', 'user_interactive', 'user_non_elevated', 'user_uac']
    - target_user | default('') | length == 0

- name: "{{ software_key }} | INTERAKTIV Zielbenutzer festlegen"
  ansible.builtin.set_fact:
    resolved_target_user: >-
      {{
        target_user
        if (target_user | default('') | length > 0)
        else (interactive_user_result.result | default(''))
      }}
  when: app.context | default('machine') in ['machine_interactive', 'user_interactive', 'user_non_elevated', 'user_uac']

- name: "{{ software_key }} | Prüfen, ob für INTERAKTIV ein Benutzer angemeldet ist"
  ansible.builtin.assert:
    that:
      - resolved_target_user | default('') | length > 0
    fail_msg: >-
      Für '{{ app.name }}' wird eine sichtbare interaktive Installation benötigt.
      Auf dem PC ist kein interaktiv angemeldeter Benutzer erkennbar.
      Benutzer anmelden oder target_user angeben.
  when: app.context | default('machine') in ['machine_interactive', 'user_interactive', 'user_non_elevated', 'user_uac']

- name: "{{ software_key }} | WinGet USER über angemeldeten Benutzer installieren"
  ansible.windows.win_powershell:
    error_action: stop
    script: |
      [CmdletBinding()]
      param(
          [Parameter(Mandatory=$true)][string]$TaskName,
          [Parameter(Mandatory=$true)][string]$RunAsUser,
          [Parameter(Mandatory=$true)][string]$ScriptPath,
          [Parameter(Mandatory=$true)][string]$PackageId,
          [Parameter(Mandatory=$true)][string]$Source,
          [string]$Version = '',
          [Parameter(Mandatory=$true)][string]$ResultFile,
          [int]$TimeoutMinutes = 30
      )

      if ($TimeoutMinutes -lt 1) { $TimeoutMinutes = 30 }
      $currentUser = (Get-CimInstance Win32_ComputerSystem).UserName
      if (-not $currentUser) { throw 'Kein interaktiv angemeldeter Benutzer gefunden.' }
      if ($currentUser -ine $RunAsUser) {
          throw "Zielbenutzer '$RunAsUser' ist nicht der aktuell angemeldete Benutzer '$currentUser'."
      }

      $old = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
      if ($old) {
          if ($old.State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
          Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
      }

      $quotedVersion = $Version.Replace('"','')
      $arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass ' +
          '-File "' + $ScriptPath + '" ' +
          '-PackageId "' + $PackageId + '" ' +
          '-Scope user ' +
          '-Source "' + $Source + '" ' +
          '-Version "' + $quotedVersion + '" ' +
          '-ResultFile "' + $ResultFile + '"'

      $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
      $principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType Interactive -RunLevel Limited
      $settings = New-ScheduledTaskSettingsSet `
          -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
          -ExecutionTimeLimit (New-TimeSpan -Minutes $TimeoutMinutes)

      Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
      try {
          $before = (Get-ScheduledTaskInfo -TaskName $TaskName).LastRunTime
          Start-ScheduledTask -TaskName $TaskName
          $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
          $started = $false
          do {
              Start-Sleep -Seconds 2
              $task = Get-ScheduledTask -TaskName $TaskName
              $info = Get-ScheduledTaskInfo -TaskName $TaskName
              if ($info.LastRunTime -gt $before) { $started = $true }
              if ($started -and $task.State -ne 'Running') { break }
          } while ((Get-Date) -lt $deadline)

          if (-not $started) { throw 'WinGet USER Task wurde nicht gestartet.' }
          if ((Get-Date) -ge $deadline) {
              Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
              throw "WinGet USER Timeout nach $TimeoutMinutes Minuten."
          }

          $info = Get-ScheduledTaskInfo -TaskName $TaskName
          $Ansible.Result = @{
              User = $RunAsUser
              LastTaskResult = [Int64]$info.LastTaskResult
              TimeoutMinutes = $TimeoutMinutes
          }
          $Ansible.Changed = $true
      }
      finally {
          Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
      }
    parameters:
      TaskName: >-
        Mavi_WinGet_{{ software_key | regex_replace('[^A-Za-z0-9_-]', '_') }}
      RunAsUser: "{{ resolved_target_user }}"
      ScriptPath: "{{ winget_script_path }}"
      PackageId: "{{ winget_package_id }}"
      Source: "{{ winget_source }}"
      Version: "{{ winget_version }}"
      ResultFile: "{{ winget_result_path }}"
      TimeoutMinutes: "{{ app.install_timeout_minutes | default(30) | int }}"
  register: mavi_winget_user_task
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'user'

- name: "{{ software_key }} | WinGet USER Ergebnis lesen"
  ansible.windows.win_powershell:
    error_action: stop
    script: |
      param([Parameter(Mandatory=$true)][string]$ResultFile)
      if (-not (Test-Path -LiteralPath $ResultFile)) {
          throw "WinGet-Ergebnisdatei fehlt: $ResultFile"
      }
      $data = Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json
      $Ansible.Result = @{
          Success = [bool]$data.Success
          Changed = [bool]$data.Changed
          AlreadyInstalled = [bool]$data.AlreadyInstalled
          Rc = [Int64]$data.Rc
          RcHex = [string]$data.RcHex
          Output = [string]$data.Output
          WingetPath = [string]$data.WingetPath
          WingetVersion = [string]$data.WingetVersion
          PackageId = [string]$data.PackageId
          Scope = [string]$data.Scope
          Action = [string]$data.Action
      }
      $Ansible.Changed = [bool]$data.Changed
    parameters:
      ResultFile: "{{ winget_result_path }}"
  register: mavi_winget_user_result
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'user'

- name: "{{ software_key }} | WinGet USER Hilfsdateien entfernen"
  ansible.windows.win_file:
    path: "{{ item }}"
    state: absent
  loop:
    - "{{ winget_script_path }}"
    - "{{ winget_result_path }}"
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'user'

- name: "{{ software_key }} | WinGet USER Erfolg prüfen"
  ansible.builtin.assert:
    that:
      - mavi_winget_user_result.result.Success | default(false) | bool
    fail_msg: >-
      WinGet USER fehlgeschlagen. Benutzer={{ resolved_target_user }},
      Paket={{ winget_package_id }},
      Code={{ mavi_winget_user_result.result.Rc | default('unbekannt') }}
      {{ mavi_winget_user_result.result.RcHex | default('') }}.
      Ausgabe: {{ mavi_winget_user_result.result.Output | default('(leer)') }}
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'user'

- name: "{{ software_key }} | WinGet USER Ergebnis anzeigen"
  ansible.builtin.debug:
    msg: >-
      WinGet {{ winget_package_id }} | Benutzer={{ resolved_target_user }} |
      {{ 'bereits installiert' if mavi_winget_user_result.result.AlreadyInstalled | default(false) | bool else 'installiert' }} |
      WinGet={{ mavi_winget_user_result.result.WingetVersion | default('?') }}
  when:
    - app.type | lower == 'winget'
    - winget_scope == 'user'

- name: "{{ software_key }} | INTERAKTIV Startkommando bestimmen"
  ansible.builtin.set_fact:
    interactive_installer_exe: >-
      {{
        'C:\Windows\System32\msiexec.exe'
        if (app.type | lower == 'msi')
        else remote_installer
      }}
    interactive_installer_args: >-
      {{
        (
          '/i "' ~ remote_installer ~ '"'
          ~ (
              ' ' ~ (app.arguments | string)
              if (app.arguments | default('') | trim | length > 0)
              else ''
            )
        )
        if (app.type | lower == 'msi')
        else (app.arguments | default(''))
      }}
    interactive_run_level: >-
      {{
        'Highest'
        if (app.context | default('machine') == 'machine_interactive')
        else (
          'UAC'
          if (app.context | default('machine') == 'user_uac')
          else 'Limited'
        )
      }}
    interactive_mode_label: >-
      {{
        'Angemeldeter Benutzer INTERAKTIV + ELEVATED / sichtbare GUI + höchste verfügbare Rechte'
        if (app.context | default('machine') == 'machine_interactive')
        else (
          'Angemeldeter Benutzer INTERAKTIV / zuerst NICHT erhöht; bei Elevation automatisch sichtbarer UAC-Fallback'
          if (app.context | default('machine') == 'user_uac')
          else 'Angemeldeter Benutzer INTERAKTIV / sichtbare GUI / NICHT erhöht'
        )
      }}
    interactive_timeout_minutes: >-
      {{ app.install_timeout_minutes | default(30) | int }}
  when:
    - app.context | default('machine') in ['machine_interactive', 'user_interactive', 'user_non_elevated', 'user_uac']
    - app.type | lower != 'winget'
  no_log: true

- name: "{{ software_key }} | INTERAKTIVE Installation"
  block:
    - name: "{{ software_key }} | INTERAKTIV Modus anzeigen"
      ansible.builtin.debug:
        msg: >-
          {{ interactive_mode_label }}. Benutzer: {{ resolved_target_user }}.
          Der temporäre Task hat KEINEN Trigger und wird genau einmal manuell gestartet.
          Timeout: {{ interactive_timeout_minutes }} Minute(n).
          Parameter: {{ '(vorhanden; Ausgabe aus Sicherheitsgründen geschwärzt)' if interactive_installer_args | default('') | length > 0 else '(KEINE)' }}.
          Falls der Installer eine GUI besitzt, sollte sie auf dem angemeldeten Desktop erscheinen.

    - name: "{{ software_key }} | Interaktiv über Task Scheduler installieren"
      ansible.windows.win_powershell:
        error_action: stop
        script: |
          [CmdletBinding()]
          param(
            [Parameter(Mandatory=$true)][string]$TaskName,
            [Parameter(Mandatory=$true)][string]$RunAsUser,
            [Parameter(Mandatory=$true)][string]$Executable,
            [string]$Arguments = "",
            [ValidateSet('Highest','Limited','UAC')][string]$RunLevel = 'Limited',
            [int]$TimeoutMinutes = 30,
            [string]$WorkingDirectory = ""
          )

          if ($TimeoutMinutes -lt 1) {
              $TimeoutMinutes = 30
          }

          $currentUser = (Get-CimInstance Win32_ComputerSystem).UserName
          if (-not $currentUser) {
              throw "Kein interaktiv angemeldeter Benutzer gefunden."
          }

          if ($RunAsUser -and ($currentUser -ine $RunAsUser)) {
              throw "Zielbenutzer '$RunAsUser' ist nicht der aktuell interaktiv angemeldete Benutzer '$currentUser'."
          }

          if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
              $WorkingDirectory = Split-Path -Parent $Executable
          }

          try {
              $oldTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
              if ($null -ne $oldTask) {
                  if ($oldTask.State -eq 'Running') {
                      Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                      Start-Sleep -Seconds 1
                  }
                  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
              }
          }
          catch {
              # Ein alter Wegwerf-Task darf den neuen Lauf nicht blockieren.
          }

          $uacLauncherPath = $null
          $uacPayloadPath = $null
          $uacAction = $null

          if ($RunLevel -eq 'UAC') {
              # USER -> UAC FALLBACK:
              # Versuch 1 wird unten absichtlich als normaler, nicht erhöhter
              # Benutzer ausgeführt. Dieser Launcher wird nur vorbereitet und
              # erst bei ERROR_ELEVATION_REQUIRED verwendet.
              $uacDir = 'C:\Mavi-Provisioner\UAC'
              New-Item -ItemType Directory -Path $uacDir -Force | Out-Null

              $safeTaskName = ($TaskName -replace '[^A-Za-z0-9_.-]', '_')
              $uacLauncherPath = Join-Path $uacDir ($safeTaskName + '.ps1')
              $uacPayloadPath = Join-Path $uacDir ($safeTaskName + '.json')

              @{
                  Executable = $Executable
                  Arguments = $Arguments
                  WorkingDirectory = $WorkingDirectory
              } | ConvertTo-Json -Compress | Set-Content -LiteralPath $uacPayloadPath -Encoding UTF8

              $uacLauncher = @'
          param([Parameter(Mandatory=$true)][string]$PayloadPath)
          $ErrorActionPreference = 'Stop'
          try {
              $cfg = Get-Content -LiteralPath $PayloadPath -Raw | ConvertFrom-Json
              $start = @{
                  FilePath = [string]$cfg.Executable
                  Verb = 'RunAs'
                  PassThru = $true
                  Wait = $true
              }
              if (-not [string]::IsNullOrWhiteSpace([string]$cfg.Arguments)) {
                  $start.ArgumentList = [string]$cfg.Arguments
              }
              if (-not [string]::IsNullOrWhiteSpace([string]$cfg.WorkingDirectory)) {
                  $start.WorkingDirectory = [string]$cfg.WorkingDirectory
              }
              $proc = Start-Process @start
              if ($null -eq $proc) { exit 1 }
              exit [int]$proc.ExitCode
          }
          catch [System.ComponentModel.Win32Exception] {
              if ($_.Exception.NativeErrorCode -eq 1223) { exit 1223 }
              exit 1
          }
          catch {
              exit 1
          }
          '@
              Set-Content -LiteralPath $uacLauncherPath -Value $uacLauncher -Encoding UTF8

              $uacArgs = '-NoProfile -ExecutionPolicy Bypass -File "' +
                  $uacLauncherPath + '" -PayloadPath "' + $uacPayloadPath + '"'
              $uacAction = New-ScheduledTaskAction `
                  -Execute 'powershell.exe' `
                  -Argument $uacArgs `
                  -WorkingDirectory $WorkingDirectory
          }

          # Versuch 1 ist auch im Fallback-Modus IMMER der echte Installer als
          # normaler Benutzer. UAC kommt erst später, wenn Windows es verlangt.
          if ([string]::IsNullOrWhiteSpace($Arguments)) {
              $action = New-ScheduledTaskAction -Execute $Executable -WorkingDirectory $WorkingDirectory
          }
          else {
              $action = New-ScheduledTaskAction -Execute $Executable -Argument $Arguments -WorkingDirectory $WorkingDirectory
          }

          if ($RunLevel -eq 'Highest') {
              $principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType Interactive -RunLevel Highest
          }
          else {
              # Limited ist hier auch für UAC absichtlich korrekt: Nur ein
              # Prozess im echten User-Desktop kann den sichtbaren UAC-Dialog
              # über das Shellverb RunAs anfordern.
              $principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType Interactive -RunLevel Limited
          }

          $executionLimit = New-TimeSpan -Minutes $TimeoutMinutes
          $settings = New-ScheduledTaskSettingsSet `
              -AllowStartIfOnBatteries `
              -DontStopIfGoingOnBatteries `
              -StartWhenAvailable `
              -ExecutionTimeLimit $executionLimit

          # Absichtlich KEIN New-ScheduledTaskTrigger:
          # Der Task ist ein einmaliger Wegwerf-Task und wird nur per Start-ScheduledTask gestartet.
          Register-ScheduledTask `
              -TaskName $TaskName `
              -Action $action `
              -Principal $principal `
              -Settings $settings `
              -Force | Out-Null

          try {
              function Invoke-MaviInteractiveTaskOnce {
                  param([Parameter(Mandatory=$true)][string]$AttemptLabel)

                  $before = (Get-ScheduledTaskInfo -TaskName $TaskName).LastRunTime
                  Start-ScheduledTask -TaskName $TaskName

                  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
                  $started = $false

                  do {
                      Start-Sleep -Seconds 2
                      $task = Get-ScheduledTask -TaskName $TaskName
                      $info = Get-ScheduledTaskInfo -TaskName $TaskName

                      if ($info.LastRunTime -gt $before) {
                          $started = $true
                      }

                      if ($started -and $task.State -ne 'Running') {
                          break
                      }
                  }
                  while ((Get-Date) -lt $deadline)

                  if (-not $started) {
                      throw "$AttemptLabel wurde nicht gestartet. Ist '$RunAsUser' wirklich angemeldet?"
                  }

                  if ((Get-Date) -ge $deadline) {
                      Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                      throw "Zeitüberschreitung nach $TimeoutMinutes Minute(n) bei $AttemptLabel."
                  }

                  return [int64](Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
              }

              # Versuch 1: normaler User-Token, keine Elevation, kein UAC.
              $initialExitCode = Invoke-MaviInteractiveTaskOnce -AttemptLabel 'INTERAKTIV-USER-Versuch'
              $exitCode = $initialExitCode
              $usedUacFallback = $false

              # ERROR_ELEVATION_REQUIRED = Win32 740.
              # Task Scheduler meldet typischerweise 0x800702E4 = 2147943140.
              # Nur in diesem eindeutigen Fall wird genau EINMAL mit sichtbarem
              # UAC wiederholt. Andere Fehler dürfen den Installer nicht blind
              # ein zweites Mal starten.
              $elevationRequiredCodes = @(
                  [int64]740,
                  [int64]2147943140,
                  [int64]-2147024156
              )

              if ($RunLevel -eq 'UAC' -and $exitCode -in $elevationRequiredCodes) {
                  if ($null -eq $uacAction) {
                      throw 'UAC-Fallback wurde benötigt, aber der UAC-Launcher wurde nicht vorbereitet.'
                  }

                  $usedUacFallback = $true
                  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

                  Register-ScheduledTask `
                      -TaskName $TaskName `
                      -Action $uacAction `
                      -Principal $principal `
                      -Settings $settings `
                      -Force | Out-Null

                  $exitCode = Invoke-MaviInteractiveTaskOnce -AttemptLabel 'INTERAKTIV-UAC-Fallback'
              }

              $successCodes = @(0, 1641, 3010)

              if ($exitCode -notin $successCodes) {
                  if ($RunLevel -eq 'UAC' -and $usedUacFallback -and $exitCode -eq 1223) {
                      throw "UAC-Fallback wurde abgebrochen oder vom Benutzer nicht bestätigt (1223)."
                  }
                  if ($RunLevel -eq 'UAC' -and -not $usedUacFallback) {
                      throw "USER-Versuch fehlgeschlagen mit Task-Scheduler-Ergebnis $exitCode. Kein UAC-Fallback, weil Windows keine erforderliche Elevation gemeldet hat."
                  }
                  throw "Installer meldete Task-Scheduler-Ergebnis $exitCode."
              }

              $Ansible.Result = @{
                  User = $RunAsUser
                  Mode = $RunLevel
                  Executable = $Executable
                  Arguments = $Arguments
                  ArgumentsUsed = (-not [string]::IsNullOrWhiteSpace($Arguments))
                  InitialTaskResult = $initialExitCode
                  UacFallbackUsed = $usedUacFallback
                  LastTaskResult = $exitCode
                  RebootRequired = ($exitCode -in @(1641, 3010))
                  TimeoutMinutes = $TimeoutMinutes
                  OneShotTask = $true
              }
              $Ansible.Changed = $true
          }
          finally {
              try {
                  $remainingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                  if ($null -ne $remainingTask -and $remainingTask.State -eq 'Running') {
                      Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                  }
              }
              catch {}

              Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
              if ($uacLauncherPath) { Remove-Item -LiteralPath $uacLauncherPath -Force -ErrorAction SilentlyContinue }
              if ($uacPayloadPath) { Remove-Item -LiteralPath $uacPayloadPath -Force -ErrorAction SilentlyContinue }
          }
        parameters:
          TaskName: >-
            Mavi_Interactive_{{ software_key | regex_replace('[^A-Za-z0-9_-]', '_') }}
          RunAsUser: "{{ resolved_target_user }}"
          Executable: "{{ interactive_installer_exe }}"
          Arguments: "{{ interactive_installer_args }}"
          RunLevel: "{{ interactive_run_level }}"
          TimeoutMinutes: "{{ interactive_timeout_minutes }}"
          WorkingDirectory: 'C:\Mavi-Provisioner\Installers'
      register: mavi_interactive_install_result
      no_log: true

    - name: "{{ software_key }} | USER -> UAC Fallback Ergebnis"
      ansible.builtin.debug:
        msg: >-
          {{
            'USER-Versuch verlangte erhöhte Rechte. Sichtbarer UAC-Fallback wurde verwendet. Erster Task-Code=' ~
            (mavi_interactive_install_result.result.InitialTaskResult | default('?') | string) ~
            ', finaler Code=' ~
            (mavi_interactive_install_result.result.LastTaskResult | default('?') | string) ~ '.'
            if mavi_interactive_install_result.result.UacFallbackUsed | default(false) | bool
            else
            'USER-Versuch war ohne Elevation erfolgreich. Kein UAC-Prompt nötig. Finaler Code=' ~
            (mavi_interactive_install_result.result.LastTaskResult | default('?') | string) ~ '.'
          }}
      when:
        - app.context | default('machine') == 'user_uac'
        - mavi_interactive_install_result.result is defined

    - name: "{{ software_key }} | Neustart-Hinweis nach INTERAKTIVER Installation"
      ansible.builtin.debug:
        msg: >-
          Installation erfolgreich. Exit-Code
          {{ mavi_interactive_install_result.result.LastTaskResult }}:
          {{
            'Der Installer hat einen Neustart ausgelöst/angefordert (1641).'
            if mavi_interactive_install_result.result.LastTaskResult | int == 1641
            else 'Die Installation ist erfolgreich, ein Neustart ist erforderlich (3010).'
          }}
      when:
        - mavi_interactive_install_result.result is defined
        - mavi_interactive_install_result.result.LastTaskResult | default(0) | int in [1641, 3010]

  rescue:
    - name: "{{ software_key }} | INTERAKTIV Fehlerdaten übernehmen"
      ansible.builtin.set_fact:
        mavi_failure_result:
          rc: >-
            {{
              mavi_interactive_install_result.result.LastTaskResult
              | default('unbekannt')
            }}
          msg: >-
            {{
              ansible_failed_result.msg
              | default(
                  mavi_interactive_install_result.msg
                  | default('INTERAKTIVE Installation fehlgeschlagen.')
                )
            }}
          stdout: >-
            {{
              mavi_interactive_install_result.output
              | default([])
              | join('\n')
            }}
          stderr: >-
            {{ mavi_interactive_install_result.host_err | default('') }}
          reboot_required: >-
            {{
              mavi_interactive_install_result.result.RebootRequired
              | default(false)
            }}
        mavi_failure_context: >-
          {{
            'machine_interactive'
            if (app.context | default('machine') == 'machine_interactive')
            else (
              'user_uac'
              if (app.context | default('machine') == 'user_uac')
              else 'user_interactive'
            )
          }}
        mavi_failure_executable: "{{ interactive_installer_exe }}"
        mavi_failure_arguments: "{{ interactive_installer_args }}"

    - name: "{{ software_key }} | INTERAKTIV Diagnosebericht erzeugen"
      ansible.builtin.include_tasks: diagnose_install_failure.yml

  when:
    - app.context | default('machine') in ['machine_interactive', 'user_interactive', 'user_non_elevated', 'user_uac']
    - app.type | lower != 'winget'

- name: "{{ software_key }} | Öffentliche Desktop-Verknüpfung sicherstellen"
  ansible.windows.win_powershell:
    error_action: stop
    script: |
      [CmdletBinding()]
      param(
        [Parameter(Mandatory=$true)][string]$ShortcutName,
        [Parameter(Mandatory=$true)][string]$TargetPath,
        [string]$Arguments = "",
        [string]$WorkingDirectory = ""
      )

      if (-not (Test-Path -LiteralPath $TargetPath)) {
          throw "Ziel der Desktop-Verknüpfung wurde nicht gefunden: $TargetPath"
      }

      if (-not $WorkingDirectory) {
          $WorkingDirectory = Split-Path -Parent $TargetPath
      }

      $desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
      if (-not $desktop) {
          $desktop = 'C:\Users\Public\Desktop'
      }

      $shortcutPath = Join-Path $desktop ($ShortcutName + '.lnk')
      $shell = New-Object -ComObject WScript.Shell
      $shortcut = $shell.CreateShortcut($shortcutPath)

      $changed = $true
      if (Test-Path -LiteralPath $shortcutPath) {
          $existing = $shell.CreateShortcut($shortcutPath)
          $changed = (
              $existing.TargetPath -ne $TargetPath -or
              $existing.Arguments -ne $Arguments -or
              $existing.WorkingDirectory -ne $WorkingDirectory
          )
      }

      if ($changed) {
          $shortcut = $shell.CreateShortcut($shortcutPath)
          $shortcut.TargetPath = $TargetPath
          $shortcut.Arguments = $Arguments
          $shortcut.WorkingDirectory = $WorkingDirectory
          $shortcut.Save()
      }

      $Ansible.Changed = $changed
      $Ansible.Result = @{
          Shortcut = $shortcutPath
          Target = $TargetPath
      }
    parameters:
      ShortcutName: "{{ app.desktop_shortcut.name | default(app.name) }}"
      TargetPath: "{{ app.desktop_shortcut.target }}"
      Arguments: "{{ app.desktop_shortcut.arguments | default('') }}"
      WorkingDirectory: "{{ app.desktop_shortcut.working_directory | default('') }}"
  when:
    - app.desktop_shortcut is defined
    - app.desktop_shortcut.enabled | default(true) | bool

- name: "{{ software_key }} | Office-XML nach erfolgreichem Lauf löschen"
  ansible.windows.win_file:
    path: "{{ remote_office_configuration }}"
    state: absent
  register: office_xml_cleanup
  retries: 12
  delay: 5
  until: office_xml_cleanup is succeeded
  when: app.type | lower == 'office_odt'

- name: "{{ software_key }} | ODT setup.exe nach erfolgreichem Lauf löschen"
  ansible.windows.win_file:
    path: "{{ remote_installer }}"
    state: absent
  register: office_odt_cleanup
  retries: 30
  delay: 10
  until: office_odt_cleanup is succeeded
  when: app.type | lower == 'office_odt'

- name: "{{ software_key }} | Installer nach erfolgreichem Lauf löschen"
  ansible.windows.win_file:
    path: "{{ remote_installer }}"
    state: absent
  when: app.type | lower not in ['office_odt', 'winget']
"""


LIVE_PROBE_PLAYBOOK_TEMPLATE = r"""---
- name: Mavi Live-Installer-Probe
  hosts: windows
  gather_facts: false

  tasks:
    - name: Remote-Installerzustand erfassen
      ansible.windows.win_powershell:
        error_action: continue
        script: |
          [CmdletBinding()]
          param(
            [string]$InstallerPath = "",
            [string]$InstallerName = "",
            [string]$SoftwareName = ""
          )

          function Get-PendingReboot {
              try {
                  if (
                      (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                      (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
                  ) {
                      return $true
                  }

                  $session = Get-ItemProperty `
                      'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                      -Name PendingFileRenameOperations `
                      -ErrorAction SilentlyContinue

                  if ($session.PendingFileRenameOperations) {
                      return $true
                  }
              }
              catch {}

              return $false
          }

          function Add-LogFiles {
              param(
                  [System.Collections.Generic.List[object]]$Target,
                  [string]$Path,
                  [bool]$Recurse,
                  [datetime]$Since
              )

              if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
                  return
              }

              try {
                  $params = @{
                      LiteralPath = $Path
                      File = $true
                      ErrorAction = 'SilentlyContinue'
                  }

                  if ($Recurse) {
                      $params.Recurse = $true
                  }

                  Get-ChildItem @params |
                  Where-Object {
                      $_.LastWriteTime -ge $Since -and
                      (
                          $_.Extension -match '^\.(log|txt|etl)$' -or
                          $_.Name -match '(?i)(install|setup|citrix|ctx|msi)'
                      )
                  } |
                  ForEach-Object {
                      $Target.Add([pscustomobject]@{
                          Path = $_.FullName
                          LastWriteTime = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                          SizeKB = [math]::Round($_.Length / 1KB, 1)
                      })
                  }
              }
              catch {}
          }

          $now = Get-Date
          $all = @(
              Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
          )

          $targetProcesses = @(
              $all | Where-Object {
                  (
                      $InstallerName -and
                      $_.Name -ieq $InstallerName
                  ) -or (
                      $InstallerPath -and
                      $_.ExecutablePath -and
                      $_.ExecutablePath -ieq $InstallerPath
                  ) -or (
                      $InstallerPath -and
                      $_.CommandLine -and
                      $_.CommandLine.IndexOf(
                          $InstallerPath,
                          [System.StringComparison]::OrdinalIgnoreCase
                      ) -ge 0
                  )
              }
          )

          $relatedIds = New-Object 'System.Collections.Generic.HashSet[int]'

          foreach ($process in $targetProcesses) {
              [void]$relatedIds.Add([int]$process.ProcessId)
          }

          # Komplette Nachkommen des eigentlichen Installer-Prozesses finden.
          $changed = $true
          while ($changed) {
              $changed = $false

              foreach ($process in $all) {
                  if (
                      $relatedIds.Contains([int]$process.ParentProcessId) -and
                      -not $relatedIds.Contains([int]$process.ProcessId)
                  ) {
                      [void]$relatedIds.Add([int]$process.ProcessId)
                      $changed = $true
                  }
              }
          }

          $processInfo = New-Object 'System.Collections.Generic.List[object]'

          foreach ($process in $all) {
              $pidValue = [int]$process.ProcessId
              $isTarget = $targetProcesses.ProcessId -contains $process.ProcessId
              $isDescendant = $relatedIds.Contains($pidValue) -and -not $isTarget

              $created = $null
              try {
                  $created = [datetime]$process.CreationDate
              }
              catch {}

              $isRecentInstallerProcess = (
                  $created -and
                  $created -ge $now.AddMinutes(-45) -and
                  $process.Name -match '(?i)^(msiexec|setup|installer|install|update|updater|bootstrap).*\.exe$'
              )

              $isProductRelated = (
                  (
                      $InstallerName -match '(?i)citrix' -and
                      (
                          $process.Name -match '(?i)(citrix|receiver|selfservice|ica|workspace)' -or
                          ($process.CommandLine -and $process.CommandLine -match '(?i)citrix')
                      )
                  ) -or (
                      $SoftwareName -match '(?i)(office|project|visio)' -and
                      (
                          $process.Name -match '(?i)(officeclicktorun|officec2rclient|integratedoffice|setup)' -or
                          ($process.CommandLine -and $process.CommandLine -match '(?i)(officeclicktorun|officec2r|microsoft office)')
                      )
                  )
              )

              if (-not ($isTarget -or $isDescendant -or $isRecentInstallerProcess -or $isProductRelated)) {
                  continue
              }

              $cpu = $null
              $ram = $null
              $uptime = $null

              try {
                  $gp = Get-Process -Id $pidValue -ErrorAction Stop

                  if ($null -ne $gp.CPU) {
                      $cpu = [math]::Round([double]$gp.CPU, 2)
                  }

                  $ram = [math]::Round(
                      [double]$gp.WorkingSet64 / 1MB,
                      1
                  )

                  try {
                      $uptime = [math]::Round(
                          ($now - $gp.StartTime).TotalSeconds,
                          0
                      )
                  }
                  catch {}
              }
              catch {}

              $role = "RELATED"

              if ($isDescendant) {
                  $role = "CHILD"
              }

              if ($isTarget) {
                  $role = "TARGET"
              }

              $processInfo.Add([pscustomobject]@{
                  Role = $role
                  Pid = $pidValue
                  ParentPid = [int]$process.ParentProcessId
                  Name = [string]$process.Name
                  CpuSeconds = $cpu
                  WorkingSetMB = $ram
                  UptimeSeconds = $uptime
                  CommandLine = [string]$process.CommandLine
              })
          }

          $roleOrder = @{
              TARGET = 0
              CHILD = 1
              RELATED = 2
          }

          $processInfo = @(
              $processInfo |
              Sort-Object `
                  @{Expression={ $roleOrder[$_.Role] }},
                  @{Expression={ $_.Pid }}
          )

          # Nur aktuelle, relevante Logdateien einsammeln.
          $logs = New-Object 'System.Collections.Generic.List[object]'
          $since = $now.AddMinutes(-30)

          Add-LogFiles -Target $logs -Path $env:TEMP -Recurse:$false -Since $since
          Add-LogFiles -Target $logs -Path 'C:\Windows\Temp' -Recurse:$false -Since $since

          if (
              $InstallerName -match '(?i)citrix' -or
              $SoftwareName -match '(?i)citrix'
          ) {
              Add-LogFiles -Target $logs -Path 'C:\Program Files (x86)\Citrix\Logs' -Recurse:$true -Since $since
              Add-LogFiles -Target $logs -Path 'C:\Program Files\Citrix\Logs' -Recurse:$true -Since $since
              Add-LogFiles -Target $logs -Path 'C:\ProgramData\Citrix\Logs' -Recurse:$true -Since $since
          }

          $logs = @(
              $logs |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 8
          )

          $msiEvents = @()

          try {
              $msiEvents = @(
                  Get-WinEvent `
                      -FilterHashtable @{
                          LogName = 'Application'
                          ProviderName = 'MsiInstaller'
                          StartTime = $now.AddMinutes(-15)
                      } `
                      -ErrorAction SilentlyContinue |
                  Select-Object -First 5 |
                  ForEach-Object {
                      $message = [string]$_.Message
                      $message = $message -replace "`r?`n", " "

                      if ($message.Length -gt 500) {
                          $message = $message.Substring(0, 500) + "..."
                      }

                      [pscustomobject]@{
                          Time = $_.TimeCreated.ToString("HH:mm:ss")
                          Id = $_.Id
                          Message = $message
                      }
                  }
              )
          }
          catch {}

          $Ansible.Result = [ordered]@{
              Timestamp = $now.ToString("yyyy-MM-dd HH:mm:ss")
              TargetRunning = ($targetProcesses.Count -gt 0)
              TargetPids = @($targetProcesses.ProcessId)
              PendingReboot = (Get-PendingReboot)
              Processes = @($processInfo)
              Logs = @($logs)
              MsiEvents = @($msiEvents)
          }

          $Ansible.Changed = $false

        parameters:
          InstallerPath: "{{ mavi_probe_installer_path | default('') }}"
          InstallerName: "{{ mavi_probe_installer_name | default('') }}"
          SoftwareName: "{{ mavi_probe_software_name | default('') }}"
      register: mavi_probe_result
      changed_when: false
      failed_when: false

    - name: Probe-Ergebnis für den Python-Provisioner speichern
      ansible.builtin.copy:
        content: "{{ mavi_probe_result.result | default({}) | to_json }}"
        dest: "{{ mavi_probe_output_file }}"
        mode: '0600'
      delegate_to: localhost
      become: false
      changed_when: false
"""

DIAGNOSTIC_TASK_TEMPLATE = r"""---
- name: "{{ software_key }} | Installationsfehler diagnostizieren"
  ansible.windows.win_powershell:
    error_action: continue
    script: |
      [CmdletBinding()]
      param(
        [Parameter(Mandatory=$true)][string]$Installer,
        [string]$LocalInstaller = "",
        [string]$CreatesPath = "",
        [string]$Arguments = "",
        [string]$PackageType = "",
        [string]$FailureRc = "",
        [string]$FailureMessage = "",
        [string]$FailureStdout = "",
        [string]$FailureStderr = "",
        [string]$InstallContext = ""
      )

      function OneLine([object]$Value, [int]$Max = 900) {
          if ($null -eq $Value) { return "" }
          $s = [string]$Value
          $s = $s -replace "`r?`n", " | "
          if ($s.Length -gt $Max) {
              return $s.Substring(0, $Max) + "..."
          }
          return $s
      }

      function Redact-Sensitive([object]$Value, [int]$Max = 1200) {
          if ($null -eq $Value) { return "" }
          $s = [string]$Value
          $names = 'password|passwd|pass|passphrase|pwd|pin|token|access[-_]?token|refresh[-_]?token|session[-_]?(?:id|token)|jwt|cookie|set[-_]?cookie|secret|client[-_]?(?:secret|key)|consumer[-_]?secret|api[-_]?key|apikey|aws[-_]?secret[-_]?access[-_]?key|aws[-_]?access[-_]?key[-_]?id|vault[-_]?password(?:[-_]?file)?|license[-_]?key|licensekey|product[-_]?key|serial(?:number)?|authorization|credential|connection[-_]?string|private[-_]?key'

          $s = [regex]::Replace($s, '(?i)(\b(?:Proxy-)?Authorization\s*[:=]\s*)[^\r\n,]+', '$1***REDACTED***')
          $s = [regex]::Replace($s, '(?i)(\bBearer\s+)[^\s,;]+', '$1***REDACTED***')
          # KEY=value, KEY:"value with spaces" und JSON-artige Formen.
          $s = [regex]::Replace(
              $s,
              '(?i)(["'']?(?:' + $names + ')["'']?\s*(?:=|:)\s*)("[^"]*"|''[^'']*''|[^\s,;]+)',
              '$1***REDACTED***'
          )
          # --password value, /token value, -Password value und bewusst auch -p.
          $s = [regex]::Replace(
              $s,
              '(?i)((?<!\S)(?:(?:--?|/)(?:' + $names + ')|-p)\s+)("[^"]*"|''[^'']*''|[^\s,;]+)',
              '$1***REDACTED***'
          )
          $s = [regex]::Replace($s, '(?i)(://[^/\s:@]+:)[^@/\s]+(?=@)', '$1***REDACTED***')
          # Zum Schluss auch unquotierte Connection-String-Werte mit
          # Leerzeichen bis zum Semikolon vollständig abdecken.
          $s = [regex]::Replace(
              $s,
              '(?i)(' + $names + ')(\s*=\s*)[^;\r\n]+(?=;)',
              '$1$2***REDACTED***'
          )
          return OneLine $s $Max
      }

      $rcHelp = switch ($FailureRc) {
          "2"    { "Datei oder Pfad nicht gefunden." }
          "5"    { "Zugriff verweigert. Berechtigungen/Elevation prüfen." }
          "87"   { "Ungültiger Parameter. Sehr starker Verdacht auf falsche Kommandozeilen-Flags." }
          "740"  { "Installer verlangt Elevation." }
          "1602" { "Installation wurde abgebrochen." }
          "1603" { "Generischer fataler Installer-/MSI-Fehler. Möglich sind falsche Flags, defekte/alte Installation, Pending Reboot, blockierte Dateien oder eine fehlerhafte Custom Action." }
          "1618" { "Eine andere Windows-Installer/MSI-Installation läuft bereits." }
          "1619" { "MSI-Paket konnte nicht geöffnet werden." }
          "1620" { "Windows Installer meldet ein ungültiges oder defektes Paket." }
          "1625" { "Installation wurde durch eine Systemrichtlinie verhindert." }
          "1638" { "Eine andere Version dieses Produkts ist bereits installiert." }
          "1639" { "Ungültige Windows-Installer-Kommandozeile. Sehr starker Verdacht auf falsche MSI-Parameter/Properties." }
          "1641" { "Installation erfolgreich, Neustart wurde ausgelöst." }
          "3010" { "Installation erfolgreich, Neustart erforderlich." }
          default { "Unbekannter oder herstellerspezifischer Exit-Code." }
      }

      $parameterCheck = "Kein eindeutiger Parameterfehler aus dem Exit-Code ableitbar."
      if ($PackageType -ieq "exe" -and [string]::IsNullOrWhiteSpace($Arguments)) {
          $parameterCheck = "EXE OHNE PARAMETER gestartet. Das ist erlaubt. Falls der Installer eine GUI oder Silent-Flags erwartet, können fehlende Flags die Ursache sein."
      }
      elseif ($FailureRc -in @("87", "1639")) {
          $parameterCheck = "HOHER VERDACHT AUF FALSCHE PARAMETER. Exakte Flags für genau diese Installer-Datei prüfen."
      }
      elseif ($FailureRc -eq "1603") {
          $parameterCheck = "PARAMETER SIND EINE MÖGLICHE URSACHE, aber 1603 ist nicht eindeutig. Windows-Events und vorhandene Installation mitprüfen."
      }
      elseif (-not [string]::IsNullOrWhiteSpace($Arguments)) {
          $parameterCheck = "Parameter wurden übergeben. Der Exit-Code beweist aber nicht automatisch, dass sie falsch sind."
      }
      elseif ($PackageType -ieq "msi") {
          $parameterCheck = "MSI ohne zusätzliche 'arguments' ist normalerweise okay; win_package übernimmt den MSI-Aufruf."
      }

      $fileInfo = $null
      $sigStatus = "unbekannt"
      if (Test-Path -LiteralPath $Installer) {
          try {
              $fileInfo = Get-Item -LiteralPath $Installer -ErrorAction Stop
          } catch {}
          try {
              $sigStatus = [string](Get-AuthenticodeSignature -FilePath $Installer).Status
          } catch {}
      }

      $pendingReboot = $false
      try {
          $rebootKeys = @(
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
          )
          foreach ($key in $rebootKeys) {
              if (Test-Path $key) { $pendingReboot = $true }
          }
          $sm = Get-ItemProperty `
              'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
              -Name PendingFileRenameOperations `
              -ErrorAction SilentlyContinue
          if ($sm.PendingFileRenameOperations) { $pendingReboot = $true }
      } catch {}

      $processes = @()
      try {
          $processes = @(
              Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
              Where-Object {
                  $_.Name -match '^(msiexec|setup|install|installer|update|updater).*\\.exe$' -or
                  $_.CommandLine -match 'msiexec|Mavi-Provisioner\\Installers'
              } |
              Select-Object -First 12 |
              ForEach-Object {
                  "PID=$($_.ProcessId) NAME=$($_.Name) CMD=$(Redact-Sensitive $_.CommandLine 700)"
              }
          )
      } catch {}

      $events = @()
      try {
          $since = (Get-Date).AddMinutes(-30)
          $events = @(
              Get-WinEvent `
                  -FilterHashtable @{ LogName='Application'; StartTime=$since } `
                  -ErrorAction SilentlyContinue |
              Where-Object {
                  $_.ProviderName -match 'MsiInstaller|Application Error|Windows Error Reporting|Application Hang'
              } |
              Select-Object -First 15 |
              ForEach-Object {
                  "$($_.TimeCreated.ToString('HH:mm:ss')) | $($_.ProviderName) | ID=$($_.Id) | $(Redact-Sensitive $_.Message 900)"
              }
          )
      } catch {}

      $result = [ordered]@{
          Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
          RcHelp = $rcHelp
          ParameterCheck = $parameterCheck
          InstallerExists = (Test-Path -LiteralPath $Installer)
          InstallerSize = if ($fileInfo) { $fileInfo.Length } else { $null }
          FileVersion = if ($fileInfo) { $fileInfo.VersionInfo.FileVersion } else { $null }
          ProductName = if ($fileInfo) { $fileInfo.VersionInfo.ProductName } else { $null }
          CompanyName = if ($fileInfo) { $fileInfo.VersionInfo.CompanyName } else { $null }
          SignatureStatus = $sigStatus
          PendingReboot = $pendingReboot
          RunningInstallerProcesses = $processes
          RecentInstallerEvents = $events
          Context = $InstallContext
          LocalInstallerRedacted = (Redact-Sensitive $LocalInstaller 1200)
          InstallerRedacted = (Redact-Sensitive $Installer 1200)
          CreatesPathRedacted = (Redact-Sensitive $CreatesPath 1200)
          ArgumentsRedacted = (Redact-Sensitive $Arguments 1200)
          InvocationRedacted = (Redact-Sensitive ('"' + $Installer + '" ' + $Arguments) 1600)
          FailureRc = $FailureRc
          FailureMessage = (Redact-Sensitive $FailureMessage 1200)
          FailureStdout = (Redact-Sensitive $FailureStdout 1200)
          FailureStderr = (Redact-Sensitive $FailureStderr 1200)
      }

      $Ansible.Result = $result
      $Ansible.Changed = $false
    parameters:
      Installer: "{{ mavi_failure_executable | default(remote_installer) }}"
      LocalInstaller: "{{ app.installer | default('') }}"
      CreatesPath: "{{ app.creates_path | default('') }}"
      Arguments: "{{ mavi_failure_arguments | default(app.arguments | default('')) }}"
      PackageType: "{{ app.type | default('unbekannt') }}"
      FailureRc: "{{ mavi_failure_result.rc | default('unbekannt') }}"
      FailureMessage: "{{ mavi_failure_result.msg | default('') }}"
      FailureStdout: "{{ mavi_failure_result.stdout | default('') }}"
      FailureStderr: "{{ mavi_failure_result.stderr | default('') }}"
      InstallContext: "{{ mavi_failure_context | default(app.context | default('machine')) }}"
  register: mavi_diag
  # Die Modulparameter enthalten bewusst die echte Installer-Kommandozeile,
  # damit Windows sie diagnostizieren kann. Ansible darf sie nie protokollieren;
  # sichtbar wird ausschließlich das zentral geschwärzte Ergebnis unten.
  no_log: true
  failed_when: false
  changed_when: false

- name: "{{ software_key }} | COPY-PASTE Fehlerbericht"
  ansible.builtin.debug:
    msg: |
      ====================== Mavi INSTALL-DIAGNOSE ======================
      Diagnose-Version: 1
      Host: {{ inventory_hostname }}
      Software-Key: {{ software_key }}
      Name: {{ app.name | default(software_key) }}
      Typ: {{ app.type | default('unbekannt') }}
      Kontext: {{ mavi_failure_context | default(app.context | default('machine')) }}
      Installer lokal: {{ mavi_diag.result.LocalInstallerRedacted | default('(nicht ermittelt)', true) }}
      Installer remote/ausgeführt: {{ mavi_diag.result.InstallerRedacted | default('(nicht ermittelt)', true) }}
      Parameter: {{ mavi_diag.result.ArgumentsRedacted | default('(KEINE)', true) }}
      Creates-Path: {{ mavi_diag.result.CreatesPathRedacted | default('(KEINER)', true) }}

      AUSGEFÜHRTER AUFRUF:
      {{ mavi_diag.result.InvocationRedacted | default('(nicht ermittelt)', true) }}

      FEHLER:
      Exit-Code: {{ mavi_diag.result.FailureRc | default(mavi_failure_result.rc | default('unbekannt')) }}
      Bedeutung: {{ mavi_diag.result.RcHelp | default('(nicht ermittelt)') }}
      Parameter-Check: {{ mavi_diag.result.ParameterCheck | default('(nicht ermittelt)') }}
      Ansible-Meldung: {{ mavi_diag.result.FailureMessage | default('(keine)', true) }}
      stdout: {{ mavi_diag.result.FailureStdout | default('(leer)', true) }}
      stderr: {{ mavi_diag.result.FailureStderr | default('(leer)', true) }}
      reboot_required: {{ mavi_failure_result.reboot_required | default(false) }}

      INSTALLER-DATEI AUF WINDOWS:
      Vorhanden: {{ mavi_diag.result.InstallerExists | default('(unbekannt)') }}
      Größe: {{ mavi_diag.result.InstallerSize | default('(unbekannt)') }}
      FileVersion: {{ mavi_diag.result.FileVersion | default('(unbekannt)', true) }}
      ProductName: {{ mavi_diag.result.ProductName | default('(unbekannt)', true) }}
      CompanyName: {{ mavi_diag.result.CompanyName | default('(unbekannt)', true) }}
      Signatur: {{ mavi_diag.result.SignatureStatus | default('(unbekannt)', true) }}
      Pending Reboot: {{ mavi_diag.result.PendingReboot | default('(unbekannt)') }}

      LAUFENDE INSTALLER-PROZESSE:
      {{ mavi_diag.result.RunningInstallerProcesses | default([]) | to_nice_yaml(indent=2) }}

      RELEVANTE WINDOWS-EVENTS DER LETZTEN 30 MINUTEN:
      {{ mavi_diag.result.RecentInstallerEvents | default([]) | to_nice_yaml(indent=2) }}

      Dieser Block wurde vor der Ausgabe zentral auf typische Passwörter,
      Tokens, Schlüssel, Credentials und URI-Zugangsdaten geschwärzt.
      ==================== ENDE Mavi INSTALL-DIAGNOSE ====================

- name: "{{ software_key }} | Installation nach Diagnose als fehlgeschlagen markieren"
  ansible.builtin.fail:
    msg: >-
      Installation fehlgeschlagen. Der vollständige
      'Mavi INSTALL-DIAGNOSE'-Block steht direkt darüber.
"""
