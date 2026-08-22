# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Ansible-Vorlagen für Drucker.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations


PRINTER_PLAYBOOK_TEMPLATE = r"""---
- name: TCP/IP-Drucker aus Mavi-Katalog installieren
  hosts: windows
  gather_facts: false

  vars_files:
    - "{{ printer_catalog_file }}"

  pre_tasks:
    - name: Gewünschte Drucker bestimmen
      ansible.builtin.set_fact:
        requested_printers: >-
          {{
            (printers.keys() | list)
            if (install_all_printers | default(false) | bool)
            else (printer_names | default([]))
          }}

    - name: Prüfen, ob mindestens ein Drucker gewählt wurde
      ansible.builtin.assert:
        that:
          - requested_printers | length > 0
        fail_msg: "Keine Drucker ausgewählt."

    - name: Prüfen, ob alle Drucker im Katalog existieren
      ansible.builtin.assert:
        that:
          - item in printers
        fail_msg: "Drucker '{{ item }}' ist nicht im Druckerkatalog vorhanden."
      loop: "{{ requested_printers }}"

  tasks:
    - name: TCP/IP-Drucker installieren
      ansible.builtin.include_tasks: tasks/install_printer_one.yml
      loop: "{{ requested_printers }}"
      loop_control:
        loop_var: printer_key
        label: "{{ printer_key }}"
"""

PRINTER_TASK_TEMPLATE = r"""---
- name: "{{ printer_key }} | Druckerdaten laden"
  ansible.builtin.set_fact:
    printer_cfg: "{{ printers[printer_key] }}"
    printer_remote_dir: >-
      C:\Mavi-Provisioner\PrinterDrivers\{{ printer_key | regex_replace('[^A-Za-z0-9_-]', '_') }}

- name: "{{ printer_key }} | Remote-INF-Pfad bestimmen"
  ansible.builtin.set_fact:
    printer_remote_inf: >-
      {{ printer_remote_dir }}\{{
        printer_cfg.driver_inf_relative
        | default(printer_cfg.driver_inf | basename)
        | replace('/', '\\')
      }}

- name: "{{ printer_key }} | Treiberordner auf dem Ansible-Server prüfen"
  ansible.builtin.stat:
    path: "{{ printer_cfg.driver_package_dir }}"
  delegate_to: localhost
  become: false
  register: printer_driver_source

- name: "{{ printer_key }} | Treiberordner muss vorhanden sein"
  ansible.builtin.assert:
    that:
      - printer_driver_source.stat.exists
      - printer_driver_source.stat.isdir
    fail_msg: >-
      Druckertreiberordner fehlt auf dem Ansible-Server:
      {{ printer_cfg.driver_package_dir }}

- name: "{{ printer_key }} | Lokale INF-Datei prüfen"
  ansible.builtin.stat:
    path: "{{ printer_cfg.driver_inf }}"
  delegate_to: localhost
  become: false
  register: printer_inf_source

- name: "{{ printer_key }} | INF-Datei muss vorhanden sein"
  ansible.builtin.assert:
    that:
      - printer_inf_source.stat.exists
      - printer_inf_source.stat.isreg
    fail_msg: "Druckertreiber-INF fehlt: {{ printer_cfg.driver_inf }}"

- name: "{{ printer_key }} | Zielordner für Druckertreiber erstellen"
  ansible.windows.win_file:
    path: "{{ printer_remote_dir }}"
    state: directory

- name: "{{ printer_key }} | Komplettes Druckertreiberpaket kopieren"
  ansible.windows.win_copy:
    src: "{{ printer_cfg.driver_package_dir }}/"
    dest: "{{ printer_remote_dir }}\\"

- name: "{{ printer_key }} | Erreichbarkeit des RAW-Druckerports prüfen"
  ansible.windows.win_powershell:
    error_action: continue
    script: |
      param(
        [Parameter(Mandatory=$true)][string]$PrinterIp,
        [Parameter(Mandatory=$true)][int]$PortNumber
      )

      $reachable = $false
      try {
          $test = Test-NetConnection `
              -ComputerName $PrinterIp `
              -Port $PortNumber `
              -InformationLevel Quiet `
              -WarningAction SilentlyContinue
          $reachable = [bool]$test
      }
      catch {}

      $Ansible.Result = @{
          Reachable = $reachable
          Address = $PrinterIp
          Port = $PortNumber
      }
      $Ansible.Changed = $false
    parameters:
      PrinterIp: "{{ printer_cfg.ip }}"
      PortNumber: "{{ printer_cfg.port_number | default(9100) | int }}"
  register: printer_tcp_probe
  failed_when: false
  changed_when: false

- name: "{{ printer_key }} | Hinweis, wenn Druckerport nicht erreichbar ist"
  ansible.builtin.debug:
    msg: >-
      WARNUNG: {{ printer_cfg.ip }}:{{ printer_cfg.port_number | default(9100) }}
      antwortet aktuell nicht. Mavi richtet Treiber, Port und Queue trotzdem ein.
  when: not (printer_tcp_probe.result.Reachable | default(false) | bool)

- name: "{{ printer_key }} | Treiberpaket in Windows Driver Store importieren"
  ansible.windows.win_command:
    argv:
      - 'C:\Windows\System32\pnputil.exe'
      - '/add-driver'
      - "{{ printer_remote_inf }}"
      - '/install'
  register: printer_pnputil
  become: true
  become_method: runas
  become_user: SYSTEM
  failed_when: false
  changed_when: printer_pnputil.rc == 0

- name: "{{ printer_key }} | Unbekannten Treiber-Herausgeber erkennen"
  ansible.builtin.set_fact:
    printer_publisher_trust_required: >-
      {{
        (printer_pnputil.rc | int == 3758096962)
        or
        (
          (
            (printer_pnputil.stdout | default(''))
            ~ ' '
            ~ (printer_pnputil.stderr | default(''))
          )
          | lower
          | regex_search(
              'trusted publisher|trusted.*publisher|vertrauensw.rdig.*herausgeber|herausgeber.*vertrauensw.rdig|publisher.*trusted'
            )
        )
      }}

- name: "{{ printer_key }} | Signatur und Herausgeber des Treiberkatalogs ermitteln"
  ansible.windows.win_powershell:
    error_action: stop
    script: |
      [CmdletBinding()]
      param(
        [Parameter(Mandatory=$true)][string]$DriverRoot,
        [Parameter(Mandatory=$true)][string]$InfPath
      )

      if (-not (Test-Path -LiteralPath $InfPath)) {
          throw "INF-Datei fehlt: $InfPath"
      }

      $infDir = Split-Path -Parent $InfPath
      $catalogNames = New-Object 'System.Collections.Generic.List[string]'

      foreach ($line in (Get-Content -LiteralPath $InfPath -ErrorAction Stop)) {
          if ($line -match '^\s*CatalogFile(?:\.[^=]+)?\s*=\s*(.+?)\s*$') {
              $value = [string]$Matches[1]
              $value = ($value -split ';', 2)[0].Trim().Trim('"').Trim("'")
              if (-not [string]::IsNullOrWhiteSpace($value)) {
                  $catalogNames.Add($value)
              }
          }
      }

      $catPath = $null
      foreach ($catalogName in @($catalogNames)) {
          $candidate = Join-Path $infDir $catalogName
          if (Test-Path -LiteralPath $candidate) {
              $catPath = (Get-Item -LiteralPath $candidate).FullName
              break
          }

          $leaf = Split-Path -Leaf $catalogName
          $matches = @(
              Get-ChildItem -LiteralPath $DriverRoot -Recurse -File -Filter $leaf -ErrorAction SilentlyContinue
          )
          if ($matches.Count -eq 1) {
              $catPath = $matches[0].FullName
              break
          }
      }

      if (-not $catPath) {
          $nearbyCats = @(
              Get-ChildItem -LiteralPath $infDir -File -Filter '*.cat' -ErrorAction SilentlyContinue
          )
          if ($nearbyCats.Count -eq 1) {
              $catPath = $nearbyCats[0].FullName
          }
      }

      if (-not $catPath) {
          throw (
              "Kein eindeutiger CAT-Sicherheitskatalog für '$InfPath' gefunden. " +
              "Mavi vertraut ohne eindeutig zuordenbare Signatur keinem Publisher."
          )
      }

      $signature = Get-AuthenticodeSignature -LiteralPath $catPath
      $cert = $signature.SignerCertificate

      if ($null -eq $cert) {
          throw "CAT-Datei '$catPath' besitzt kein auslesbares Signer-Zertifikat."
      }

      $alreadyTrusted = Test-Path -LiteralPath ("Cert:\LocalMachine\TrustedPublisher\" + $cert.Thumbprint)

      $Ansible.Result = [ordered]@{
          Catalog = $catPath
          SignatureStatus = [string]$signature.Status
          SignatureMessage = [string]$signature.StatusMessage
          Subject = [string]$cert.Subject
          Issuer = [string]$cert.Issuer
          Thumbprint = [string]$cert.Thumbprint
          NotBefore = $cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss')
          NotAfter = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
          AlreadyTrusted = [bool]$alreadyTrusted
      }
      $Ansible.Changed = $false
    parameters:
      DriverRoot: "{{ printer_remote_dir }}"
      InfPath: "{{ printer_remote_inf }}"
  register: printer_publisher_signature
  become: true
  become_method: runas
  become_user: SYSTEM
  when: printer_publisher_trust_required | bool

- name: "{{ printer_key }} | Ungültige oder nicht prüfbare Publisher-Signatur ablehnen"
  ansible.builtin.fail:
    msg: |
      Windows verlangt Vertrauen für den Herausgeber dieses Druckertreibers,
      aber die CAT-Signatur ist nicht eindeutig als gültig prüfbar.

      CAT: {{ printer_publisher_signature.result.Catalog | default('(unbekannt)') }}
      Signaturstatus: {{ printer_publisher_signature.result.SignatureStatus | default('(unbekannt)') }}
      Statusmeldung: {{ printer_publisher_signature.result.SignatureMessage | default('(keine)', true) }}
      Publisher: {{ printer_publisher_signature.result.Subject | default('(unbekannt)') }}
      Thumbprint: {{ printer_publisher_signature.result.Thumbprint | default('(unbekannt)') }}

      Mavi nimmt in diesem Zustand KEINE automatische Vertrauensstellung vor.
  when:
    - printer_publisher_trust_required | bool
    - printer_publisher_signature.result.SignatureStatus | default('') != 'Valid'

- name: "{{ printer_key }} | Bereits vertrauten Publisher anzeigen"
  ansible.builtin.debug:
    msg: >-
      Publisher ist bereits in LocalMachine\\TrustedPublisher vorhanden:
      {{ printer_publisher_signature.result.Subject }}
      [{{ printer_publisher_signature.result.Thumbprint }}]
  when:
    - printer_publisher_trust_required | bool
    - printer_publisher_signature.result.SignatureStatus | default('') == 'Valid'
    - printer_publisher_signature.result.AlreadyTrusted | default(false) | bool

- name: "{{ printer_key }} | Sicherheitsfreigabe für Treiber-Herausgeber"
  ansible.builtin.pause:
    prompt: |

      ================= Mavi DRUCKERTREIBER-SICHERHEITSFREIGABE =================
      Windows kennt den Herausgeber dieses gültig signierten Treibers noch nicht
      als vertrauenswürdigen Publisher.

      Drucker:     {{ printer_cfg.name }}
      Treiber:     {{ printer_cfg.driver_name }}
      CAT-Datei:   {{ printer_publisher_signature.result.Catalog }}
      Publisher:   {{ printer_publisher_signature.result.Subject }}
      Aussteller:  {{ printer_publisher_signature.result.Issuer }}
      Thumbprint:  {{ printer_publisher_signature.result.Thumbprint }}
      Gültig von:  {{ printer_publisher_signature.result.NotBefore }}
      Gültig bis:  {{ printer_publisher_signature.result.NotAfter }}

      Bei Bestätigung wird NUR dieses konkrete Signer-Zertifikat in
      Cert:\LocalMachine\TrustedPublisher aufgenommen. Es wird KEINE
      Treibersignaturprüfung deaktiviert und KEINE Root-CA hinzugefügt.

      Nur bestätigen, wenn Hersteller/Paket erwartet sind.
      Publisher auf diesem PC vertrauen? [j/N]
  register: printer_publisher_confirmation
  when:
    - printer_publisher_trust_required | bool
    - printer_publisher_signature.result.SignatureStatus | default('') == 'Valid'
    - not (printer_publisher_signature.result.AlreadyTrusted | default(false) | bool)
    - printer_prompt_publisher_trust | default(true) | bool

- name: "{{ printer_key }} | Publisher-Freigabe auswerten"
  ansible.builtin.set_fact:
    printer_publisher_approved: >-
      {{
        (printer_publisher_signature.result.AlreadyTrusted | default(false) | bool)
        or
        (
          printer_publisher_confirmation.user_input
          | default('')
          | trim
          | lower
          in ['j', 'ja', 'y', 'yes']
        )
      }}
  when: printer_publisher_trust_required | bool

- name: "{{ printer_key }} | Ohne Sicherheitsfreigabe abbrechen"
  ansible.builtin.fail:
    msg: |
      Treiber-Herausgeber wurde NICHT freigegeben. Installation wird sicher abgebrochen.

      Publisher: {{ printer_publisher_signature.result.Subject | default('(unbekannt)') }}
      Thumbprint: {{ printer_publisher_signature.result.Thumbprint | default('(unbekannt)') }}

      Für unbeaufsichtigte Läufe wird ein unbekannter Publisher absichtlich nicht
      automatisch vertraut. Installation interaktiv erneut starten und Publisher prüfen.
  when:
    - printer_publisher_trust_required | bool
    - not (printer_publisher_approved | default(false) | bool)

- name: "{{ printer_key }} | Signer-Zertifikat in TrustedPublisher aufnehmen"
  ansible.windows.win_powershell:
    error_action: stop
    script: |
      [CmdletBinding()]
      param(
        [Parameter(Mandatory=$true)][string]$CatalogPath,
        [Parameter(Mandatory=$true)][string]$ExpectedThumbprint
      )

      if (-not (Test-Path -LiteralPath $CatalogPath)) {
          throw "CAT-Datei fehlt vor Vertrauensstellung: $CatalogPath"
      }

      $signature = Get-AuthenticodeSignature -LiteralPath $CatalogPath
      if ([string]$signature.Status -ne 'Valid') {
          throw "CAT-Signatur ist nicht mehr gültig: $($signature.Status) $($signature.StatusMessage)"
      }

      $cert = $signature.SignerCertificate
      if ($null -eq $cert) {
          throw "Signer-Zertifikat konnte nicht erneut gelesen werden."
      }

      $actualThumbprint = ([string]$cert.Thumbprint).Replace(' ', '').ToUpperInvariant()
      $expected = ([string]$ExpectedThumbprint).Replace(' ', '').ToUpperInvariant()
      if ($actualThumbprint -ne $expected) {
          throw (
              "SICHERHEITSABBRUCH: Signer-Zertifikat hat sich zwischen Prüfung und " +
              "Import geändert. Erwartet=$expected, tatsächlich=$actualThumbprint"
          )
      }

      $existing = Test-Path -LiteralPath ("Cert:\LocalMachine\TrustedPublisher\" + $actualThumbprint)
      if (-not $existing) {
          $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
              'TrustedPublisher',
              [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
          )
          try {
              $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
              $store.Add($cert)
          }
          finally {
              $store.Close()
          }
      }

      $Ansible.Result = @{
          Subject = [string]$cert.Subject
          Thumbprint = $actualThumbprint
          AlreadyTrusted = [bool]$existing
          TrustedNow = $true
      }
      $Ansible.Changed = (-not $existing)
    parameters:
      CatalogPath: "{{ printer_publisher_signature.result.Catalog }}"
      ExpectedThumbprint: "{{ printer_publisher_signature.result.Thumbprint }}"
  register: printer_publisher_import
  become: true
  become_method: runas
  become_user: SYSTEM
  when:
    - printer_publisher_trust_required | bool
    - printer_publisher_approved | default(false) | bool
    - not (printer_publisher_signature.result.AlreadyTrusted | default(false) | bool)

- name: "{{ printer_key }} | Treiberimport nach Publisher-Freigabe erneut versuchen"
  ansible.windows.win_command:
    argv:
      - 'C:\Windows\System32\pnputil.exe'
      - '/add-driver'
      - "{{ printer_remote_inf }}"
      - '/install'
  register: printer_pnputil_retry
  become: true
  become_method: runas
  become_user: SYSTEM
  failed_when: false
  changed_when: printer_pnputil_retry.rc == 0
  when: printer_publisher_trust_required | bool

- name: "{{ printer_key }} | Endgültiges pnputil-Ergebnis bestimmen"
  ansible.builtin.set_fact:
    printer_pnputil_final: >-
      {{
        printer_pnputil_retry
        if (printer_pnputil_retry is defined and printer_pnputil_retry.rc is defined)
        else printer_pnputil
      }}

- name: "{{ printer_key }} | Treiberpaket bei pnputil-Fehler diagnostizieren"
  ansible.windows.win_powershell:
    error_action: continue
    script: |
      param(
        [Parameter(Mandatory=$true)][string]$DriverRoot,
        [Parameter(Mandatory=$true)][string]$InfPath
      )

      $files = @()
      if (Test-Path -LiteralPath $DriverRoot) {
          $files = @(
              Get-ChildItem -LiteralPath $DriverRoot -Recurse -File -ErrorAction SilentlyContinue |
              Select-Object -First 80 |
              ForEach-Object { $_.FullName.Substring($DriverRoot.Length).TrimStart('\') }
          )
      }

      $Ansible.Result = @{
          DriverRootExists = (Test-Path -LiteralPath $DriverRoot)
          InfExists = (Test-Path -LiteralPath $InfPath)
          InfPath = $InfPath
          Files = $files
      }
      $Ansible.Changed = $false
    parameters:
      DriverRoot: "{{ printer_remote_dir }}"
      InfPath: "{{ printer_remote_inf }}"
  register: printer_pnputil_diag
  failed_when: false
  changed_when: false
  # pnputil reports 259 when the package is already present and current.
  # That is a successful, unchanged install rather than a driver import failure.
  when: printer_pnputil_final.rc | int not in [0, 259]

- name: "{{ printer_key }} | pnputil-Fehler verständlich melden"
  ansible.builtin.fail:
    msg: |
      Druckertreiber konnte nicht in den Windows Driver Store importiert werden.
      pnputil Exit-Code: {{ printer_pnputil_final.rc }}
      Ausgabe: {{ printer_pnputil_final.stdout | default('(leer)', true) }}
      Fehlerausgabe: {{ printer_pnputil_final.stderr | default('(leer)', true) }}
      Remote-INF vorhanden: {{ printer_pnputil_diag.result.InfExists | default('unbekannt') }}
      Remote-INF: {{ printer_pnputil_diag.result.InfPath | default(printer_remote_inf) }}
      Kopierte Paketdateien (Auszug):
      {{ printer_pnputil_diag.result.Files | default([]) | to_nice_yaml(indent=2) }}

      Falls die Meldung auf fehlende Dateien hinweist, fehlt meist mindestens eine
      von der INF referenzierte CAT/CAB/DLL/GPD-Datei. Falls die Meldung einen
      unbekannten Herausgeber nennt, prüfe Publisher/Thumbprint und die lokale
      TrustedPublisher-Richtlinie.
  when: printer_pnputil_final.rc | int not in [0, 259]

- name: "{{ printer_key }} | Treiber, TCP/IP-Port und Druckerqueue sicherstellen"
  ansible.windows.win_powershell:
    error_action: stop
    script: |
      [CmdletBinding()]
      param(
        [Parameter(Mandatory=$true)][string]$PrinterName,
        [Parameter(Mandatory=$true)][string]$DriverName,
        [Parameter(Mandatory=$true)][string]$PortName,
        [Parameter(Mandatory=$true)][string]$PrinterIp,
        [Parameter(Mandatory=$true)][int]$PortNumber
      )

      Import-Module PrintManagement -ErrorAction Stop
      $changed = $false
      $actions = New-Object 'System.Collections.Generic.List[string]'

      $driver = Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue
      if ($null -eq $driver) {
          try {
              Add-PrinterDriver -Name $DriverName -ErrorAction Stop
              $changed = $true
              $actions.Add("Treiber registriert: $DriverName")
          }
          catch {
              $names = @(
                  Get-PrinterDriver -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty Name
              )
              $sample = ($names | Select-Object -First 25) -join ' | '
              throw (
                  "Druckertreiber '$DriverName' konnte nach pnputil nicht " +
                  "registriert werden. Prüfe den EXAKTEN Treibernamen. " +
                  "Vorhandene Treiber (Auszug): $sample. Fehler: $($_.Exception.Message)"
              )
          }
      }

      $port = Get-PrinterPort -Name $PortName -ErrorAction SilentlyContinue
      if ($null -eq $port) {
          Add-PrinterPort `
              -Name $PortName `
              -PrinterHostAddress $PrinterIp `
              -PortNumber $PortNumber `
              -ErrorAction Stop
          $changed = $true
          $actions.Add("TCP/IP-Port erstellt: $PortName -> $PrinterIp`:$PortNumber")
      }
      else {
          $existingAddress = [string]$port.PrinterHostAddress
          if ($existingAddress -and $existingAddress -ne $PrinterIp) {
              throw (
                  "Port '$PortName' existiert bereits, zeigt aber auf " +
                  "'$existingAddress' statt '$PrinterIp'. Bitte Portnamen ändern " +
                  "oder alten Port bewusst entfernen."
              )
          }
      }

      $queue = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
      if ($null -eq $queue) {
          Add-Printer `
              -Name $PrinterName `
              -DriverName $DriverName `
              -PortName $PortName `
              -ErrorAction Stop
          $changed = $true
          $actions.Add("Druckerqueue erstellt: $PrinterName")
      }
      else {
          $update = @{}
          if ([string]$queue.DriverName -ne $DriverName) {
              $update.DriverName = $DriverName
          }
          if ([string]$queue.PortName -ne $PortName) {
              $update.PortName = $PortName
          }

          if ($update.Count -gt 0) {
              Set-Printer -Name $PrinterName @update -ErrorAction Stop
              $changed = $true
              $actions.Add("Bestehende Druckerqueue aktualisiert: $PrinterName")
          }
      }

      $final = Get-Printer -Name $PrinterName -ErrorAction Stop
      $Ansible.Result = @{
          Name = [string]$final.Name
          DriverName = [string]$final.DriverName
          PortName = [string]$final.PortName
          PrinterIp = $PrinterIp
          PortNumber = $PortNumber
          Actions = @($actions)
      }
      $Ansible.Changed = $changed
    parameters:
      PrinterName: "{{ printer_cfg.name }}"
      DriverName: "{{ printer_cfg.driver_name }}"
      PortName: "{{ printer_cfg.port_name }}"
      PrinterIp: "{{ printer_cfg.ip }}"
      PortNumber: "{{ printer_cfg.port_number | default(9100) | int }}"
  register: printer_install_result
  become: true
  become_method: runas
  become_user: SYSTEM

- name: "{{ printer_key }} | Drucker-Ergebnis anzeigen"
  ansible.builtin.debug:
    msg: >-
      Fertig: {{ printer_install_result.result.Name }} |
      IP={{ printer_cfg.ip }} |
      Port={{ printer_install_result.result.PortName }} |
      Treiber={{ printer_install_result.result.DriverName }}

- name: "{{ printer_key }} | Temporären Treiberordner entfernen"
  ansible.windows.win_file:
    path: "{{ printer_remote_dir }}"
    state: absent
"""
