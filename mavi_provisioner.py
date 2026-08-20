#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mavi Provisioner contributors
"""
Mavi Provisioner
================

TUI-first provisioning for Windows endpoints with Ansible.

v0.9.4 adds a repeatable WinRM/Kerberos reset over the existing OpenSSH key.
It removes all WinRM listeners, Mavi WinRM firewall rules, certificates,
policy values and working files from the selected Windows endpoint, then
stops and disables WinRM. OpenSSH can remain available for immediate
re-provisioning or be disabled as the final delayed remote step together
with the current environment's Mavi key and firewall rule. Host-specific
WinRM state and issued certificates are removed from the controller while
the shared Mavi WinRM CA remains available for other endpoints.

v0.9.3 makes the fail-closed Windows TCP/22 firewall audit application- and
service-aware. Program-specific rules such as FortiClient.exe no longer count
as SSH bypasses, while unbound rules and rules that can apply to sshd still
abort safely.

v0.9.2 aligns the Windows CA-import flow with the proven production bootstrap.
The fragile TEMP marker is gone; CA ownership is handed to the successful
bootstrap process only when this launcher actually added the CA.

This Open Source edition deliberately contains no organisation-specific
network addresses, domains, shares, accounts, certificates, inventories or
installer catalogues. Start it without arguments and choose "Neue Umgebung
einrichten". The setup assistant writes a local environment profile; the
read-only Doctor explains missing prerequisites per feature.

Supported feature areas include software catalogues, WinGet and Microsoft
Store packages, printer deployment, OpenSSH bootstrap, and an optional
WinRM HTTPS/Kerberos endpoint. Secrets belong in Ansible Vault or another
secret provider, never in a profile or repository.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import getpass
import html
import hashlib
import ipaddress
import json
import os
import re
import queue
import secrets
import shutil
import socket
import subprocess
import struct
import sys
import tempfile
import threading
import time
import signal
import ssl
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

VERSION = "0.9.4"
# Ein neues Projekt wird bewusst außerhalb des Quell-Repositorys angelegt.
# So bleiben Umgebungswerte, Inventories, Zertifikate und Secrets getrennt
# vom veröffentlichbaren Programmcode.
DEFAULT_PROJECT = Path(
    os.environ.get(
        "XDG_DATA_HOME",
        str(Path.home() / ".local" / "share"),
    )
) / "mavi-provisioner"

try:
    import pefile  # optional: genauerer PE-VersionInfo-Scan
except ImportError:
    pefile = None

try:
    import yaml
except ImportError:
    print(
        "\nFEHLER: Python-Modul 'yaml' fehlt.\n"
        "Auf Ubuntu installieren mit:\n\n"
        "  sudo apt install -y python3-yaml\n",
        file=sys.stderr,
    )
    sys.exit(2)


CONFIG_TEMPLATE = {
    # Dieses Profil enthält ausschließlich nicht geheime Umgebungsfakten.
    # Passwörter gehören in Ansible Vault oder einen externen Secret Store.
    "profile": {
        "schema_version": 2,
        "name": "",
        "setup_completed": False,
    },
    "local_admin_user": "",
    "identity": {
        # Nicht geheim; der Setup-Assistent übernimmt den Wert zusätzlich in
        # windows.vars. Das Kennwort liegt ausschließlich im Ansible Vault.
        "ansible_user": "",
        "vault_path": "inventory/group_vars/windows/vault.yml",
    },
    "default_catalog": "default",
    # Der Setup-Assistent setzt den HTTPS-Endpunkt. Mavi deaktiviert die
    # Zertifikatsprüfung an keiner Stelle.
    "bootstrap_base_url": "",
    "bootstrap_local_dir": "",
    "ansible_server_ip": "",
    # Leer = das passende private RFC1918-/ULA-Netz automatisch verwenden.
    # Das hält den bewährten Ein-Klick-OpenSSH-Weg ohne zusätzliche Netzfrage
    # im Erststart nutzbar.
    "bootstrap_allowed_cidrs": [],
    # Kurze, umgebungseigene Zertifikatslaufzeiten. Eine CA-Rotation ist immer
    # ein expliziter administrativer Vorgang und geschieht nie still.
    "bootstrap_ca_validity_days": 825,
    "bootstrap_server_cert_validity_days": 90,
    # Leer = automatisch <software_source.local_root>/Mavi-Bootstrap und
    # <software_source.drive>\\Mavi-Bootstrap verwenden.
    "bootstrap_launcher_local_dir": "",
    "bootstrap_launcher_windows_dir": "",
    # Optional: exakter Zertifikat-Subject ODER exakter SimpleName der
    # vorhandenen Hersteller-Signatur der OpenSSH-MSI.
    "openssh_msi_expected_signer": "",
    "software_source": {
        "kind": "local",
        "label": "",
        "drive": "",
        "unc_root": "",
        "local_root": "",
        "mount_user": "",
        "mount_host": "",
    },
    "path_mappings": {},
    "ssh": {
        "port": 22,
        "private_key": "",
    },
    # PSRP/WinRM-Endstufe für eine optionale AD-Domäne. Mavi akzeptiert hier
    # absichtlich ausschließlich Kerberos: Kein Negotiate-/NTLM-Fallback.
    "winrm_https": {
        "domain_suffix": "",
        "port": 5986,
        "auth": "kerberos",
        # Leer = aus dem vorhandenen ansible_user als UPN ableiten.
        # Nur setzen, falls der UPN absichtlich davon abweicht.
        "kerberos_principal": "",
        # Leer = den echten AD-DNS-Server automatisch aus resolvectl bzw.
        # /etc/resolv.conf ermitteln. Optional eine einzelne DNS-Server-IP
        # setzen, wenn der Controller mehrere getrennte Resolver verwendet.
        "kerberos_dns_server": "",
        "message_encryption": "always",
        "disable_http_after_verified": True,
    },
    "ui": {
        # Welche Installationskontexte in der TUI angeboten werden.
        # Interne Werte bleiben stabil, damit bestehende Kataloge kompatibel sind.
        "visible_install_contexts": [
            "machine",
            "system",
            "user_interactive",
            "machine_detached",
            "machine_interactive",
            "user_uac",
        ],
        "install_contexts_schema": 2,
    },
}

CATALOG_TEMPLATE = {"software_catalog": {}}

INSTALLER_RULES_TEMPLATE = {"installer_rules": {}}
PARAMETER_BACKUP_TEMPLATE = {"parameter_profiles": {}}
PRINTER_CATALOG_TEMPLATE = {"printers": {}}

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
  when: printer_pnputil_final.rc | int != 0

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
  when: printer_pnputil_final.rc | int != 0

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
          $names = 'password|passwd|pass|passphrase|pwd|pin|token|access[-_]?token|refresh[-_]?token|session[-_]?(?:id|token)|jwt|cookie|set[-_]?cookie|secret|client[-_]?(?:secret|key)|consumer[-_]?secret|api[-_]?key|apikey|aws[-_]?secret[-_]?access[-_]?key|aws[-_]?access[-_]?key[-_]?id|vault[-_]?password|license[-_]?key|licensekey|product[-_]?key|serial(?:number)?|authorization|credential|connection[-_]?string|private[-_]?key'

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


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, file=sys.stderr, **kwargs)


def die(message: str, code: int = 1) -> None:
    eprint(f"\nFEHLER: {redact_sensitive_text(message)}\n")
    raise SystemExit(code)


def project_paths(project: Path) -> dict[str, Path]:
    return {
        "project": project,
        "inventory": project / "inventory" / "hosts.yml",
        "credentials_vault": project / "inventory" / "group_vars" / "windows" / "vault.yml",
        "software_dir": project / "software",
        "legacy_catalog": project / "software" / "catalog.yml",
        "catalogs_dir": project / "software" / "catalogs",
        "office_configs_dir": project / "software" / "office_configs",
        "installer_rules": project / "software" / "installer_rules.yml",
        "parameter_backups": project / "software" / "parameter_backups.yml",
        "config": project / "software" / "mavi_config.yml",
        "playbooks": project / "playbooks",
        "playbook": project / "playbooks" / "install_catalog.yml",
        "tasks_dir": project / "playbooks" / "tasks",
        "task": project / "playbooks" / "tasks" / "install_one.yml",
        "diagnostic_task": project / "playbooks" / "tasks" / "diagnose_install_failure.yml",
        "live_probe_playbook": project / "playbooks" / "live_install_probe.yml",
        "printers_dir": project / "printers",
        "printer_catalog": project / "printers" / "catalog.yml",
        "printer_playbook": project / "playbooks" / "install_printers.yml",
        "printer_task": project / "playbooks" / "tasks" / "install_printer_one.yml",
        "ssh_dir": project / ".ssh",
        "ssh_key": project / ".ssh" / "mavi_windows_ed25519",
        "ssh_known_hosts": project / ".ssh" / "known_hosts",
        "ssh_bootstrap_dir": project / ".ssh" / "bootstrap",
        # Von der HTTPS-Bootstrap-CA bewusst getrennte CA ausschließlich für
        # WinRM-Serverzertifikate. Sie wird nie über nginx veröffentlicht.
        "winrm_pki_dir": project / ".mavi-winrm-pki",
        # Projektlokale Kerberos-Laufzeitkonfiguration. Mavi verändert nie
        # systemweit /etc/krb5.conf und nutzt ausschließlich diese Datei für
        # seine eigenen Ansible-Unterprozesse.
        "kerberos_runtime_dir": project / ".mavi-kerberos",
        "reports_dir": project / "reports",
    }


def load_yaml(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        value = yaml.safe_load(f)
    return default if value is None else value


def atomic_write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(
                data,
                f,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=120,
            )
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def atomic_write_text(path: Path, content: str, *, mode: int | None = None) -> None:
    """Text vollständig schreiben, bevor der bisherige Pfad ersetzt wird."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        if mode is not None:
            os.chmod(tmp_name, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def write_if_missing(path: Path, content: str) -> bool:
    if path.exists():
        return False
    atomic_write_text(path, content)
    return True


def write_managed_file(path: Path, content: str) -> str:
    """
    Vom Mavi-Tool verwaltete Dateien werden bei einem Versionsupdate aktualisiert.
    Wenn bereits anderer Inhalt existiert, bleibt eine eindeutige, nicht erneut
    überschriebene Sicherung erhalten.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        current = path.read_text(encoding="utf-8")
        if current == content:
            return "unchanged"

        backup = path.with_name(f"{path.name}.bak.{time.time_ns()}")
        atomic_write_text(backup, current)
        atomic_write_text(path, content)
        return "updated"

    atomic_write_text(path, content)
    return "created"


def ensure_initialized(project: Path, quiet: bool = False) -> None:
    p = project_paths(project)
    # Falls dieses Projekt bereits einen gehärteten WinRM-/Kerberos-Transport
    # eingerichtet hat, muss auch ein später neu gestartetes Mavi dieselbe
    # projektlokale KDC-DNS-Konfiguration an seine Ansible-Prozesse vererben.
    # Fehlt sie noch, wird sie ausschließlich beim WinRM-Setup erzeugt.
    _activate_existing_kerberos_runtime_config(project)
    p["software_dir"].mkdir(parents=True, exist_ok=True)
    p["catalogs_dir"].mkdir(parents=True, exist_ok=True)
    p["office_configs_dir"].mkdir(parents=True, exist_ok=True)
    p["printers_dir"].mkdir(parents=True, exist_ok=True)

    # Legacy-Datei bleibt kompatibel, wird in v0.8 aber nicht mehr
    # automatisch für Silent-Erkennung verwendet.
    if not p["installer_rules"].exists():
        atomic_write_yaml(p["installer_rules"], INSTALLER_RULES_TEMPLATE)

    if not p["parameter_backups"].exists():
        atomic_write_yaml(
            p["parameter_backups"],
            PARAMETER_BACKUP_TEMPLATE,
        )
        if not quiet:
            print(
                f"✓ Parameter-Backupdatei angelegt: "
                f"{p['parameter_backups']}"
            )

    if not p["printer_catalog"].exists():
        atomic_write_yaml(p["printer_catalog"], PRINTER_CATALOG_TEMPLATE)
        if not quiet:
            print(f"✓ Druckerkatalog angelegt: {p['printer_catalog']}")

    p["playbooks"].mkdir(parents=True, exist_ok=True)
    p["tasks_dir"].mkdir(parents=True, exist_ok=True)

    created: list[Path] = []
    updated: list[Path] = []
    migrated: list[tuple[Path, Path]] = []

    # Konfiguration anlegen bzw. neue Standardwerte ergänzen.
    if not p["config"].exists():
        atomic_write_yaml(p["config"], CONFIG_TEMPLATE)
        created.append(p["config"])
        config_data = dict(CONFIG_TEMPLATE)
    else:
        config_data = load_yaml(p["config"], {}) or {}
        changed = False

        for key, value in CONFIG_TEMPLATE.items():
            if key not in config_data:
                config_data[key] = value
                changed = True

        # Verschachtelte Bereiche ebenfalls ergänzen.
        for nested_key in (
            "profile",
            "identity",
            "software_source",
            "path_mappings",
            "ssh",
            "winrm_https",
            "ui",
        ):
            defaults = CONFIG_TEMPLATE.get(nested_key, {}) or {}
            current = config_data.get(nested_key, {}) or {}

            # v0.8.33-Migration muss passieren, bevor die neuen UI-Defaults
            # gemerged werden. Sonst würde das Default-Schema die alte
            # Konfiguration bereits wie eine neue aussehen lassen.
            if nested_key == "ui" and "install_contexts_schema" not in current:
                current = dict(current)
                visible = current.get("visible_install_contexts")
                if not isinstance(visible, list):
                    visible = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
                else:
                    visible = list(visible)
                    if "user_uac" not in visible:
                        visible.append("user_uac")
                current["visible_install_contexts"] = visible
                current["install_contexts_schema"] = 2
                changed = True

            merged = dict(defaults)
            merged.update(current)
            if merged != config_data.get(nested_key, {}):
                config_data[nested_key] = merged
                changed = True

        # v0.8.33: Der neue UAC-Kontext existierte vorher noch nicht und kann
        # deshalb in alten Sichtbarkeitslisten nicht bewusst deaktiviert worden sein.
        # Einmalig sichtbar ergänzen; danach respektiert das Optionen-Menü die Auswahl.
        ui_current = dict(config_data.get("ui", {}) or {})
        try:
            ui_schema = int(ui_current.get("install_contexts_schema", 1) or 1)
        except (TypeError, ValueError):
            ui_schema = 1
        if ui_schema < 2:
            visible = ui_current.get("visible_install_contexts")
            if not isinstance(visible, list):
                visible = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
            else:
                visible = list(visible)
                if "user_uac" not in visible:
                    visible.append("user_uac")
            ui_current["visible_install_contexts"] = visible
            ui_current["install_contexts_schema"] = 2
            config_data["ui"] = ui_current
            changed = True

        if changed:
            atomic_write_yaml(p["config"], config_data)
            updated.append(p["config"])

    default_name = str(config_data.get("default_catalog", "default")).strip() or "default"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", default_name):
        default_name = "default"
        config_data["default_catalog"] = default_name
        atomic_write_yaml(p["config"], config_data)
        if p["config"] not in updated:
            updated.append(p["config"])

    default_catalog_path = p["catalogs_dir"] / f"{default_name}.yml"

    # Migration aus v0.2.x:
    # software/catalog.yml bleibt als Legacy-Backup liegen.
    if not default_catalog_path.exists():
        if p["legacy_catalog"].exists():
            legacy_data = load_yaml(p["legacy_catalog"], CATALOG_TEMPLATE)
            if "software_catalog" not in (legacy_data or {}):
                legacy_data = {"software_catalog": legacy_data or {}}
            atomic_write_yaml(default_catalog_path, legacy_data)
            migrated.append((p["legacy_catalog"], default_catalog_path))
        else:
            atomic_write_yaml(default_catalog_path, CATALOG_TEMPLATE)
            created.append(default_catalog_path)

    playbook_status = write_managed_file(p["playbook"], PLAYBOOK_TEMPLATE)
    if playbook_status == "created":
        created.append(p["playbook"])
    elif playbook_status == "updated":
        updated.append(p["playbook"])

    task_status = write_managed_file(p["task"], TASK_TEMPLATE)
    if task_status == "created":
        created.append(p["task"])
    elif task_status == "updated":
        updated.append(p["task"])

    diagnostic_status = write_managed_file(
        p["diagnostic_task"],
        DIAGNOSTIC_TASK_TEMPLATE,
    )
    if diagnostic_status == "created":
        created.append(p["diagnostic_task"])
    elif diagnostic_status == "updated":
        updated.append(p["diagnostic_task"])

    live_probe_status = write_managed_file(
        p["live_probe_playbook"],
        LIVE_PROBE_PLAYBOOK_TEMPLATE,
    )
    if live_probe_status == "created":
        created.append(p["live_probe_playbook"])
    elif live_probe_status == "updated":
        updated.append(p["live_probe_playbook"])

    printer_playbook_status = write_managed_file(
        p["printer_playbook"],
        PRINTER_PLAYBOOK_TEMPLATE,
    )
    if printer_playbook_status == "created":
        created.append(p["printer_playbook"])
    elif printer_playbook_status == "updated":
        updated.append(p["printer_playbook"])

    printer_task_status = write_managed_file(
        p["printer_task"],
        PRINTER_TASK_TEMPLATE,
    )
    if printer_task_status == "created":
        created.append(p["printer_task"])
    elif printer_task_status == "updated":
        updated.append(p["printer_task"])

    if not quiet:
        if migrated:
            print("Katalog migriert:")
            for old_path, new_path in migrated:
                print(f"  ✓ {old_path}")
                print(f"    → {new_path}")
                print("    Alte Datei bleibt als Legacy-Backup erhalten.")

        if created:
            print("Erstellt:")
            for path in created:
                print(f"  ✓ {path}")

        if updated:
            print("Aktualisiert:")
            for path in updated:
                print(f"  ✓ {path}")

        if not created and not updated and not migrated:
            print("✓ Mavi-Provisioner-Dateien sind bereits aktuell.")

        if not p["inventory"].exists():
            print(f"\n! Inventory fehlt noch: {p['inventory']}")



def get_config(project: Path) -> dict[str, Any]:
    """
    Lädt die Konfiguration und ergänzt neue Standardwerte automatisch,
    ohne bestehende benutzerdefinierte Werte zu überschreiben.
    """
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
    atomic_write_yaml(project_paths(project)["config"], config)


def _mavi_prompt_normalized(
    label: str,
    default: str,
    normalizer: Any,
    *,
    allow_empty: bool = True,
) -> str:
    """Einfacher Dialog für nicht geheime Werte mit verständlicher Korrektur."""
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


def normalize_path(raw: str, config: dict[str, Any]) -> Path:
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
    return browse_files(
        root,
        drive,
        extensions={".msi", ".exe"},
        title="Software auswählen",
    )



def choose_installer_path(config: dict[str, Any]) -> Path:
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

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_binary_sample(path: Path, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    size = path.stat().st_size
    with path.open("rb") as f:
        if size <= max_bytes:
            return f.read()
        half = max_bytes // 2
        start = f.read(half)
        f.seek(max(0, size - half))
        end = f.read(half)
        return start + end



def _decode_binary_text(sample: bytes) -> str:
    chunks = []

    try:
        chunks.append(sample.decode("latin-1", errors="ignore"))
    except Exception:
        pass

    try:
        chunks.append(sample.decode("utf-16le", errors="ignore"))
    except Exception:
        pass

    return "\n".join(chunks).lower()


def _extract_execution_level(text_data: str) -> str | None:
    patterns = [
        r'requestedexecutionlevel.{0,300}?level\s*=\s*["\'](requireadministrator|highestavailable|asinvoker)["\']',
        r'level\s*=\s*["\'](requireadministrator|highestavailable|asinvoker)["\'].{0,300}?requestedexecutionlevel',
    ]

    compact = re.sub(r"\s+", " ", text_data, flags=re.MULTILINE)
    for pattern in patterns:
        match = re.search(pattern, compact, re.IGNORECASE)
        if match:
            return match.group(1).lower()
    return None


def _inspect_msi_properties(path: Path) -> dict[str, str]:
    """
    Nutzt msiinfo aus dem Paket msitools, falls es auf dem Controller
    installiert ist. Ohne msiinfo funktioniert das Tool weiterhin.
    """
    exe = shutil.which("msiinfo")
    if not exe:
        return {}

    try:
        result = subprocess.run(
            [exe, "export", str(path), "Property"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:
        return {}

    if result.returncode != 0:
        return {}

    wanted = {
        "ProductName",
        "Manufacturer",
        "ProductVersion",
        "ProductCode",
        "ALLUSERS",
        "MSIINSTALLPERUSER",
    }
    props: dict[str, str] = {}

    for line in result.stdout.splitlines():
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) >= 2 and parts[0] in wanted:
            props[parts[0]] = parts[1]

    return props




# ---------------------------------------------------------------------
# Intelligente Silent-Parameter-Erkennung und lokale Lernregeln
# ---------------------------------------------------------------------

SILENT_SWITCH_DEFINITIONS: dict[str, dict[str, Any]] = {
    "/silent": {
        "kind": "silent",
        "weight": 9,
        "canonical": "/silent",
    },
    "--silent": {
        "kind": "silent",
        "weight": 9,
        "canonical": "--silent",
    },
    "/verysilent": {
        "kind": "silent",
        "weight": 10,
        "canonical": "/VERYSILENT",
    },
    "/quiet": {
        "kind": "silent",
        "weight": 9,
        "canonical": "/quiet",
    },
    "--quiet": {
        "kind": "silent",
        "weight": 9,
        "canonical": "--quiet",
    },
    "/qn": {
        "kind": "silent",
        "weight": 10,
        "canonical": "/qn",
    },
    "/passive": {
        "kind": "passive",
        "weight": 5,
        "canonical": "/passive",
    },
    "/s": {
        "kind": "silent_ambiguous",
        "weight": 3,
        "canonical": "/S",
    },
    "-s": {
        "kind": "silent_ambiguous",
        "weight": 2,
        "canonical": "-s",
    },
    "/norestart": {
        "kind": "restart",
        "weight": 7,
        "canonical": "/norestart",
    },
    "/noreboot": {
        "kind": "restart",
        "weight": 7,
        "canonical": "/noreboot",
    },
    "/suppressmsgboxes": {
        "kind": "ui",
        "weight": 7,
        "canonical": "/SUPPRESSMSGBOXES",
    },
    "/exenoui": {
        "kind": "ui",
        "weight": 6,
        "canonical": "/exenoui",
    },
    "/install": {
        "kind": "action",
        "weight": 3,
        "canonical": "/install",
    },
    "--install": {
        "kind": "action",
        "weight": 3,
        "canonical": "--install",
    },
}

HELP_CONTEXT_MARKERS = (
    "usage",
    "command line",
    "command-line",
    "commandline",
    "options",
    "arguments",
    "switches",
    "silent",
    "quiet",
    "unattended",
    "unattend",
    "norestart",
    "noreboot",
    "install",
    "setup",
)


def normalize_rule_key(value: str) -> str:
    value = (value or "").lower().strip()
    value = re.sub(r"[^a-z0-9äöüß]+", "_", value)
    return value.strip("_")


def learned_rule_identity(
    path: Path,
    metadata: dict[str, Any],
) -> tuple[str, str]:
    """
    Stable Produktidentität:
    Company + Product bevorzugt, sonst OriginalFilename, sonst Dateiname.
    """
    company = _clean_pe_text(metadata.get("CompanyName", ""))
    product = _clean_pe_text(metadata.get("ProductName", ""))
    original = _clean_pe_text(metadata.get("OriginalFilename", ""))

    if company and product:
        label = f"{company} | {product}"
        key = normalize_rule_key(f"{company}__{product}")
        return key, label

    if product:
        label = product
        key = normalize_rule_key(product)
        return key, label

    if original:
        label = original
        key = normalize_rule_key(original)
        return key, label

    label = path.name
    key = normalize_rule_key(path.name)
    return key, label


def load_installer_rules(project: Path) -> dict[str, Any]:
    ensure_initialized(project, quiet=True)
    p = project_paths(project)

    if not p["installer_rules"].exists():
        return {"installer_rules": {}}

    data = load_yaml(p["installer_rules"])
    if not isinstance(data, dict):
        return {"installer_rules": {}}

    rules = data.get("installer_rules")
    if not isinstance(rules, dict):
        data["installer_rules"] = {}

    return data


def save_installer_rules(project: Path, data: dict[str, Any]) -> None:
    p = project_paths(project)
    p["installer_rules"].parent.mkdir(parents=True, exist_ok=True)
    atomic_write_yaml(p["installer_rules"], data)


def find_learned_installer_rule(
    project: Path,
    path: Path,
    metadata: dict[str, Any],
) -> tuple[str, dict[str, Any]] | None:
    data = load_installer_rules(project)
    rules = data.get("installer_rules", {})

    rule_key, _ = learned_rule_identity(path, metadata)
    rule = rules.get(rule_key)

    if isinstance(rule, dict):
        return rule_key, rule

    return None


def remember_installer_rule(
    project: Path,
    path: Path,
    analysis: dict[str, Any],
    *,
    arguments: str,
    context: str,
    creates_path: str,
) -> tuple[str, str]:
    metadata = analysis.get("metadata", {}) or {}
    key, label = learned_rule_identity(path, metadata)

    data = load_installer_rules(project)
    rules = data.setdefault("installer_rules", {})

    rules[key] = {
        "label": label,
        "company": metadata.get("CompanyName", ""),
        "product": metadata.get("ProductName", ""),
        "original_filename": metadata.get("OriginalFilename", ""),
        "arguments": arguments,
        "context": context,
        "creates_path": creates_path,
        "source": "user_confirmed",
    }

    save_installer_rules(project, data)
    return key, label



def _ascii_readability(value: str) -> float:
    """
    Anteil normal lesbarer ASCII-Zeichen.
    Binär-/Mojibake-Strings wie 'ñëäõ.../qn...' sollen durchfallen.
    """
    if not value:
        return 0.0

    allowed = 0
    total = 0

    for ch in value:
        if ch in "\r\n\t":
            allowed += 1
            total += 1
            continue

        total += 1

        code = ord(ch)
        if 32 <= code <= 126:
            allowed += 1

    return allowed / max(total, 1)


def _word_quality(value: str) -> dict[str, Any]:
    """
    Prüft, ob ein String nach menschlich lesbarem CLI-/Hilfetext aussieht.
    """
    value = value.strip()
    lower = value.lower()

    ascii_ratio = _ascii_readability(value)
    words = re.findall(r"[a-zA-Z]{3,}", value)
    help_hits = [
        marker
        for marker in HELP_CONTEXT_MARKERS
        if marker in lower
    ]

    # Typische CLI-Erklärungen.
    semantic_hits = [
        marker
        for marker in (
            "silent",
            "quiet",
            "install",
            "installation",
            "setup",
            "option",
            "usage",
            "argument",
            "switch",
            "reboot",
            "restart",
            "unattended",
            "msiexec",
            "windows installer",
            "user interface",
            "no ui",
            "without ui",
        )
        if marker in lower
    ]

    # Muss fast komplett lesbar sein. Unicode-Müll aus zufälligem UTF-16
    # wird dadurch nicht als CLI-Hilfe akzeptiert.
    human_readable = (
        ascii_ratio >= 0.92
        and (
            len(words) >= 2
            or len(help_hits) >= 1
            or len(semantic_hits) >= 1
        )
    )

    return {
        "ascii_ratio": round(ascii_ratio, 3),
        "word_count": len(words),
        "help_hits": help_hits,
        "semantic_hits": semantic_hits,
        "human_readable": human_readable,
    }


def _embedded_cli_records_from_binary(
    sample: bytes,
) -> list[dict[str, Any]]:
    """
    Extrahiert tatsächliche ASCII-/UTF-16LE-Strings aus der Binärdatei,
    statt die gesamte EXE blind als Text zu decodieren.
    """
    strings = _printable_pe_strings(sample)
    records: list[dict[str, Any]] = []

    for idx, (offset, value) in enumerate(strings):
        current = _clean_pe_text(value)
        if not current:
            continue

        # Nachbarstrings helfen bei Ressourcen wie:
        #   "/silent"
        #   "Perform silent installation"
        neighbours: list[str] = []

        for neighbour_idx in (idx - 1, idx, idx + 1):
            if 0 <= neighbour_idx < len(strings):
                neighbour_offset, neighbour_value = strings[neighbour_idx]

                # Nur nahe beieinanderliegende Resource-/Stringdaten verbinden.
                if abs(neighbour_offset - offset) <= 2048:
                    cleaned = _clean_pe_text(neighbour_value)
                    if cleaned:
                        neighbours.append(cleaned)

        context = " | ".join(dict.fromkeys(neighbours))
        quality = _word_quality(context)

        records.append({
            "offset": offset,
            "value": current,
            "context": context[:600],
            "quality": quality,
        })

    return records


def _switch_context_is_plausible(
    switch: str,
    context: str,
    quality: dict[str, Any],
) -> tuple[bool, str, int]:
    """
    Sicherheits-Gate vor dem Scoring.
    """
    lower = context.lower()
    switch_lower = switch.lower()

    if not quality.get("human_readable"):
        return (
            False,
            "verworfen: Kontext sieht nach Binär-/Mojibake-Daten aus",
            -100,
        )

    semantic = set(quality.get("semantic_hits", []))
    help_hits = set(quality.get("help_hits", []))

    # /qn ist ein MSI-UI-Schalter. Bei einer beliebigen EXE nur akzeptieren,
    # wenn der Kontext klar MSI/Windows Installer/quiet-install beschreibt.
    if switch_lower == "/qn":
        if not any(
            marker in lower
            for marker in (
                "msiexec",
                "windows installer",
                " msi",
                "msi ",
                "quiet",
                "silent",
                "no ui",
                "user interface",
            )
        ):
            return (
                False,
                "verworfen: /qn ohne MSI-/Quiet-/UI-Kontext",
                -30,
            )
        return True, "plausibel: /qn mit MSI-/Quiet-Kontext", 2

    # /S und -s sind extrem mehrdeutig. Nur bei Help-/Silent-Kontext.
    if switch_lower in {"/s", "-s"}:
        if not any(
            marker in lower
            for marker in (
                "silent",
                "quiet",
                "unattended",
                "usage",
                "options",
                "command line",
                "switch",
            )
        ):
            return (
                False,
                "verworfen: /S bzw. -s ohne Silent-/Help-Kontext",
                -30,
            )
        return True, "plausibel: /S mit Silent-/Help-Kontext", 0

    # Restart-Schalter alleine sagen noch nichts über Silent-Installation,
    # dürfen aber als Zusatzkandidat erkannt werden.
    if switch_lower in {"/norestart", "/noreboot"}:
        if not any(
            marker in lower
            for marker in (
                "restart",
                "reboot",
                "install",
                "setup",
                "option",
                "usage",
            )
        ):
            return (
                False,
                "verworfen: Neustart-Schalter ohne CLI-/Installationskontext",
                -20,
            )

    # Starke Silent-Schalter brauchen wenigstens lesbaren Kontext.
    if switch_lower in {
        "/silent",
        "--silent",
        "/verysilent",
        "/quiet",
        "--quiet",
        "/passive",
        "/suppressmsgboxes",
        "/exenoui",
    }:
        if not (
            semantic
            or help_hits
            or any(
                marker in lower
                for marker in (
                    "silent",
                    "quiet",
                    "install",
                    "setup",
                )
            )
        ):
            return (
                False,
                "verworfen: Silent-Schalter ohne semantischen CLI-Kontext",
                -20,
            )

    return True, "plausibler lesbarer CLI-Kontext", 0


def _extract_switch_occurrences_from_binary(
    sample: bytes,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Liefert akzeptierte UND verworfene Kandidaten.
    """
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    for record in _embedded_cli_records_from_binary(sample):
        value = str(record["value"])
        context = str(record["context"])
        context_lower = context.lower()
        quality = record["quality"]

        for switch, definition in SILENT_SWITCH_DEFINITIONS.items():
            pattern = (
                r"(?<![a-z0-9])"
                + re.escape(switch)
                + r"(?![a-z0-9])"
            )

            if not (
                re.search(pattern, value, re.IGNORECASE)
                or re.search(pattern, context, re.IGNORECASE)
            ):
                continue

            plausible, evidence, evidence_bonus = _switch_context_is_plausible(
                switch,
                context,
                quality,
            )

            base_score = int(definition["weight"])

            context_hits = [
                marker
                for marker in HELP_CONTEXT_MARKERS
                if marker in context_lower
            ]
            context_bonus = min(8, 2 + len(context_hits)) if context_hits else 0

            direct_help_bonus = 0
            if any(
                marker in context_lower
                for marker in (
                    "usage:",
                    "options:",
                    "command line",
                    "silent install",
                    "quiet install",
                    "perform silent",
                    "installs silently",
                )
            ):
                direct_help_bonus = 5

            score = (
                base_score
                + context_bonus
                + direct_help_bonus
                + evidence_bonus
            )

            item = {
                "switch": switch,
                "canonical": definition["canonical"],
                "kind": definition["kind"],
                "score": score,
                "offset": record["offset"],
                "context": context[:300],
                "ascii_ratio": quality.get("ascii_ratio"),
                "word_count": quality.get("word_count"),
                "evidence": evidence,
            }

            if plausible:
                accepted.append(item)
            else:
                rejected.append(item)

    return accepted, rejected



def _extract_switch_occurrences(text_data: str) -> list[dict[str, Any]]:
    """
    Findet CLI-Schalter nur statisch in eingebetteten Strings.
    Die EXE wird NICHT ausgeführt.
    """
    occurrences: list[dict[str, Any]] = []

    # Zeilen begrenzen, damit sehr lange Binär-Decodes nicht wild korrelieren.
    lines = text_data.splitlines()

    for line_no, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue

        line_lower = line.lower()
        if len(line_lower) > 3000:
            line_lower = line_lower[:3000]

        context_bonus = 0
        context_hits = [
            marker for marker in HELP_CONTEXT_MARKERS
            if marker in line_lower
        ]
        if context_hits:
            context_bonus = min(8, 2 + len(context_hits))

        for switch, definition in SILENT_SWITCH_DEFINITIONS.items():
            # /S ist extrem häufig als Zufall in Pfaden/Strings.
            # Deshalb nur als eigenständiges Token werten.
            pattern = (
                r"(?<![a-z0-9])"
                + re.escape(switch)
                + r"(?![a-z0-9])"
            )

            if not re.search(pattern, line_lower, re.IGNORECASE):
                continue

            score = int(definition["weight"]) + context_bonus

            # Extra Bonus wenn die Zeile direkt nach Hilfe aussieht.
            if any(
                marker in line_lower
                for marker in (
                    "usage:",
                    "options:",
                    "command line",
                    "silent install",
                    "quiet install",
                )
            ):
                score += 5

            occurrences.append({
                "switch": switch,
                "canonical": definition["canonical"],
                "kind": definition["kind"],
                "score": score,
                "line_no": line_no,
                "context": line[:240],
            })

    return occurrences


def _dedupe_switch_candidates(
    occurrences: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}

    for item in occurrences:
        canonical = str(item["canonical"]).lower()
        current = best.get(canonical)

        if current is None or item["score"] > current["score"]:
            best[canonical] = item

    return sorted(
        best.values(),
        key=lambda item: (-int(item["score"]), str(item["canonical"]).lower()),
    )



def infer_silent_arguments_from_binary(
    sample: bytes,
    *,
    engine: str = "unbekannt",
) -> dict[str, Any]:
    """
    Statische Silent-Erkennung direkt aus echten eingebetteten Strings.
    Die komplette EXE wird NICHT als Text interpretiert.
    """
    occurrences, rejected = _extract_switch_occurrences_from_binary(sample)
    candidates = _dedupe_switch_candidates(occurrences)

    engine_lower = engine.lower()

    if "inno setup" in engine_lower:
        return {
            "arguments": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "rejected_candidates": rejected[:12],
            "reason": "Inno Setup erkannt.",
        }

    if "nsis" in engine_lower or "nullsoft" in engine_lower:
        return {
            "arguments": "/S",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "rejected_candidates": rejected[:12],
            "reason": "NSIS/Nullsoft erkannt.",
        }

    if "wix burn" in engine_lower:
        return {
            "arguments": "/quiet /norestart",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "rejected_candidates": rejected[:12],
            "reason": "WiX Burn erkannt.",
        }

    silent = [
        x
        for x in candidates
        if x["kind"] in {"silent", "silent_ambiguous"}
    ]
    restart = [
        x
        for x in candidates
        if x["kind"] == "restart"
    ]
    ui = [
        x
        for x in candidates
        if x["kind"] == "ui"
    ]

    strong_silent = [
        x
        for x in silent
        if int(x["score"]) >= 13
    ]
    medium_silent = [
        x
        for x in silent
        if int(x["score"]) >= 10
    ]

    chosen: list[str] = []
    confidence = "niedrig"
    reason = (
        "Keine belastbare Silent-Kombination in lesbaren "
        "CLI-/Help-Strings erkannt."
    )

    if strong_silent:
        best = strong_silent[0]

        # /qn und /S bleiben selbst bei gutem Kontext vorsichtiger,
        # solange keine passende Engine erkannt wurde.
        if str(best["canonical"]).lower() not in {"/qn", "/s", "-s"}:
            chosen.append(str(best["canonical"]))

            strong_restart = [
                x for x in restart
                if int(x["score"]) >= 10
            ]
            if strong_restart:
                chosen.append(
                    str(strong_restart[0]["canonical"])
                )

            strong_ui = [
                x for x in ui
                if int(x["score"]) >= 11
            ]
            if strong_ui:
                chosen.append(str(strong_ui[0]["canonical"]))

            confidence = "hoch"
            reason = (
                "Starke, lesbare eingebettete CLI-/Help-Strings erkannt."
            )

        elif str(best["canonical"]).lower() == "/qn":
            # /qn ohne erkannte MSI-Wrapper-Engine niemals automatisch
            # als EXE-Argument setzen.
            confidence = "niedrig"
            reason = (
                "/qn wurde in lesbarem Kontext gefunden, aber ohne "
                "erkannte MSI-/Wrapper-Engine nicht automatisch verwendet."
            )

        else:
            confidence = "niedrig"
            reason = (
                "/S bzw. -s ist ohne erkannte Installer-Engine zu mehrdeutig "
                "und wird nicht automatisch verwendet."
            )

    elif medium_silent:
        best = medium_silent[0]

        if str(best["canonical"]).lower() not in {"/qn", "/s", "-s"}:
            chosen.append(str(best["canonical"]))

            medium_restart = [
                x
                for x in restart
                if int(x["score"]) >= 9
            ]
            if medium_restart:
                chosen.append(
                    str(medium_restart[0]["canonical"])
                )

            confidence = "mittel"
            reason = (
                "Plausible, lesbare CLI-Strings erkannt, "
                "aber keine eindeutige Installer-Engine."
            )

    return {
        "arguments": " ".join(dict.fromkeys(chosen)),
        "confidence": confidence,
        "method": "embedded_cli_strings",
        "source_label": "EINGEBETTETE CLI-STRINGS",
        "candidates": candidates[:12],
        "rejected_candidates": rejected[:12],
        "reason": reason,
    }



def infer_silent_arguments_from_strings(
    text_data: str,
    *,
    engine: str = "unbekannt",
) -> dict[str, Any]:
    """
    Liefert Vorschlag + Evidenz + Konfidenz.
    Nichts wird ausgeführt.
    """
    occurrences = _extract_switch_occurrences(text_data)
    candidates = _dedupe_switch_candidates(occurrences)

    # Engine-spezifische sichere Regeln zuerst.
    engine_lower = engine.lower()

    if "inno setup" in engine_lower:
        return {
            "arguments": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "reason": "Inno Setup erkannt.",
        }

    if "nsis" in engine_lower or "nullsoft" in engine_lower:
        return {
            "arguments": "/S",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "reason": "NSIS/Nullsoft erkannt.",
        }

    if "wix burn" in engine_lower:
        return {
            "arguments": "/quiet /norestart",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "reason": "WiX Burn erkannt.",
        }

    # Statischer Kandidaten-Score.
    silent = [
        x for x in candidates
        if x["kind"] in {"silent", "silent_ambiguous"}
    ]
    restart = [
        x for x in candidates
        if x["kind"] == "restart"
    ]
    ui = [
        x for x in candidates
        if x["kind"] == "ui"
    ]

    # Nur starke Kandidaten automatisch kombinieren.
    strong_silent = [x for x in silent if int(x["score"]) >= 11]
    medium_silent = [x for x in silent if int(x["score"]) >= 8]

    chosen: list[str] = []
    confidence = "niedrig"
    reason = "Keine belastbare Silent-Kombination erkannt."

    if strong_silent:
        chosen.append(str(strong_silent[0]["canonical"]))

        strong_restart = [
            x for x in restart if int(x["score"]) >= 9
        ]
        if strong_restart:
            chosen.append(str(strong_restart[0]["canonical"]))

        strong_ui = [
            x for x in ui if int(x["score"]) >= 10
        ]
        if strong_ui:
            chosen.append(str(strong_ui[0]["canonical"]))

        confidence = "hoch"
        reason = (
            "Starke eingebettete CLI-/Help-Strings mit Silent-Schalter erkannt."
        )

    elif medium_silent:
        # /S alleine ist zu mehrdeutig.
        best = medium_silent[0]
        if str(best["canonical"]).lower() not in {"/s", "-s"}:
            chosen.append(str(best["canonical"]))

            medium_restart = [
                x for x in restart if int(x["score"]) >= 7
            ]
            if medium_restart:
                chosen.append(str(medium_restart[0]["canonical"]))

            confidence = "mittel"
            reason = (
                "Plausible eingebettete CLI-Strings erkannt, "
                "aber keine eindeutige Installer-Engine."
            )

    return {
        "arguments": " ".join(dict.fromkeys(chosen)),
        "confidence": confidence,
        "method": "embedded_cli_strings",
        "source_label": "EINGEBETTETE CLI-STRINGS",
        "candidates": candidates[:12],
        "reason": reason,
    }


def print_silent_detection(analysis: dict[str, Any]) -> None:
    detection = analysis.get("silent_detection") or {}
    candidates = detection.get("candidates") or []
    rejected = detection.get("rejected_candidates") or []

    if not detection:
        print()
        print("Silent-Erkennung")
        print("================")
        print("Quelle:      KEINE")
        print("Ergebnis:    kein belastbarer Silent-Parameter")
        return

    method = str(detection.get("method", "unbekannt"))
    source_label = str(
        detection.get("source_label")
        or {
            "known_product_rule": "FESTE PRODUKTREGEL",
            "learned_product_rule": "GELERNTE REGEL",
            "installer_engine": "INSTALLER-ENGINE",
            "embedded_cli_strings": "EINGEBETTETE CLI-STRINGS",
        }.get(method, method.upper())
    )

    print()
    print("Silent-Erkennung")
    print("================")
    print(f"Quelle:      {source_label}")
    print(f"Technisch:   {method}")
    print(
        f"Ergebnis:    "
        f"{detection.get('arguments') or analysis.get('arguments') or '(keins)'}"
    )
    print(
        f"Konfidenz:   "
        f"{detection.get('confidence', analysis.get('confidence', 'niedrig'))}"
    )

    reason = detection.get("reason")
    if reason:
        print(f"Bewertung:   {reason}")

    if candidates:
        print()
        print("Akzeptierte CLI-Kandidaten")
        print("--------------------------")

        for item in candidates[:10]:
            print(
                f"  {item.get('canonical', '?'):<18} "
                f"Score {item.get('score', '?')}  "
                f"ASCII {item.get('ascii_ratio', '?')}"
            )
            if item.get("evidence"):
                print(f"      Evidenz: {item['evidence']}")
            context = str(item.get("context", "")).strip()
            if context:
                print(f"      Kontext: {context[:180]}")

    if rejected:
        print()
        print("Verworfene Treffer")
        print("------------------")

        for item in rejected[:8]:
            print(
                f"  {item.get('canonical', '?'):<18} "
                f"{item.get('evidence', 'verworfen')}"
            )
            context = str(item.get("context", "")).strip()
            if context:
                print(f"      Kontext: {context[:160]}")



def cmd_rules_list(args: argparse.Namespace) -> None:
    data = load_installer_rules(args.project)
    rules = data.get("installer_rules", {})

    print()
    print("GELERNTE INSTALLER-REGELN")
    print("=========================")

    if not rules:
        print("Noch keine lokalen Regeln gespeichert.")
        return

    for idx, (key, rule) in enumerate(
        sorted(rules.items()),
        start=1,
    ):
        print(
            f"{idx:>3}) {rule.get('label', key)}"
            f"  [{rule.get('arguments', '')}]"
        )


def cmd_rules_remove(args: argparse.Namespace) -> None:
    data = load_installer_rules(args.project)
    rules = data.get("installer_rules", {})

    if not rules:
        print("Keine lokalen Installer-Regeln vorhanden.")
        return

    key = args.key

    if not key and sys.stdin.isatty():
        key = select_from_list(
            "Gelernte Regel entfernen",
            [
                (rule_key, str(rule.get("label", rule_key)))
                for rule_key, rule in sorted(rules.items())
            ],
        )

    if key not in rules:
        die(f"Installer-Regel '{key}' nicht gefunden.")

    label = str(rules[key].get("label", key))

    if not getattr(args, "yes", False):
        if not yes_no(
            f"Gelernte Regel '{label}' wirklich entfernen?",
            False,
        ):
            print("Abgebrochen.")
            return

    del rules[key]
    save_installer_rules(args.project, data)
    print(f"✓ Gelernte Installer-Regel '{label}' entfernt.")



PE_VERSION_KEYS = (
    "CompanyName",
    "ProductName",
    "FileDescription",
    "ProductVersion",
    "FileVersion",
    "OriginalFilename",
    "InternalName",
    "LegalCopyright",
)


def _clean_pe_text(value: Any) -> str:
    if isinstance(value, bytes):
        for encoding in ("utf-8", "utf-16le", "latin-1"):
            try:
                value = value.decode(encoding, errors="ignore")
                break
            except Exception:
                continue

    value = str(value or "")
    value = value.replace("\x00", "").strip()
    value = re.sub(r"\s+", " ", value)
    return value


def _pe_architecture_from_bytes(data: bytes) -> str:
    """
    Liest nur DOS/PE-Header. Keine Ausführung der EXE.
    """
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return ""

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 6 > len(data):
            return ""

        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return ""

        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        return {
            0x014C: "x86",
            0x8664: "x64",
            0xAA64: "arm64",
        }.get(machine, f"0x{machine:04x}")
    except (struct.error, IndexError):
        return ""


def _printable_pe_strings(data: bytes) -> list[tuple[int, str]]:
    """
    Extrahiert ASCII- und UTF-16LE-Strings inklusive Position.
    Das dient als Fallback, wenn python-pefile nicht installiert ist.
    """
    found: list[tuple[int, str]] = []

    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){3,}", data):
        try:
            value = match.group(0).decode("utf-16le", errors="ignore").strip()
        except Exception:
            continue
        if value:
            found.append((match.start(), value))

    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        try:
            value = match.group(0).decode("latin-1", errors="ignore").strip()
        except Exception:
            continue
        if value:
            found.append((match.start(), value))

    found.sort(key=lambda item: item[0])
    return found


def _versioninfo_from_strings(data: bytes) -> dict[str, str]:
    """
    Windows VERSIONINFO besteht häufig aus UTF-16LE-Schlüsseln wie
    CompanyName/ProductName und dem direkt folgenden Wert.
    """
    strings = _printable_pe_strings(data)
    result: dict[str, str] = {}
    key_lookup = {key.lower(): key for key in PE_VERSION_KEYS}
    ignored_values = {
        "StringFileInfo",
        "VarFileInfo",
        "Translation",
        "VS_VERSION_INFO",
    }

    for idx, (offset, value) in enumerate(strings):
        canonical = key_lookup.get(value.lower())
        if not canonical or canonical in result:
            continue

        # Der Wert folgt im VERSIONINFO normalerweise kurz nach dem Schlüssel.
        for next_offset, candidate in strings[idx + 1: idx + 8]:
            if next_offset - offset > 2048:
                break

            candidate = _clean_pe_text(candidate)
            if not candidate:
                continue

            if candidate in ignored_values:
                continue

            if candidate.lower() in key_lookup:
                break

            # Binärrauschen und offensichtliche Struktur-Strings ignorieren.
            if len(candidate) > 300:
                continue
            if candidate.count("\\") > 8:
                continue

            result[canonical] = candidate
            break

    return result


def _versioninfo_with_pefile(path: Path) -> dict[str, str]:
    if pefile is None:
        return {}

    result: dict[str, str] = {}

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
            ]
        )

        for block in getattr(pe, "FileInfo", []) or []:
            # pefile kann FileInfo als verschachtelte Listen liefern.
            entries = block if isinstance(block, list) else [block]

            for entry in entries:
                key = _clean_pe_text(getattr(entry, "Key", ""))

                if key != "StringFileInfo":
                    continue

                for table in getattr(entry, "StringTable", []) or []:
                    for raw_key, raw_value in (
                        getattr(table, "entries", {}) or {}
                    ).items():
                        k = _clean_pe_text(raw_key)
                        v = _clean_pe_text(raw_value)
                        if k in PE_VERSION_KEYS and v:
                            result[k] = v

        try:
            pe.close()
        except Exception:
            pass

    except Exception:
        return {}

    return result


def inspect_pe_metadata(path: Path, sample: bytes | None = None) -> dict[str, Any]:
    """
    Deep-Scan einer Windows-EXE, ohne sie auszuführen.

    Reihenfolge:
      1. PE-Header / Architektur
      2. python-pefile, falls vorhanden
      3. eigener VERSIONINFO-String-Fallback
      4. optional Authenticode-Info über osslsigncode, falls installiert
    """
    metadata: dict[str, Any] = {}
    sources: list[str] = []

    try:
        if sample is None:
            sample = read_binary_sample(path)
    except OSError:
        sample = b""

    arch = _pe_architecture_from_bytes(sample or b"")
    if arch:
        metadata["PEArchitecture"] = arch
        sources.append("PE-Header")

    precise = _versioninfo_with_pefile(path)
    if precise:
        metadata.update(precise)
        sources.append("PE-VersionInfo (pefile)")

    fallback = _versioninfo_from_strings(sample or b"")
    for key, value in fallback.items():
        metadata.setdefault(key, value)
    if fallback:
        sources.append("PE-VersionInfo (String-Fallback)")

    # Optional: Signaturinformationen lesen, wenn osslsigncode vorhanden ist.
    # Fehlt das Tool, funktioniert der Scanner trotzdem vollständig weiter.
    osslsigncode = shutil.which("osslsigncode")
    if osslsigncode:
        try:
            proc = subprocess.run(
                [osslsigncode, "verify", "-in", str(path)],
                capture_output=True,
                text=True,
                timeout=20,
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")

            subject_patterns = [
                r"Subject:\s*(.+)",
                r"Signer Certificate:\s*\n\s*Subject:\s*(.+)",
            ]
            for pattern in subject_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    subject = _clean_pe_text(match.group(1))
                    if subject:
                        metadata["SignatureSubject"] = subject
                        sources.append("Authenticode (osslsigncode)")
                        break
        except (OSError, subprocess.TimeoutExpired):
            pass

    if sources:
        metadata["ScanSources"] = list(dict.fromkeys(sources))

    return metadata


def _metadata_blob(path: Path, metadata: dict[str, Any]) -> str:
    values = [str(path)]
    for key in (
        "CompanyName",
        "ProductName",
        "FileDescription",
        "OriginalFilename",
        "InternalName",
        "SignatureSubject",
    ):
        value = metadata.get(key)
        if value:
            values.append(str(value))
    return "\n".join(values).lower()


def _citrix_detection_path(metadata: dict[str, Any]) -> str:
    """
    Native x64 Citrix Workspace landet systemweit unter Program Files.
    Für x86 verwenden wir Program Files (x86).
    """
    arch = str(metadata.get("PEArchitecture", "")).lower()

    if arch == "x64":
        return (
            r"C:\Program Files\Citrix\ICA Client"
            r"\SelfServicePlugin\SelfService.exe"
        )

    return (
        r"C:\Program Files (x86)\Citrix\ICA Client"
        r"\Receiver\receiver.exe"
    )


def _apply_known_exe_product_rule(
    path: Path,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> bool:
    """
    Produktregeln verwenden Dateiname UND PE-Metadaten.
    Rückgabe True bedeutet: sichere bekannte Regel, Analyse ist fertig.
    """
    blob = _metadata_blob(path, metadata)

    # PASCOM
    if "pascom" in blob:
        result.update(
            type="exe",
            engine="PASCOM Windows App",
            arguments="/S",
            context="user_interactive",
            confidence="hoch",
            admin_requirement="nein",
            name_guess=metadata.get("ProductName") or "PASCOM",
            note=(
                "Bekannte PASCOM-Regel. Für den normalen Client wird der "
                "nicht erhöhte Benutzerkontext verwendet."
            ),
        )
        result["reasons"].extend([
            "PASCOM über Dateiname oder PE-Metadaten erkannt.",
            "Bekannte Mavi-Regel: Silent-Schalter /S.",
            "Bekannte Mavi-Regel: interaktive Installation im angemeldeten Benutzerkontext.",
        ])
        return True

    # FortiClient
    if "forticlient" in blob or "fortivpn" in blob:
        result.update(
            type="exe",
            engine="FortiClient VPN",
            arguments="/quiet /norestart",
            context="machine",
            confidence="hoch",
            admin_requirement="ja",
            name_guess=metadata.get("ProductName") or "FortiClient VPN",
            note=(
                "FortiClient über Dateiname oder PE-Metadaten erkannt. "
                "Systemweite Installation wird als Machine/Admin behandelt."
            ),
        )
        result["reasons"].extend([
            "FortiClient/FortiVPN über Dateiname oder PE-Metadaten erkannt.",
            "Bekannte Mavi-Regel: /quiet /norestart.",
            "Systemweite VPN-Client-Installation.",
        ])
        return True

    # Citrix Workspace
    citrix_workspace = (
        "citrixworkspaceapp" in blob.replace(" ", "")
        or (
            "citrix" in blob
            and (
                "workspace" in blob
                or "receiver" in blob
            )
        )
    )

    if citrix_workspace:
        detection_path = _citrix_detection_path(metadata)
        result.update(
            type="exe",
            engine="Citrix Workspace",
            arguments="/silent /noreboot",
            context="machine",
            confidence="hoch",
            admin_requirement="ja",
            name_guess=metadata.get("ProductName") or "Citrix Workspace",
            creates_path=detection_path,
            note=(
                "Citrix Workspace über Dateiname/PE-Metadaten erkannt. "
                "Für Mavi wird die systemweite unbeaufsichtigte Installation verwendet."
            ),
        )
        result["metadata"]["DetectedProduct"] = "Citrix Workspace"
        result["reasons"].extend([
            "Citrix Workspace über Dateiname oder PE-VersionInfo erkannt.",
            "Silent-Installation: /silent /noreboot.",
            "Mavi-Provisioner: systemweit als Machine/Admin.",
            f"Detection-Datei: {detection_path}",
        ])
        return True

    return False




def analyze_installer(
    path: Path,
    project: Path | None = None,
    *,
    use_known_rules: bool = True,
    use_learned_rules: bool = False,
) -> dict[str, Any]:
    """
    v0.8: bewusst KEIN Deep-Scan mehr.

    Es werden nur noch:
      - Dateityp MSI/EXE,
      - feste, im Skript hinterlegte Produktregeln
    verwendet.

    Unbekannte EXE-Parameter werden immer vom Benutzer eingetragen.
    Keine Binary-String-Suche, keine Engine-Raterei, keine gelernten
    Regeln und keine automatische Silent-Erkennung.
    """
    ext = path.suffix.lower()

    result: dict[str, Any] = {
        "type": ext.lstrip("."),
        "engine": "unbekannt",
        "arguments": "",
        "context": "machine",
        "confidence": "manuell",
        "admin_requirement": "unbekannt",
        "name_guess": path.stem,
        "creates_path": "",
        "note": "",
        "reasons": [],
        "metadata": {},
    }

    if ext == ".msi":
        result.update(
            type="msi",
            engine="MSI / Windows Installer",
            arguments="",
            context="machine",
            confidence="fest",
            admin_requirement="wahrscheinlich",
            note=(
                "MSI erkannt. Kein Deep-Scan und keine Silent-Parameter-"
                "Raterei. Ansible win_package behandelt MSI direkt."
            ),
        )
        result["reasons"].append("Dateiendung .msi erkannt.")
        return result

    if ext != ".exe":
        result["note"] = (
            "Nur MSI und EXE werden für normale Software unterstützt."
        )
        return result

    result.update(
        type="exe",
        engine="EXE / manuelle Parameter",
        context="machine",
        confidence="manuell",
        note=(
            "Deep-Scan ist deaktiviert. Für unbekannte EXE-Dateien werden "
            "Silent-Parameter ausschließlich manuell eingetragen."
        ),
    )

    if use_known_rules and _apply_known_exe_product_rule(
        path,
        result,
        {},
    ):
        result["reasons"].append(
            "Parameter stammen ausschließlich aus einer festen "
            "Produktregel im Python-Skript."
        )
        return result

    result["reasons"].append(
        "Keine feste Produktregel gefunden. Parameter werden manuell gesetzt."
    )
    return result




def slugify(value: str) -> str:
    value = value.strip().lower()
    for a, b in {
        "ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
        "Ä": "ae", "Ö": "oe", "Ü": "ue",
    }.items():
        value = value.replace(a, b)
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_") or "software"


def prompt(text: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    value = input(f"{text}{suffix}: ").strip()
    if not value and default is not None:
        return default
    return value


def prompt_choice(text: str, choices: list[tuple[str, str]], default: str) -> str:
    print(text)
    for key, label in choices:
        mark = " (Standard)" if key == default else ""
        print(f"  {key}) {label}{mark}")
    valid = {k for k, _ in choices}
    while True:
        value = input("> ").strip() or default
        if value in valid:
            return value
        print("Ungültige Auswahl.")



def select_from_list(
    title: str,
    items: list[tuple[str, str]],
    *,
    default_key: str | None = None,
    allow_name: bool = True,
) -> str:
    """
    Nummerierte Auswahl. Akzeptiert optional weiterhin den Schlüssel/Namen.
    Enter übernimmt default_key, falls gesetzt.
    """
    if not items:
        die(f"Keine Einträge für '{title}' vorhanden.")

    keys = [key for key, _ in items]

    print()
    print(title)
    print("=" * len(title))

    for idx, (key, label) in enumerate(items, start=1):
        default_mark = "  [Standard]" if default_key == key else ""
        if label and label != key:
            print(f"  {idx}) {label}  ({key}){default_mark}")
        else:
            print(f"  {idx}) {key}{default_mark}")

    print()

    while True:
        suffix = ""
        if default_key is not None:
            try:
                default_index = keys.index(default_key) + 1
                suffix = f" [{default_index}]"
            except ValueError:
                suffix = ""

        value = input(f">{suffix} ").strip()

        if not value and default_key is not None:
            return default_key

        if value.isdigit():
            idx = int(value) - 1
            if 0 <= idx < len(items):
                return items[idx][0]
            print("Ungültige Nummer.")
            continue

        if allow_name:
            # Exakter Key
            for key, _ in items:
                if value.lower() == key.lower():
                    return key

            # Exaktes Label
            for key, label in items:
                if value.lower() == label.lower():
                    return key

        print("Bitte eine Nummer auswählen" + (" oder Namen eingeben." if allow_name else "."))


def choose_host_interactive(project: Path) -> str:
    inv = load_inventory(project)
    windows = ensure_windows_tree(inv)
    hosts = windows.get("hosts", {}) or {}

    if not hosts:
        die("Keine Windows-PCs im Inventory vorhanden.")

    items = []
    for host_name, data in hosts.items():
        data = data or {}
        ip = str(data.get("ansible_host", ""))
        connection = _connection_label(windows, data)
        label = f"{host_name}  [{ip}]  [{connection}]" if ip else f"{host_name}  [{connection}]"
        items.append((host_name, label))

    return select_from_list(
        "Ziel-PC auswählen",
        items,
        allow_name=True,
    )


def choose_software_interactive(
    project: Path,
    catalog_name: str,
) -> str:
    catalog = get_catalog(project, catalog_name)["software_catalog"]

    if not catalog:
        die(f"Katalog '{catalog_name}' ist leer.")

    items = []
    for key, app in catalog.items():
        name = str(app.get("name", key))
        typ = str(app.get("type", "?")).upper()
        context = str(app.get("context", "machine"))
        label = f"{name}  [{typ}, {context}]"
        items.append((key, label))

    return select_from_list(
        f"Programm aus '{catalog_name}' auswählen",
        items,
        allow_name=True,
    )


CTRL2_SENTINEL = "__Mavi_CTRL2__"


def _input_with_ctrl2(prompt_text: str = "> ") -> str:
    """
    Kleine TUI-Eingabe mit sofortigem Strg+2-Shortcut.

    Viele Linux-Terminals senden Strg+2 als NUL (0x00). In einem echten TTY
    lesen wir deshalb zeichenweise im cbreak-Modus. Auf nicht-interaktiven
    Eingaben fällt die Funktion sauber auf input() zurück. Zusätzlich kann
    jeder Aufrufer 'm' als gut sichtbaren Fallback anbieten.
    """
    if os.name != "posix" or not sys.stdin.isatty() or not sys.stdout.isatty():
        return input(prompt_text).strip()

    try:
        import termios
        import tty
    except ImportError:
        return input(prompt_text).strip()

    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except (termios.error, OSError):
        return input(prompt_text).strip()

    buffer = bytearray()
    sys.stdout.write(prompt_text)
    sys.stdout.flush()

    try:
        tty.setcbreak(fd)
        while True:
            raw = os.read(fd, 1)
            if not raw:
                sys.stdout.write("\n")
                return buffer.decode("utf-8", errors="replace").strip()

            # Strg+2 wird in den üblichen xterm/SSH-Terminals als NUL gesendet.
            if raw == b"\x00":
                sys.stdout.write("^2  → Mehrfachmodus\n")
                sys.stdout.flush()
                return CTRL2_SENTINEL

            if raw in {b"\r", b"\n"}:
                sys.stdout.write("\n")
                sys.stdout.flush()
                return buffer.decode("utf-8", errors="replace").strip()

            if raw in {b"\x7f", b"\x08"}:
                if buffer:
                    # Menüs erwarten überwiegend ASCII/Nummern; ein Byte reicht
                    # hier für den schnellen Rückschritt vollständig aus.
                    buffer.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue

            # Escape-Sequenzen (Pfeiltasten etc.) nicht als Menütext übernehmen.
            if raw == b"\x1b":
                continue

            buffer.extend(raw)
            try:
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
            except Exception:
                sys.stdout.write(raw.decode("utf-8", errors="ignore"))
                sys.stdout.flush()
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            pass


def _software_selection_rows(catalog: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        (str(key), raw_app if isinstance(raw_app, dict) else {})
        for key, raw_app in catalog.items()
    ]


def choose_software_single_with_multi_shortcut(
    project: Path,
    catalog_name: str,
    *,
    title: str | None = None,
) -> tuple[str | None, bool]:
    """Ein Programm wählen; Strg+2/M signalisiert Wechsel in Mehrfachmodus."""
    catalog = get_catalog(project, catalog_name)["software_catalog"]
    if not catalog:
        die(f"Katalog '{catalog_name}' ist leer.")

    rows = _software_selection_rows(catalog)
    heading = title or f"Programm aus '{catalog_name}' auswählen"

    while True:
        print()
        print(heading)
        print("=" * len(heading))
        for idx, (key, app) in enumerate(rows, start=1):
            meta = _software_mode_meta(app)
            name = str(app.get("name", key))
            typ = str(app.get("type", "?")).upper()
            print(f"  {idx:>2}) {name}  [{typ} | {meta['mode']}]  ({key})")
        print()
        print("  Strg+2  → MEHRFACHAUSWAHL / Programme markieren")
        print("  m       → dasselbe als Fallback")
        print()

        value = _input_with_ctrl2("> ").strip()
        if value == CTRL2_SENTINEL or value.lower() in {"m", "multi", "mehrfach"}:
            return None, True

        if value.isdigit():
            idx = int(value) - 1
            if 0 <= idx < len(rows):
                return rows[idx][0], False
            print("Ungültige Nummer.")
            continue

        for key, app in rows:
            name = str(app.get("name", key))
            if value.casefold() in {key.casefold(), name.casefold()}:
                return key, False

        print("Bitte Nummer, Schlüssel oder exakten Namen eingeben. Strg+2 = Mehrfachmodus.")


def choose_software_multi_interactive(
    project: Path,
    catalog_name: str,
    *,
    title: str = "PROGRAMME MARKIEREN",
) -> list[str]:
    """
    Checklisten-artige Mehrfachauswahl.

    Nummern/Bereiche toggeln die Markierung. Enter bestätigt die aktuelle
    Auswahl. Dadurch kann man z.B. nacheinander 2, 5 und 8-10 markieren.
    """
    catalog = get_catalog(project, catalog_name)["software_catalog"]
    if not catalog:
        die(f"Katalog '{catalog_name}' ist leer.")

    rows = _software_selection_rows(catalog)
    selected: set[int] = set()

    while True:
        print()
        print(title)
        print("=" * len(title))
        print(f"Katalog: {catalog_name} | Markiert: {len(selected)}")
        print()

        for idx, (key, app) in enumerate(rows, start=1):
            mark = "X" if idx in selected else " "
            meta = _software_mode_meta(app)
            name = str(app.get("name", key))
            typ = str(app.get("type", "?")).upper()
            print(f"  {idx:>2}) [{mark}] {name}  [{typ} | {meta['mode']}]  ({key})")

        print()
        print("Nummern toggeln:  1,3,5   |   2-6   |   1,4,7-10")
        print("a = alle markieren   c = leeren   Enter = Auswahl übernehmen   0 = abbrechen")
        print()

        raw = input("Markieren > ").strip()
        lowered = raw.casefold()

        if raw == "0":
            return []
        if not raw:
            if not selected:
                print("! Noch kein Programm markiert.")
                continue
            return [rows[idx - 1][0] for idx in sorted(selected)]
        if lowered in {"a", "alle", "all", "*"}:
            selected = set(range(1, len(rows) + 1))
            continue
        if lowered in {"c", "clear", "leer", "leeren"}:
            selected.clear()
            continue

        try:
            toggles = _parse_multi_program_selection(raw, len(rows))
        except ValueError as exc:
            print(f"! {exc}")
            continue

        for number in toggles:
            if number in selected:
                selected.remove(number)
            else:
                selected.add(number)


def choose_catalog_by_number(
    project: Path,
    *,
    default_name: str | None = None,
    title: str = "Katalog auswählen",
) -> str:
    names = list_catalog_names(project)

    if not names:
        die("Keine Kataloge vorhanden.")

    if default_name is None:
        default_name = get_default_catalog_name(project)

    items = []
    for name in names:
        label = name
        if name == get_default_catalog_name(project):
            label = f"{name} [DEFAULT]"
        items.append((name, label))

    return select_from_list(
        title,
        items,
        default_key=default_name if default_name in names else None,
        allow_name=True,
    )

def yes_no(text: str, default: bool = True) -> bool:
    suffix = "[J/n]" if default else "[j/N]"
    value = input(f"{text} {suffix} ").strip().lower()
    if not value:
        return default
    return value in {"j", "ja", "y", "yes"}


CATALOG_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SOFTWARE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def validate_catalog_name(name: str) -> str:
    name = str(name).strip()
    if not name:
        die("Katalogname darf nicht leer sein.")
    if not CATALOG_NAME_RE.fullmatch(name):
        die(
            "Ungültiger Katalogname. Erlaubt sind Buchstaben, Zahlen, "
            "Punkt, Bindestrich und Unterstrich."
        )
    return name


def validate_software_key(key: str) -> str:
    """Validate the shared software/Office/WinGet identifier namespace."""
    key = str(key or "").strip()
    if not SOFTWARE_KEY_RE.fullmatch(key) or key in {".", ".."}:
        die(
            "Ungültiger Software-Schlüssel. Er muss mit einer Zahl oder einem "
            "Buchstaben beginnen, darf höchstens 64 Zeichen lang sein und nur "
            "Buchstaben, Zahlen, Punkt, Bindestrich und Unterstrich enthalten."
        )
    return key


def validate_host_address(value: str) -> str:
    """Accept exactly one IPv4 address or a DNS FQDN, never an Ansible pattern."""
    value = str(value or "").strip().rstrip(".")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass

    if not value or len(value) > 253 or "." not in value:
        die("Zieladresse muss eine gültige IPv4-Adresse oder ein FQDN sein.")
    if re.fullmatch(r"[0-9.]+", value):
        die("Ungültige IPv4-Adresse.")
    labels = value.split(".")
    if any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    ):
        die("FQDN enthält ein ungültiges DNS-Label.")
    return value.lower()


def _validate_catalog_for_persistence(
    data: dict[str, Any],
    *,
    require_installer_integrity: bool = False,
) -> None:
    """Central fail-closed validation for every catalog writer and installer."""
    if not isinstance(data, dict):
        die("Katalog muss ein YAML-Objekt sein.")
    software_catalog = data.get("software_catalog", {})
    if not isinstance(software_catalog, dict):
        die("software_catalog muss ein YAML-Objekt sein.")

    for raw_key, raw_app in software_catalog.items():
        key = validate_software_key(str(raw_key))
        if not isinstance(raw_app, dict):
            die(f"Katalogeintrag '{key}' muss ein YAML-Objekt sein.")

        validate_installer_arguments(
            raw_app.get("arguments", ""),
            context=f"Katalogeintrag '{key}'",
        )

        app_type = str(raw_app.get("type", "") or "").strip().lower()
        if app_type not in {"msi", "exe", "office_odt", "winget"}:
            die(f"Katalogeintrag '{key}' hat einen ungültigen Typ: {app_type!r}.")

        if app_type == "winget":
            _winget_validate_identifier(raw_app.get("winget_id", ""))
            _winget_validate_source(raw_app.get("winget_source", "winget"))
            _winget_validate_version(raw_app.get("winget_version", ""))
            continue

        sha256 = str(raw_app.get("sha256", "") or "").strip().lower()
        unsafe_without_hash = raw_app.get("allow_unsafe_missing_sha256") is True
        if sha256 and not re.fullmatch(r"[0-9a-f]{64}", sha256):
            die(
                f"Katalogeintrag '{key}' enthält keinen gültigen SHA-256. "
                "Erwartet werden exakt 64 hexadezimale Zeichen."
            )
        if require_installer_integrity and not sha256 and not unsafe_without_hash:
            die(
                f"SICHERHEITSABBRUCH: Für den lokalen Installer '{key}' fehlt SHA-256. "
                "Den Eintrag erneut hinzufügen/bearbeiten und hashen. Nur für eine "
                "bewusste Legacy-Ausnahme darf allow_unsafe_missing_sha256: true "
                "direkt im Katalog gesetzt werden."
            )


def catalog_path(project: Path, catalog_name: str) -> Path:
    name = validate_catalog_name(catalog_name)
    return project_paths(project)["catalogs_dir"] / f"{name}.yml"


def list_catalog_names(project: Path) -> list[str]:
    ensure_initialized(project, quiet=True)
    directory = project_paths(project)["catalogs_dir"]
    return sorted(
        [p.stem for p in directory.glob("*.yml") if p.is_file()],
        key=str.lower,
    )


def get_default_catalog_name(project: Path) -> str:
    ensure_initialized(project, quiet=True)
    config = get_config(project)
    name = validate_catalog_name(str(config.get("default_catalog", "default")))
    path = catalog_path(project, name)

    # Sollte normalerweise bereits durch init existieren.
    if not path.exists():
        atomic_write_yaml(path, CATALOG_TEMPLATE)

    return name


def resolve_catalog_name(
    project: Path,
    requested: str | None = None,
    *,
    must_exist: bool = True,
) -> str:
    name = validate_catalog_name(requested) if requested else get_default_catalog_name(project)
    path = catalog_path(project, name)

    if must_exist and not path.exists():
        available = ", ".join(list_catalog_names(project)) or "(keine)"
        die(f"Katalog '{name}' existiert nicht. Vorhanden: {available}")

    return name


def choose_catalog_interactive(
    project: Path,
    requested: str | None = None,
    *,
    purpose: str = "verwenden",
    ask_other: bool = True,
) -> str:
    if requested:
        return resolve_catalog_name(project, requested)

    default_name = get_default_catalog_name(project)

    if not ask_other or not sys.stdin.isatty():
        return default_name

    print()
    print("Katalog")
    print("=======")
    print(f"Standardkatalog: {default_name}")

    if yes_no(f"Standardkatalog '{default_name}' {purpose}?", True):
        return default_name

    return choose_catalog_by_number(
        project,
        default_name=default_name,
        title="Anderen Katalog auswählen",
    )



def get_catalog(
    project: Path,
    catalog_name: str | None = None,
) -> dict[str, Any]:
    ensure_initialized(project, quiet=True)
    name = resolve_catalog_name(project, catalog_name)
    path = catalog_path(project, name)
    data = load_yaml(path, CATALOG_TEMPLATE)

    if "software_catalog" not in (data or {}):
        data = {"software_catalog": data or {}}

    return data


def save_catalog(
    project: Path,
    data: dict[str, Any],
    catalog_name: str | None = None,
) -> None:
    name = resolve_catalog_name(project, catalog_name)
    sanitized = sanitize_catalog_data(data)
    _validate_catalog_for_persistence(sanitized)
    atomic_write_yaml(catalog_path(project, name), sanitized)


def cmd_catalog_list(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    default_name = get_default_catalog_name(args.project)
    names = list_catalog_names(args.project)

    print(f"{'KATALOG':<30} {'PAKETE':>8}  STATUS")
    print("-" * 55)

    for name in names:
        count = len(get_catalog(args.project, name).get("software_catalog", {}))
        status = "DEFAULT" if name == default_name else ""
        print(f"{name:<30} {count:>8}  {status}")


def cmd_catalog_create(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    name = validate_catalog_name(args.name)
    dest = catalog_path(args.project, name)

    if dest.exists():
        die(f"Katalog '{name}' existiert bereits.")

    if args.copy_from:
        source_name = resolve_catalog_name(args.project, args.copy_from)
        source_data = get_catalog(args.project, source_name)
        atomic_write_yaml(dest, source_data)
        print(f"✓ Katalog '{name}' als Kopie von '{source_name}' erstellt.")
    else:
        atomic_write_yaml(dest, CATALOG_TEMPLATE)
        print(f"✓ Katalog '{name}' erstellt.")

    if args.set_default:
        ns = argparse.Namespace(project=args.project, name=name)
        cmd_catalog_set_default(ns)


def cmd_catalog_set_default(args: argparse.Namespace) -> None:
    name = resolve_catalog_name(args.project, args.name)
    config = get_config(args.project)
    config["default_catalog"] = name
    atomic_write_yaml(project_paths(args.project)["config"], config)
    print(f"✓ Standardkatalog ist jetzt '{name}'.")


def cmd_catalog_copy(args: argparse.Namespace) -> None:
    source_name = resolve_catalog_name(args.project, args.source)
    dest_name = validate_catalog_name(args.destination)
    dest_path = catalog_path(args.project, dest_name)

    if not dest_path.exists():
        if getattr(args, "create_destination", False):
            atomic_write_yaml(dest_path, CATALOG_TEMPLATE)
            print(f"✓ Zielkatalog '{dest_name}' wurde automatisch erstellt.")
        elif sys.stdin.isatty() and yes_no(
            f"Zielkatalog '{dest_name}' existiert nicht. Jetzt erstellen?",
            True,
        ):
            atomic_write_yaml(dest_path, CATALOG_TEMPLATE)
            print(f"✓ Zielkatalog '{dest_name}' erstellt.")
        else:
            die(
                f"Zielkatalog '{dest_name}' existiert nicht. "
                "Erst 'catalog create' verwenden oder --create-destination setzen."
            )

    source = get_catalog(args.project, source_name)
    dest = get_catalog(args.project, dest_name)
    source_sw = source["software_catalog"]
    dest_sw = dest["software_catalog"]

    keys = list(args.software or [])

    if args.all:
        keys = list(source_sw.keys())
    elif not keys:
        if not sys.stdin.isatty():
            die("Software-Schlüssel angeben oder --all verwenden.")

        print()
        print("Was soll kopiert werden?")
        print("  1) ALLE Programme (Standard)")
        print("  2) Ein einzelnes Programm")
        print()

        mode = input("> [1] ").strip() or "1"

        if mode == "1":
            keys = list(source_sw.keys())
        elif mode == "2":
            keys = [
                choose_software_interactive(
                    args.project,
                    source_name,
                )
            ]
        else:
            die("Ungültige Auswahl.")

    missing = [key for key in keys if key not in source_sw]
    if missing:
        die(
            f"Nicht in '{source_name}' vorhanden: "
            + ", ".join(missing)
        )

    copied = 0
    skipped = 0

    for key in keys:
        incoming = source_sw[key]

        if key in dest_sw:
            if dest_sw[key] == incoming:
                print(f"= {key}: bereits identisch in '{dest_name}'")
                skipped += 1
                continue

            overwrite = bool(args.overwrite)
            if not overwrite and sys.stdin.isatty():
                overwrite = yes_no(
                    f"'{key}' existiert in '{dest_name}' anders. Überschreiben?",
                    False,
                )

            if not overwrite:
                print(f"- {key}: übersprungen")
                skipped += 1
                continue

        dest_sw[key] = incoming
        print(f"✓ {key}: {source_name} → {dest_name}")
        copied += 1

    save_catalog(args.project, dest, dest_name)
    print(f"\nFertig. Kopiert: {copied}, übersprungen: {skipped}.")



PARAMETER_PROFILE_FIELDS = (
    "arguments",
    "context",
    "creates_path",
    "installer_engine",
    "desktop_shortcut",
    "install_timeout_minutes",
)


def load_parameter_backups(project: Path) -> dict[str, Any]:
    ensure_initialized(project, quiet=True)
    path = project_paths(project)["parameter_backups"]
    data = load_yaml(path, PARAMETER_BACKUP_TEMPLATE) or {}
    profiles = data.get("parameter_profiles")
    if not isinstance(profiles, dict):
        data["parameter_profiles"] = {}
    return _scrub_parameter_backup_secrets(data)


def _scrub_parameter_backup_secrets(data: dict[str, Any]) -> dict[str, Any]:
    """Never retain a legacy literal credential in the backup data model."""
    profiles = data.get("parameter_profiles", {})
    if not isinstance(profiles, dict):
        return {"parameter_profiles": {}}
    for raw_profile in profiles.values():
        if not isinstance(raw_profile, dict):
            continue
        arguments = str(raw_profile.get("arguments", "") or "")
        if _literal_secret_argument_names(arguments):
            raw_profile.pop("arguments", None)
            raw_profile["arguments_omitted"] = (
                "Legacy-Klartext-Geheimwert wurde nicht in das Parameter-Backup übernommen."
            )
    return data


def save_parameter_backups(project: Path, data: dict[str, Any]) -> None:
    atomic_write_yaml(
        project_paths(project)["parameter_backups"],
        sanitize_catalog_data(_scrub_parameter_backup_secrets(data)),
    )


def parameter_profile_from_app(
    key: str,
    app: dict[str, Any],
    catalog_name: str,
) -> dict[str, Any]:
    profile: dict[str, Any] = {
        "name": str(app.get("name", key)),
        "source_catalog": catalog_name,
        "type": str(app.get("type", "")),
    }

    for field in PARAMETER_PROFILE_FIELDS:
        if field == "arguments":
            arguments = str(app.get(field, ""))
            if _literal_secret_argument_names(arguments):
                profile["arguments_omitted"] = (
                    "Klartext-Geheimwert nicht gesichert; zuerst Vault-Referenz verwenden."
                )
            else:
                profile[field] = arguments
        elif field == "context":
            profile[field] = str(app.get(field, "machine"))
        elif field in app:
            profile[field] = app[field]

    return sanitize_catalog_data(profile)


def backup_parameter_profile(
    project: Path,
    catalog_name: str,
    key: str,
    app: dict[str, Any],
) -> None:
    data = load_parameter_backups(project)
    profiles = data.setdefault("parameter_profiles", {})
    profiles[key] = parameter_profile_from_app(
        key,
        app,
        catalog_name,
    )
    save_parameter_backups(project, data)


def cmd_params_backup(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(
        args.project,
        catalog_name,
    ).get("software_catalog", {})

    requested = list(getattr(args, "software", []) or [])
    backup_all = bool(getattr(args, "all", False)) or not requested

    if backup_all:
        keys = list(catalog.keys())
    else:
        keys = requested

    if not keys:
        die(f"Katalog '{catalog_name}' ist leer.")

    missing = [key for key in keys if key not in catalog]
    if missing:
        die(
            "Nicht im Katalog gefunden: "
            + ", ".join(missing)
        )

    data = load_parameter_backups(args.project)
    profiles = data.setdefault("parameter_profiles", {})

    for key in keys:
        profiles[key] = parameter_profile_from_app(
            key,
            catalog[key],
            catalog_name,
        )

    save_parameter_backups(args.project, data)

    print()
    print(
        f"✓ {len(keys)} Parameter-Profil(e) gesichert."
    )
    print(
        "  Datei: "
        + str(project_paths(args.project)["parameter_backups"])
    )


def cmd_params_list(args: argparse.Namespace) -> None:
    data = load_parameter_backups(args.project)
    profiles = data.get("parameter_profiles", {})

    print("PARAMETER-BACKUPS")
    print("=================")

    if not profiles:
        print("Noch keine Parameter-Backups vorhanden.")
        return

    print()
    print(
        f"{'KEY':<25} {'NAME':<32} {'TYP':<6} "
        f"{'KONTEXT':<20} ARGUMENTE"
    )
    print("-" * 120)

    for key, profile in profiles.items():
        print(
            f"{key[:24]:<25} "
            f"{str(profile.get('name', key))[:31]:<32} "
            f"{str(profile.get('type', ''))[:5]:<6} "
            f"{str(profile.get('context', ''))[:19]:<20} "
            f"{redact_sensitive_text(profile.get('arguments', ''))}"
        )


def _restore_parameter_profile(
    project: Path,
    catalog_name: str,
    profile_key: str,
    target_key: str,
    *,
    force: bool = False,
) -> bool:
    data = load_parameter_backups(project)
    profiles = data.get("parameter_profiles", {})
    profile = profiles.get(profile_key)

    if not isinstance(profile, dict):
        die(f"Parameter-Profil '{profile_key}' nicht gefunden.")

    catalog = get_catalog(project, catalog_name)
    sw = catalog.get("software_catalog", {})
    app = sw.get(target_key)

    if not isinstance(app, dict):
        die(
            f"'{target_key}' ist nicht im Katalog "
            f"'{catalog_name}'."
        )

    old_type = str(profile.get("type", "")).lower()
    new_type = str(app.get("type", "")).lower()

    if (
        old_type
        and new_type
        and old_type != new_type
        and not force
    ):
        die(
            f"Typ hat sich geändert: Backup={old_type}, "
            f"aktueller Installer={new_type}. "
            "Nicht blind wiederhergestellt. "
            "Mit --force erzwingen, falls wirklich gewollt."
        )

    # Installerpfad, SHA256 und aktuelle Analyse bleiben absichtlich erhalten.
    if "arguments" in profile:
        arguments = str(profile.get("arguments", ""))
        validate_installer_arguments(
            arguments,
            context=f"Parameter-Profil '{profile_key}'",
        )
        if arguments:
            app["arguments"] = arguments
        else:
            app.pop("arguments", None)

    if profile.get("context"):
        app["context"] = str(profile["context"])

    if profile.get("creates_path"):
        app["creates_path"] = profile["creates_path"]
    else:
        app.pop("creates_path", None)

    if profile.get("installer_engine"):
        app["installer_engine"] = profile["installer_engine"]

    if "desktop_shortcut" in profile:
        app["desktop_shortcut"] = profile["desktop_shortcut"]
    else:
        app.pop("desktop_shortcut", None)

    if "install_timeout_minutes" in profile:
        try:
            timeout_value = int(profile["install_timeout_minutes"])
        except (TypeError, ValueError):
            timeout_value = 30

        if timeout_value < 1:
            timeout_value = 30

        app["install_timeout_minutes"] = timeout_value
    else:
        app.pop("install_timeout_minutes", None)

    sw[target_key] = sanitize_catalog_data(app)
    save_catalog(project, catalog, catalog_name)
    return True


def cmd_params_restore(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )

    if getattr(args, "all", False):
        profiles = load_parameter_backups(
            args.project
        ).get("parameter_profiles", {})
        catalog = get_catalog(
            args.project,
            catalog_name,
        ).get("software_catalog", {})

        restored = 0
        skipped = 0

        for profile_key in profiles:
            if profile_key not in catalog:
                skipped += 1
                continue

            _restore_parameter_profile(
                args.project,
                catalog_name,
                profile_key,
                profile_key,
                force=bool(getattr(args, "force", False)),
            )
            restored += 1

        print(
            f"✓ Wiederhergestellt: {restored}, "
            f"übersprungen: {skipped}"
        )
        return

    profile_key = getattr(args, "profile", None)
    if not profile_key:
        data = load_parameter_backups(args.project)
        profiles = data.get("parameter_profiles", {})
        if not profiles:
            die("Keine Parameter-Backups vorhanden.")

        keys = list(profiles.keys())
        print()
        print("Parameter-Profil auswählen:")
        for i, key in enumerate(keys, 1):
            profile = profiles[key]
            print(
                f"  {i}) {key} - "
                f"{profile.get('name', key)}"
            )

        while True:
            raw = input("> ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(keys):
                profile_key = keys[int(raw) - 1]
                break
            print("Ungültige Auswahl.")

    target_key = getattr(args, "target_key", None) or profile_key

    _restore_parameter_profile(
        args.project,
        catalog_name,
        profile_key,
        target_key,
        force=bool(getattr(args, "force", False)),
    )

    print(
        f"✓ Parameter '{profile_key}' auf "
        f"'{target_key}' in '{catalog_name}' wiederhergestellt."
    )


def parameter_backup_menu(project: Path) -> None:
    while True:
        print()
        print("PARAMETER-BACKUPS")
        print("=================")
        print("  1) Backups anzeigen")
        print("  2) Parameter eines Programms sichern")
        print("  3) ALLE Parameter eines Katalogs sichern")
        print("  4) Parameter wiederherstellen")
        print("  0) Zurück")
        print()

        choice = input("> ").strip()

        if choice == "1":
            cmd_params_list(
                argparse.Namespace(project=project)
            )

        elif choice in {"2", "3"}:
            catalog_name = choose_catalog_by_number(
                project,
                default_name=get_default_catalog_name(project),
                title="Katalog auswählen",
            )

            if choice == "2":
                key = choose_software_interactive(
                    project,
                    catalog_name,
                )
                software = [key]
                all_ = False
            else:
                software = []
                all_ = True

            cmd_params_backup(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    software=software,
                    all=all_,
                )
            )

        elif choice == "4":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=get_default_catalog_name(project),
                title="Zielkatalog auswählen",
            )
            cmd_params_restore(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    profile=None,
                    target_key=None,
                    all=False,
                    force=False,
                )
            )

        elif choice == "0":
            return

        else:
            print("Ungültige Auswahl.")





EDITABLE_CONTEXTS: list[tuple[str, str, str]] = [
    ("1", "machine", "Machine / normal administrativ"),
    ("2", "system", "SYSTEM / LocalSystem"),
    (
        "3",
        "user_interactive",
        "Angemeldeter Benutzer INTERAKTIV / GUI sichtbar / NICHT erhöht",
    ),
    (
        "4",
        "machine_detached",
        "SYSTEM DETACHED / LocalSystem / unbeaufsichtigt / keine sichtbare GUI",
    ),
    (
        "5",
        "machine_interactive",
        "Angemeldeter Benutzer INTERAKTIV + ELEVATED / GUI sichtbar / höchste verfügbare Rechte",
    ),
    (
        "6",
        "user_uac",
        "Angemeldeter Benutzer INTERAKTIV / zuerst USER, bei benötigten Adminrechten Fallback UAC",
    ),
]


def _context_label(context: str) -> str:
    normalized = str(context or "machine")

    if normalized == "user_non_elevated":
        normalized = "user_interactive"

    for _, value, label in EDITABLE_CONTEXTS:
        if value == normalized:
            return label

    return normalized


DEFAULT_VISIBLE_INSTALL_CONTEXTS = [value for _, value, _ in EDITABLE_CONTEXTS]


def _normalize_context_value(value: str) -> str:
    normalized = str(value or "machine").strip()
    if normalized == "user_non_elevated":
        normalized = "user_interactive"
    return normalized


def get_visible_install_contexts(project: Path) -> list[str]:
    config = get_config(project)
    raw = config.get("ui", {}).get(
        "visible_install_contexts",
        DEFAULT_VISIBLE_INSTALL_CONTEXTS,
    )
    if not isinstance(raw, list):
        raw = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)

    allowed = set(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
    selected: list[str] = []
    for item in raw:
        value = _normalize_context_value(str(item))
        if value in allowed and value not in selected:
            selected.append(value)

    if not selected:
        selected = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
    return selected


def _visible_context_choices(project: Path) -> list[tuple[str, str, str]]:
    visible = set(get_visible_install_contexts(project))
    rows = [row for row in EDITABLE_CONTEXTS if row[1] in visible]
    return [
        (str(index), value, label)
        for index, (_, value, label) in enumerate(rows, start=1)
    ]


def prompt_install_context(project: Path, default_context: str = "machine") -> str:
    choices = _visible_context_choices(project)
    if not choices:
        choices = [("1", "machine", _context_label("machine"))]

    normalized_default = _normalize_context_value(default_context)
    default_number = next(
        (number for number, value, _ in choices if value == normalized_default),
        choices[0][0],
    )

    if normalized_default not in {value for _, value, _ in choices}:
        print(
            f"! Vorgeschlagener/aktueller Kontext '{_context_label(normalized_default)}' "
            "ist in Optionen ausgeblendet."
        )

    selected = prompt_choice(
        "Installationskontext:",
        [(number, label) for number, _, label in choices],
        default_number,
    )
    return next(value for number, value, _ in choices if number == selected)


def install_context_options_menu(project: Path) -> None:
    while True:
        visible_list = get_visible_install_contexts(project)
        visible = set(visible_list)

        print("\nINSTALLATIONSKONTEXTE ANZEIGEN / AUSBLENDEN")
        print("===========================================")
        print("Nur die Auswahl in der TUI wird vereinfacht.")
        print("Bestehende Katalogeinträge bleiben unverändert.\n")

        for number, value, label in EDITABLE_CONTEXTS:
            mark = "X" if value in visible else " "
            print(f"  {number}) [{mark}] {label}")

        print("  7) Alle anzeigen")
        print("  8) Kurzansicht: Machine / SYSTEM / Benutzer")
        print("  0) Zurück")
        print()

        choice = input("> ").strip()
        values_by_number = {number: value for number, value, _ in EDITABLE_CONTEXTS}

        if choice == "0":
            return
        if choice == "7":
            new_visible = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
        elif choice == "8":
            new_visible = ["machine", "system", "user_interactive"]
        elif choice in values_by_number:
            value = values_by_number[choice]
            new_visible = list(visible_list)
            if value in new_visible:
                if len(new_visible) <= 1:
                    print("! Mindestens ein Installationskontext muss sichtbar bleiben.")
                    continue
                new_visible.remove(value)
            else:
                enabled = set(new_visible) | {value}
                new_visible = [
                    item for item in DEFAULT_VISIBLE_INSTALL_CONTEXTS if item in enabled
                ]
        else:
            print("Ungültige Auswahl.")
            continue

        config_path = project_paths(project)["config"]
        config = load_yaml(config_path, {}) or {}
        ui = dict(config.get("ui", {}) or {})
        ui["visible_install_contexts"] = new_visible
        config["ui"] = ui
        atomic_write_yaml(config_path, config)
        print("✓ Sichtbare Installationskontexte gespeichert.")


def options_menu(project: Path) -> None:
    while True:
        print("\nOPTIONEN")
        print("========")
        print("  1) Installationskontexte anzeigen / ausblenden")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()
        if choice == "1":
            install_context_options_menu(project)
        elif choice == "0":
            return
        else:
            print("Ungültige Auswahl.")


def _save_quick_edit(
    project: Path,
    catalog_name: str,
    catalog: dict[str, Any],
    key: str,
) -> None:
    app = catalog["software_catalog"][key]
    catalog["software_catalog"][key] = sanitize_catalog_data(app)

    save_catalog(
        project,
        catalog,
        catalog_name,
    )

    backup_parameter_profile(
        project,
        catalog_name,
        key,
        catalog["software_catalog"][key],
    )

    print("✓ Änderung gespeichert.")


def cmd_software_edit(args: argparse.Namespace) -> None:
    """
    Bestehenden Katalogeintrag schnell ändern.
    Kein Löschen und Neuanlegen nötig.
    """
    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(args.project, catalog_name)
    software_catalog = catalog["software_catalog"]

    key = getattr(args, "key", None)
    if not key:
        key = choose_software_interactive(
            args.project,
            catalog_name,
        )
    key = validate_software_key(key)

    if key not in software_catalog:
        die(f"'{key}' ist nicht im Katalog '{catalog_name}'.")

    while True:
        app = software_catalog[key]
        app_type = str(app.get("type", "exe")).lower()

        context = str(app.get("context", "machine"))
        arguments = str(app.get("arguments", ""))
        creates_path = str(app.get("creates_path", ""))
        timeout_value = int(
            app.get("install_timeout_minutes", 30)
            or 30
        )

        desktop_shortcut = app.get("desktop_shortcut")
        shortcut_text = "(keine)"

        if (
            isinstance(desktop_shortcut, dict)
            and desktop_shortcut.get("enabled")
        ):
            shortcut_text = (
                f"{desktop_shortcut.get('name', app.get('name', key))} -> "
                f"{desktop_shortcut.get('target', '(kein Ziel)')}"
            )

        print()
        print("PROGRAMM SCHNELL BEARBEITEN")
        print("===========================")
        print(f"Katalog:     {catalog_name}")
        print(f"Schlüssel:   {key}")
        print(f"Name:        {app.get('name', key)}")
        print(f"Installer:   {app.get('installer', '')}")
        print(f"Typ:         {_software_type_label(app)}")
        if app_type == "winget":
            if _is_msstore_app(app):
                print(f"Store-ID:    {app.get('winget_id', '(fehlt)')}")
                print("Store:       Microsoft Store / WinGet msstore | Scope=USER")
            else:
                print(f"WinGet-ID:   {app.get('winget_id', '(fehlt)')}")
                print(f"WinGet:      Scope={app.get('winget_scope', '?')} | Quelle={app.get('winget_source', 'winget')} | Version={app.get('winget_version', 'aktuell')}")
        print(f"Kontext:     {_context_label(context)}")
        print(f"Parameter:   {redact_sensitive_text(arguments) or '(KEINE)'}")

        if context in {
            "machine_detached",
            "machine_interactive",
            "user_interactive",
            "user_non_elevated",
            "user_uac",
        }:
            print(f"Timeout:     {timeout_value} Min.")
        else:
            print("Timeout:     (für diesen Kontext nicht verwendet)")

        print(f"Erkennung:   {creates_path or '(KEINER)'}")
        print(f"Shortcut:    {shortcut_text}")
        print()
        print("  1) Installationskontext ändern")
        print("  2) Parameter / Flags ändern")
        print("  3) Timeout ändern")
        print("  4) Erkennungspfad ändern")
        print("  5) Anzeigename ändern")
        print("  6) Installer-Datei ändern")
        print("  7) Installer-Typ ändern")
        print("  8) Desktop-Verknüpfung ändern")
        print("  9) Kompletten YAML-Eintrag anzeigen")
        print("  0) Fertig / zurück")
        print()
        print("  Strg+2 / m) MEHRFACHAUSWAHL: mehrere Programme markieren + Installationsmodus ändern")
        print()

        choice = _input_with_ctrl2("> ").strip()

        if choice == CTRL2_SENTINEL or choice.lower() in {"m", "multi", "mehrfach"}:
            bulk_install_context_menu(args.project, catalog_name)
            # Bulk-Modus speichert den Katalog selbst. Danach frisch laden,
            # damit die Schnellbearbeitung sofort den neuen Modus zeigt.
            catalog = get_catalog(args.project, catalog_name)
            software_catalog = catalog["software_catalog"]
            if key not in software_catalog:
                print("! Der aktuell bearbeitete Eintrag ist nicht mehr vorhanden.")
                return
            continue

        if choice == "1":
            if app_type == "winget" and _is_msstore_app(app):
                print()
                print("Microsoft-Store-Apps bleiben in Mavi im USER-Kontext.")
                print("Für SYSTEM/MACHINE-AppX-Provisioning wäre ein anderer Bereitstellungsweg nötig.")
                continue
            if app_type == "winget":
                picked = prompt_choice(
                    "WinGet-Installationsbereich:",
                    [("1", "MACHINE / für den ganzen PC"), ("2", "USER / aktuell angemeldeter Benutzer")],
                    "2" if str(app.get("winget_scope", "machine")) == "user" else "1",
                )
                scope = "user" if picked == "2" else "machine"
                app["winget_scope"] = scope
                app["context"] = "user_interactive" if scope == "user" else "machine"
                if scope == "user":
                    app["install_timeout_minutes"] = int(app.get("install_timeout_minutes", 30) or 30)
                else:
                    app.pop("install_timeout_minutes", None)
            else:
                new_context = prompt_install_context(
                    args.project,
                    context,
                )
                app["context"] = new_context

                if new_context in {
                    "machine_detached",
                    "machine_interactive",
                    "user_interactive",
                    "user_uac",
                }:
                    app["install_timeout_minutes"] = int(
                        app.get("install_timeout_minutes", 30)
                        or 30
                    )
                else:
                    app.pop("install_timeout_minutes", None)

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "2":
            if app_type == "winget":
                print("Microsoft-Store-/WinGet-Pakete verwenden keine normalen EXE/MSI-Flags in diesem Menü.")
                print("Version/Scope stehen direkt im WinGet-Katalogeintrag.")
                continue
            print()
            print(f"Aktuell: {redact_sensitive_text(arguments) or '(KEINE)'}")
            print("Enter = unverändert")
            print("-     = Parameter komplett entfernen")
            new_value = input("Neue Parameter: ").strip()

            if not new_value:
                print("Unverändert.")
                continue

            if new_value == "-":
                app.pop("arguments", None)
            else:
                app["arguments"] = validate_installer_arguments(
                    new_value,
                    context=f"Katalogeintrag '{key}'",
                )

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "3":
            if context not in {
                "machine_detached",
                "machine_interactive",
                "user_interactive",
                "user_non_elevated",
                "user_uac",
            }:
                print()
                print(
                    "Der aktuelle Kontext verwendet keinen eigenen "
                    "Mavi-Task-Timeout."
                )
                print(
                    "Timeout wird bei DETACHED und INTERAKTIVEN "
                    "Task-Scheduler-Modi verwendet."
                )
                continue

            while True:
                raw = prompt(
                    "Timeout in Minuten",
                    str(timeout_value),
                )

                try:
                    new_timeout = int(raw)
                except ValueError:
                    print("Bitte eine ganze Zahl eingeben.")
                    continue

                if new_timeout < 1:
                    print("Timeout muss mindestens 1 Minute sein.")
                    continue

                app["install_timeout_minutes"] = new_timeout
                break

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "4":
            print()
            print(f"Aktuell: {creates_path or '(KEINER)'}")
            print("Enter = unverändert")
            print("-     = Erkennungspfad entfernen")
            new_value = input("Neuer Erkennungspfad: ").strip()

            if not new_value:
                print("Unverändert.")
                continue

            if new_value == "-":
                app.pop("creates_path", None)
            else:
                app["creates_path"] = new_value

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "5":
            current_name = str(app.get("name", key))
            new_name = prompt(
                "Anzeigename",
                current_name,
            ).strip()

            if not new_name or new_name == current_name:
                print("Unverändert.")
                continue

            app["name"] = new_name

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "6":
            if app_type == "winget":
                print("Store-/WinGet-Eintrag hat keine lokale Installer-Datei. Für eine andere Paket-ID den Eintrag neu anlegen.")
                continue
            config = get_config(args.project)
            current_installer = str(app.get("installer", ""))

            print()
            print(f"Aktuell: {current_installer}")
            print("Enter = unverändert")
            raw_path = input("Neue Installer-Datei: ").strip()

            if not raw_path:
                print("Unverändert.")
                continue

            new_path = resolve_installer_path(
                normalize_path(raw_path, config),
                config,
            )

            if not new_path.exists():
                print(f"Installer nicht gefunden: {new_path}")
                continue

            if not new_path.is_file():
                print(f"Pfad ist keine Datei: {new_path}")
                continue

            app["installer"] = str(new_path)

            suffix = new_path.suffix.lower()
            if suffix == ".msi":
                app["type"] = "msi"
            elif suffix == ".exe":
                app["type"] = "exe"

            print("Berechne verpflichtenden SHA-256 ...")
            app["sha256"] = sha256_file(new_path)
            app.pop("allow_unsafe_missing_sha256", None)

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "7":
            if app_type == "winget":
                print("Store/WinGet wird absichtlich nicht blind in EXE/MSI umgewandelt. Bitte neuen Eintrag anlegen.")
                continue
            current_type = str(
                app.get("type", "exe")
            ).lower()

            new_type = prompt_choice(
                "Installer-Typ:",
                [
                    ("1", "EXE"),
                    ("2", "MSI"),
                ],
                "2" if current_type == "msi" else "1",
            )

            app["type"] = (
                "msi"
                if new_type == "2"
                else "exe"
            )

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "8":
            enabled = (
                isinstance(desktop_shortcut, dict)
                and bool(desktop_shortcut.get("enabled"))
            )

            if enabled:
                print()
                print(f"Aktuell: {shortcut_text}")
                print("  1) Verknüpfung ändern")
                print("  2) Verknüpfung entfernen")
                print("  0) Abbrechen")

                sub_choice = input("> ").strip()

                if sub_choice == "0":
                    continue

                if sub_choice == "2":
                    app.pop("desktop_shortcut", None)

                    _save_quick_edit(
                        args.project,
                        catalog_name,
                        catalog,
                        key,
                    )
                    continue

                if sub_choice != "1":
                    print("Ungültige Auswahl.")
                    continue

            current_shortcut = (
                desktop_shortcut
                if isinstance(desktop_shortcut, dict)
                else {}
            )

            shortcut_name = prompt(
                "Name der Desktop-Verknüpfung",
                str(
                    current_shortcut.get(
                        "name",
                        app.get("name", key),
                    )
                ),
            )

            shortcut_target = prompt(
                "Ziel-EXE der Desktop-Verknüpfung",
                str(
                    current_shortcut.get(
                        "target",
                        "",
                    )
                ),
            )

            if not shortcut_target:
                print("Kein Ziel angegeben. Unverändert.")
                continue

            app["desktop_shortcut"] = {
                "enabled": True,
                "name": shortcut_name,
                "target": shortcut_target,
            }

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "9":
            print()
            print(
                redact_sensitive_text(
                    yaml.safe_dump(
                        {key: app},
                        allow_unicode=True,
                        sort_keys=False,
                    ).rstrip()
                )
            )

        elif choice == "0":
            return

        else:
            print("Ungültige Auswahl.")



def _parse_multi_program_selection(raw: str, item_count: int) -> list[int]:
    """Mehrfachauswahl wie 1,3,5-8 / 1 3 5-8 / alle parsen."""
    value = str(raw or "").strip().lower()
    if not value:
        return []
    if value in {"alle", "all", "*", "a"}:
        return list(range(1, item_count + 1))

    normalized = value.replace(";", ",").replace(" ", ",")
    tokens = [part.strip() for part in normalized.split(",") if part.strip()]
    selected: set[int] = set()

    for token in tokens:
        if "-" in token:
            if token.count("-") != 1:
                raise ValueError(f"Ungültiger Bereich: {token}")
            start_raw, end_raw = token.split("-", 1)
            if not start_raw.isdigit() or not end_raw.isdigit():
                raise ValueError(f"Ungültiger Bereich: {token}")
            start = int(start_raw)
            end = int(end_raw)
            if start > end:
                start, end = end, start
            if start < 1 or end > item_count:
                raise ValueError(f"Auswahl außerhalb 1-{item_count}: {token}")
            selected.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Ungültige Auswahl: {token}")
            number = int(token)
            if number < 1 or number > item_count:
                raise ValueError(f"Auswahl außerhalb 1-{item_count}: {token}")
            selected.add(number)

    return sorted(selected)


def _bulk_context_compatibility(app: dict[str, Any], target_context: str) -> tuple[bool, str]:
    app_type = str(app.get("type", "exe") or "exe").lower()
    target_context = _normalize_context_value(target_context)

    if app_type == "office_odt":
        return (
            False,
            "Office ODT läuft in Mavi fest als SYSTEM DETACHED; Kontextfeld wird nicht umgestellt.",
        )

    if app_type == "winget":
        if _is_msstore_app(app):
            if target_context == "user_interactive":
                return True, "Microsoft Store bleibt im USER-Kontext (msstore)."
            return (
                False,
                "Microsoft-Store-Apps bleiben in Mavi im USER-Kontext; Machine/SYSTEM wird nicht erzwungen.",
            )
        if target_context == "machine":
            return True, "WinGet wird auf Scope=MACHINE umgestellt."
        if target_context == "user_interactive":
            return True, "WinGet wird auf Scope=USER umgestellt."
        return (
            False,
            "WinGet unterstützt hier nur Machine oder Benutzer INTERAKTIV (Scope user).",
        )

    return True, ""


def _apply_bulk_install_context(app: dict[str, Any], target_context: str) -> None:
    """Installationskontext konsistent auf einen Katalogeintrag anwenden."""
    target_context = _normalize_context_value(target_context)
    app_type = str(app.get("type", "exe") or "exe").lower()

    if app_type == "winget":
        if _is_msstore_app(app):
            if target_context != "user_interactive":
                raise ValueError("Microsoft-Store-App darf nur USER-Kontext verwenden")
            app["context"] = "user_interactive"
            app["winget_scope"] = "user"
            app["winget_source"] = "msstore"
            app["install_timeout_minutes"] = int(app.get("install_timeout_minutes", 30) or 30)
            return
        if target_context == "machine":
            app["context"] = "machine"
            app["winget_scope"] = "machine"
            app.pop("install_timeout_minutes", None)
            return
        if target_context == "user_interactive":
            app["context"] = "user_interactive"
            app["winget_scope"] = "user"
            app["install_timeout_minutes"] = int(app.get("install_timeout_minutes", 30) or 30)
            return
        raise ValueError("Unzulässiger WinGet-Kontext")

    app["context"] = target_context
    if target_context in {
        "machine_detached",
        "machine_interactive",
        "user_interactive",
        "user_uac",
    }:
        app["install_timeout_minutes"] = int(app.get("install_timeout_minutes", 30) or 30)
    else:
        app.pop("install_timeout_minutes", None)


def bulk_install_context_menu(project: Path, catalog_name: str | None = None) -> None:
    """Mehrere Katalogprogramme markieren und deren Installationsmodus gemeinsam ändern."""
    if catalog_name is None:
        default_name = get_default_catalog_name(project)
        catalog_name = choose_catalog_by_number(
            project,
            default_name=default_name,
            title="Katalog für Mehrfachänderung auswählen",
        )
    else:
        catalog_name = resolve_catalog_name(project, catalog_name)
    catalog = get_catalog(project, catalog_name)
    software_catalog = catalog.get("software_catalog", {}) or {}

    if not software_catalog:
        print(f"Katalog '{catalog_name}' ist leer.")
        return

    items = list(software_catalog.items())

    while True:
        selected_keys = choose_software_multi_interactive(
            project,
            catalog_name,
            title="MEHRERE PROGRAMME · INSTALLATIONSMODUS ÄNDERN",
        )
        if not selected_keys:
            return

        by_key = {key: (idx, app) for idx, (key, app) in enumerate(items, start=1)}
        selected = [
            (by_key[key][0], key, by_key[key][1])
            for key in selected_keys
            if key in by_key
        ]
        print()
        print(f"Markiert: {len(selected)} Programm(e)")
        for number, key, app in selected:
            meta = _software_mode_meta(app if isinstance(app, dict) else {})
            print(f"  [{number:>2}] {app.get('name', key)}  |  {meta['mode']}")

        print()
        target_context = prompt_install_context(project, "machine")
        target_label = _context_label(target_context)

        applicable: list[tuple[int, str, dict[str, Any], str]] = []
        skipped: list[tuple[int, str, dict[str, Any], str]] = []

        for number, key, raw_app in selected:
            app = raw_app if isinstance(raw_app, dict) else {}
            ok, note = _bulk_context_compatibility(app, target_context)
            if ok:
                applicable.append((number, key, app, note))
            else:
                skipped.append((number, key, app, note))

        print()
        print("ÄNDERUNGSVORSCHAU")
        print("=================")
        print(f"Neuer Modus: {target_label}")
        print()
        for number, key, app, note in applicable:
            current = _software_mode_meta(app)["mode"]
            suffix = f"  ({note})" if note else ""
            print(f"  ✓ [{number:>2}] {app.get('name', key)}: {current} -> {target_label}{suffix}")
        for number, key, app, note in skipped:
            print(f"  ! [{number:>2}] {app.get('name', key)}: ÜBERSPRUNGEN | {note}")

        if not applicable:
            print()
            print("! Für den gewählten Modus ist keines der markierten Programme kompatibel.")
            return

        print()
        if skipped:
            print(f"Hinweis: {len(skipped)} inkompatible Einträge werden nicht verändert.")
        if not yes_no(f"Installationsmodus bei {len(applicable)} Programm(en) jetzt ändern?", False):
            print("Abgebrochen. Keine Änderung gespeichert.")
            return

        changed_keys: list[str] = []
        for _, key, app, _ in applicable:
            before = sanitize_catalog_data(dict(app))
            _apply_bulk_install_context(app, target_context)
            software_catalog[key] = sanitize_catalog_data(app)
            if software_catalog[key] != before:
                changed_keys.append(key)

        if not changed_keys:
            print("✓ Alle markierten Programme hatten diesen Modus bereits. Nichts zu speichern.")
            return

        save_catalog(project, catalog, catalog_name)
        for key in changed_keys:
            backup_parameter_profile(
                project,
                catalog_name,
                key,
                software_catalog[key],
            )

        print()
        print(f"✓ Installationsmodus für {len(changed_keys)} Programm(e) geändert.")
        if skipped:
            print(f"! {len(skipped)} inkompatible Einträge wurden sicher übersprungen.")
        print("✓ Parameter-Profile der geänderten Programme wurden aktualisiert.")
        return


def catalog_menu(project: Path) -> None:
    while True:
        default_name = get_default_catalog_name(project)

        print()
        print("KATALOGE VERWALTEN")
        print("==================")
        print(f"Standard: {default_name}")
        print()
        print("  1) Kataloge anzeigen")
        print("  2) Programme in einem Katalog anzeigen")
        print("  3) Programm schnell bearbeiten")
        print("  4) Programm aus einem Katalog entfernen")
        print("  5) Neuen Katalog erstellen")
        print("  6) Standardkatalog festlegen")
        print("  7) Software zwischen Katalogen kopieren")
        print("  8) Parameter-Backups verwalten")
        print("  9) Alten Scan-Müll aus Katalog entfernen")
        print(" 10) Mehrfachmodus: Programme markieren / Installationsmodus ändern")
        print("  0) Zurück")
        print()

        choice = input("> ").strip()

        if choice == "1":
            cmd_catalog_list(
                argparse.Namespace(
                    project=project,
                )
            )

        elif choice == "2":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Katalog auswählen",
            )

            cmd_software_list(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                )
            )

        elif choice == "3":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Katalog auswählen",
            )

            catalog = get_catalog(
                project,
                catalog_name,
            )

            if not catalog.get("software_catalog"):
                print(f"Katalog '{catalog_name}' ist leer.")
                continue

            software_key, multi_mode = choose_software_single_with_multi_shortcut(
                project,
                catalog_name,
                title=f"Programm aus '{catalog_name}' schnell bearbeiten",
            )

            if multi_mode:
                bulk_install_context_menu(project, catalog_name)
                continue

            if software_key is None:
                continue

            cmd_software_edit(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    key=software_key,
                )
            )

        elif choice == "4":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Katalog auswählen",
            )

            catalog = get_catalog(
                project,
                catalog_name,
            )

            if not catalog.get("software_catalog"):
                print(f"Katalog '{catalog_name}' ist leer.")
                continue

            software_key = choose_software_interactive(
                project,
                catalog_name,
            )

            cmd_software_remove(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    key=software_key,
                    yes=False,
                )
            )

        elif choice == "5":
            name = prompt("Neuer Katalogname")
            copy_from = None

            if yes_no(
                "Bestehenden Katalog als Vorlage kopieren?",
                False,
            ):
                copy_from = choose_catalog_by_number(
                    project,
                    default_name=default_name,
                    title="Vorlage auswählen",
                )

            set_default = yes_no(
                "Diesen Katalog als Standard setzen?",
                False,
            )

            cmd_catalog_create(
                argparse.Namespace(
                    project=project,
                    name=name,
                    copy_from=copy_from,
                    set_default=set_default,
                )
            )

        elif choice == "6":
            name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Neuen Standardkatalog auswählen",
            )

            cmd_catalog_set_default(
                argparse.Namespace(
                    project=project,
                    name=name,
                )
            )

        elif choice == "7":
            source = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Quellkatalog auswählen",
            )

            destination = choose_catalog_by_number(
                project,
                default_name=None,
                title="Zielkatalog auswählen",
            )

            source_data = get_catalog(
                project,
                source,
            )["software_catalog"]

            if not source_data:
                print(f"Katalog '{source}' ist leer.")
                continue

            print()
            print("Was soll kopiert werden?")
            print("  1) ALLE Programme (Standard)")
            print("  2) Ein einzelnes Programm")
            mode = input("> [1] ").strip() or "1"

            if mode == "1":
                all_ = True
                software = []

            elif mode == "2":
                all_ = False
                software = [
                    choose_software_interactive(
                        project,
                        source,
                    )
                ]

            else:
                print("Ungültige Auswahl.")
                continue

            cmd_catalog_copy(
                argparse.Namespace(
                    project=project,
                    source=source,
                    destination=destination,
                    software=software,
                    all=all_,
                    overwrite=False,
                    create_destination=False,
                )
            )

        elif choice == "8":
            parameter_backup_menu(project)

        elif choice == "9":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Katalog reparieren",
            )

            cmd_catalog_repair(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    all=False,
                )
            )

        elif choice == "10":
            bulk_install_context_menu(project)

        elif choice == "0":
            return

        else:
            print("Ungültige Auswahl.")




def cmd_init(args: argparse.Namespace) -> None:
    ensure_initialized(args.project)



OFFICE_PRODUCTS: dict[str, dict[str, Any]] = {
    # Planner / Project subscription
    "project_plan3": {
        "name": "Planner and Project Plan 3",
        "product_id": "ProjectProRetail",
        "family": "project",
        "channel": None,
    },
    "project_plan5": {
        "name": "Planner and Project Plan 5",
        "product_id": "ProjectProRetail",
        "family": "project",
        "channel": None,
    },

    # Microsoft 365 / Office 365
    "m365_apps_enterprise": {
        "name": "Microsoft 365 Apps for enterprise (EEA / ohne Teams)",
        "product_id": "O365ProPlusEEANoTeamsRetail",
        "family": "office",
        "channel": None,
    },
    "m365_apps_business": {
        "name": "Microsoft 365 Apps for business (EEA / ohne Teams)",
        "product_id": "O365BusinessEEANoTeamsRetail",
        "family": "office",
        "channel": None,
    },
    "m365_business_standard": {
        "name": "Microsoft 365 Business Standard",
        "product_id": "O365BusinessRetail",
        "family": "office",
        "channel": None,
    },
    "m365_business_premium": {
        "name": "Microsoft 365 Business Premium",
        "product_id": "O365BusinessRetail",
        "family": "office",
        "channel": None,
    },
    "m365_e3_e5": {
        "name": "Microsoft 365 E3/E5 oder Office 365 E3/E5",
        "product_id": "O365ProPlusRetail",
        "family": "office",
        "channel": None,
    },

    # Office 2024 Retail / Volume
    "office_home_business_2024": {
        "name": "Office Home & Business 2024 Retail",
        "product_id": "HomeBusiness2024Retail",
        "family": "office",
        "channel": None,
    },
    "office_professional_2024": {
        "name": "Office Professional 2024 Retail",
        "product_id": "Professional2024Retail",
        "family": "office",
        "channel": None,
    },
    "office_proplus_2024_retail": {
        "name": "Office Professional Plus 2024 Retail",
        "product_id": "ProPlus2024Retail",
        "family": "office",
        "channel": None,
    },
    "office_ltsc_proplus_2024": {
        "name": "Office LTSC Professional Plus 2024 Volume",
        "product_id": "ProPlus2024Volume",
        "family": "office",
        "channel": "PerpetualVL2024",
    },
    "office_ltsc_standard_2024": {
        "name": "Office LTSC Standard 2024 Volume",
        "product_id": "Standard2024Volume",
        "family": "office",
        "channel": "PerpetualVL2024",
    },

    # Project 2024
    "project_pro_2024_retail": {
        "name": "Project Professional 2024 Retail",
        "product_id": "ProjectPro2024Retail",
        "family": "project",
        "channel": None,
    },
    "project_std_2024_retail": {
        "name": "Project Standard 2024 Retail",
        "product_id": "ProjectStd2024Retail",
        "family": "project",
        "channel": None,
    },
    "project_pro_2024_volume": {
        "name": "Project Professional LTSC 2024 Volume",
        "product_id": "ProjectPro2024Volume",
        "family": "project",
        "channel": "PerpetualVL2024",
    },
    "project_std_2024_volume": {
        "name": "Project Standard LTSC 2024 Volume",
        "product_id": "ProjectStd2024Volume",
        "family": "project",
        "channel": "PerpetualVL2024",
    },

    # Visio
    "visio_subscription": {
        "name": "Visio Professional Subscription / Visio Plan 2",
        "product_id": "VisioProRetail",
        "family": "visio",
        "channel": None,
    },
    "visio_pro_2024_retail": {
        "name": "Visio Professional 2024 Retail",
        "product_id": "VisioPro2024Retail",
        "family": "visio",
        "channel": None,
    },
    "visio_std_2024_retail": {
        "name": "Visio Standard 2024 Retail",
        "product_id": "VisioStd2024Retail",
        "family": "visio",
        "channel": None,
    },
    "visio_pro_2024_volume": {
        "name": "Visio Professional LTSC 2024 Volume",
        "product_id": "VisioPro2024Volume",
        "family": "visio",
        "channel": "PerpetualVL2024",
    },
    "visio_std_2024_volume": {
        "name": "Visio Standard LTSC 2024 Volume",
        "product_id": "VisioStd2024Volume",
        "family": "visio",
        "channel": "PerpetualVL2024",
    },
}


def looks_like_office_candidate(path: Path) -> bool:
    name = path.name.lower()

    obvious_names = {
        "officesetup.exe",
        "office setup.exe",
    }

    if name in obvious_names:
        return True

    # Nicht blind im gesamten Pfad nach Teilzeichenfolgen suchen:
    # "mavi-provisioner" enthält beispielsweise selbst "visio".
    marker_pattern = re.compile(
        r"(?<![a-z0-9])(?:"
        r"microsoft[ _-]+office|"
        r"office[ _-]*365|"
        r"microsoft[ _-]*365|"
        r"m365|"
        r"project|"
        r"visio|"
        r"office[ _-]*deployment|"
        r"officedeployment|"
        r"odt"
        r")(?![a-z0-9])"
    )

    return any(marker_pattern.search(part.lower()) for part in path.parts)


def friendly_product_from_id(product_id: str) -> dict[str, Any] | None:
    for profile in OFFICE_PRODUCTS.values():
        if profile["product_id"].lower() == product_id.lower():
            return dict(profile)
    return None


def parse_office_xml(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "product_id": "",
        "architecture": "",
        "channel": "",
        "languages": [],
    }

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as exc:
        die(f"XML konnte nicht gelesen werden: {path}\n{exc}")

    add = root.find(".//Add")
    if add is not None:
        result["architecture"] = add.attrib.get("OfficeClientEdition", "")
        result["channel"] = add.attrib.get("Channel", "")

        product = add.find("Product")
        if product is not None:
            result["product_id"] = product.attrib.get("ID", "")
            result["languages"] = [
                lang.attrib.get("ID", "")
                for lang in product.findall("Language")
                if lang.attrib.get("ID")
            ]

    return result


def choose_office_profile() -> dict[str, Any]:
    print()
    print("Microsoft-Produkt auswählen")
    print("===========================")
    print("  1) Planner / Project")
    print("  2) Microsoft 365 / Office 365")
    print("  3) Office 2024")
    print("  4) Visio")
    print("  5) Product-ID manuell eingeben")
    print()

    category = input("> ").strip()

    groups = {
        "1": [
            "project_plan3",
            "project_plan5",
            "project_pro_2024_retail",
            "project_std_2024_retail",
            "project_pro_2024_volume",
            "project_std_2024_volume",
        ],
        "2": [
            "m365_apps_enterprise",
            "m365_apps_business",
            "m365_business_standard",
            "m365_business_premium",
            "m365_e3_e5",
        ],
        "3": [
            "office_home_business_2024",
            "office_professional_2024",
            "office_proplus_2024_retail",
            "office_ltsc_proplus_2024",
            "office_ltsc_standard_2024",
        ],
        "4": [
            "visio_subscription",
            "visio_pro_2024_retail",
            "visio_std_2024_retail",
            "visio_pro_2024_volume",
            "visio_std_2024_volume",
        ],
    }

    if category == "5":
        product_id = prompt("ODT Product-ID")
        family_choice = select_from_list(
            "Produktart",
            [
                ("office", "Office"),
                ("project", "Project"),
                ("visio", "Visio"),
            ],
            default_key="office",
        )

        channel = prompt(
            "Optionaler Channel (Enter = keiner / vorhandenen Office-Kanal übernehmen)",
            "",
        )

        return {
            "name": product_id,
            "product_id": product_id,
            "family": family_choice,
            "channel": channel or None,
        }

    if category not in groups:
        die("Ungültige Microsoft-Produktkategorie.")

    keys = groups[category]
    selected = select_from_list(
        "Produkt/Lizenz auswählen",
        [
            (key, OFFICE_PRODUCTS[key]["name"])
            for key in keys
        ],
        allow_name=True,
    )

    return dict(OFFICE_PRODUCTS[selected])


def choose_office_architecture() -> str:
    return select_from_list(
        "Office-Architektur",
        [
            ("64", "64 Bit"),
            ("32", "32 Bit"),
        ],
        default_key="64",
    )


def choose_office_language() -> str:
    choice = select_from_list(
        "Office-Sprache",
        [
            ("de-de", "Deutsch (de-de)"),
            ("MatchOS", "Windows-Sprache übernehmen (MatchOS)"),
            ("custom", "Andere Sprache eingeben"),
        ],
        default_key="de-de",
    )

    if choice == "custom":
        return prompt("Language ID, z. B. en-us")

    return choice


def office_default_creates_path(family: str, architecture: str) -> str:
    root = (
        r"C:\Program Files\Microsoft Office\root\Office16"
        if architecture == "64"
        else r"C:\Program Files (x86)\Microsoft Office\root\Office16"
    )

    exe = {
        "project": "WINPROJ.EXE",
        "visio": "VISIO.EXE",
        "office": "WINWORD.EXE",
    }.get(family, "WINWORD.EXE")

    return root + "\\" + exe


def generate_office_xml(
    path: Path,
    *,
    product_id: str,
    architecture: str,
    language: str,
    channel: str | None,
    remove_msi: bool,
) -> None:
    configuration = ET.Element("Configuration")

    add_attrs = {
        "OfficeClientEdition": architecture,
    }
    if channel:
        add_attrs["Channel"] = channel

    add = ET.SubElement(configuration, "Add", add_attrs)
    product = ET.SubElement(add, "Product", {"ID": product_id})
    ET.SubElement(product, "Language", {"ID": language})

    if remove_msi:
        ET.SubElement(configuration, "RemoveMSI")

    ET.SubElement(
        configuration,
        "Display",
        {
            "Level": "None",
            "AcceptEULA": "TRUE",
        },
    )

    try:
        ET.indent(configuration, space="  ")
    except AttributeError:
        pass

    tree = ET.ElementTree(configuration)
    path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(
        path,
        encoding="utf-8",
        xml_declaration=True,
    )


def choose_xml_file(
    config: dict[str, Any],
    *,
    preferred_dir: Path | None = None,
) -> Path:
    local_root = _mavi_source_root(config)
    drive = _mavi_drive_label(
        (config.get("software_source", {}) or {}).get("drive")
    )

    # XML im selben Ordner zuerst anbieten.
    if preferred_dir and preferred_dir.exists():
        same_dir_xml = sorted(
            preferred_dir.glob("*.xml"),
            key=lambda p: p.name.lower(),
        )
        if same_dir_xml:
            print()
            print("XML-Dateien im gleichen Ordner gefunden:")
            selected = select_from_list(
                "XML auswählen",
                [
                    (str(path), path.name)
                    for path in same_dir_xml
                ],
            )
            return Path(selected)

    print()
    print("XML auswählen")
    print(f"  1) Durch {drive or _mavi_source_label(config)} browsen (Standard)")
    print("  2) Pfad eintippen")
    print()

    mode = input("> [1] ").strip() or "1"

    if mode == "1":
        if local_root is None:
            die(
                "Die Softwarequelle ist noch nicht eingerichtet. "
                "Bitte zuerst Mavi-Setup ausführen."
            )
        return browse_files(
            local_root,
            drive,
            extensions={".xml"},
            title="Office XML auswählen",
            start_dir=preferred_dir if preferred_dir else None,
        )

    if mode == "2":
        raw = prompt("XML-Pfad (Windows-Laufwerk, UNC oder Linux)")
        return normalize_path(raw, config)

    die("Ungültige XML-Auswahl.")


def choose_odt_setup(
    selected_installer: Path | None,
    config: dict[str, Any],
) -> Path:
    """
    Wählt die echte Office Deployment Tool setup.exe aus.

    OfficeSetup.exe aus dem Microsoft-Portal ist NICHT die ODT setup.exe
    und darf nicht für /configure verwendet werden.
    """
    print()
    print("Office Deployment Tool")
    print("======================")
    print("Für /configure wird die echte ODT-Datei 'setup.exe' benötigt.")
    print("Eine 'OfficeSetup.exe' aus dem Microsoft-Portal ist dafür NICHT geeignet.")

    if selected_installer is not None:
        print(f"Vorher ausgewählte EXE: {selected_installer}")

        if selected_installer.name.lower() == "setup.exe":
            if yes_no(
                "Ist diese setup.exe wirklich das Microsoft Office Deployment Tool?",
                True,
            ):
                return selected_installer
        elif selected_installer.name.lower() == "officesetup.exe":
            print()
            print("! OfficeSetup.exe erkannt.")
            print("  Diese Datei wird NICHT als ODT verwendet.")
            print("  Bitte jetzt die echte ODT setup.exe auswählen.")
        else:
            print()
            print(
                "! Die ausgewählte Datei heißt nicht 'setup.exe' und wird "
                "nicht als ODT akzeptiert."
            )

    local_root = _mavi_source_root(config)
    drive = _mavi_drive_label(
        (config.get("software_source", {}) or {}).get("drive")
    )

    while True:
        print()
        print("ODT setup.exe auswählen")
        print(f"  1) Durch {drive or _mavi_source_label(config)} browsen (Standard)")
        print("  2) Pfad eintippen")
        print()

        mode = input("> [1] ").strip() or "1"

        start_dir = (
            selected_installer.parent
            if selected_installer is not None
            else None
        )

        if mode == "1":
            if local_root is None:
                die(
                    "Die Softwarequelle ist noch nicht eingerichtet. "
                    "Bitte zuerst Mavi-Setup ausführen."
                )
            candidate = browse_files(
                local_root,
                drive,
                extensions={".exe"},
                title="ODT setup.exe auswählen",
                start_dir=start_dir,
            )
        elif mode == "2":
            raw = prompt("Pfad zur ODT setup.exe")
            candidate = normalize_path(raw, config)
        else:
            print("Ungültige Auswahl.")
            continue

        if not candidate.exists():
            print(f"ODT-Datei nicht gefunden: {candidate}")
            continue

        if not candidate.is_file() or candidate.suffix.lower() != ".exe":
            print("Bitte eine EXE-Datei auswählen.")
            continue

        if candidate.name.lower() == "officesetup.exe":
            print()
            print("! Das ist OfficeSetup.exe aus dem Portal, nicht die ODT setup.exe.")
            continue

        if candidate.name.lower() != "setup.exe":
            print()
            print(
                "! Für den ODT-Modus akzeptiere ich bewusst nur eine Datei "
                "mit dem Namen 'setup.exe'."
            )
            print(
                "  So landet nicht versehentlich wieder OfficeSetup.exe "
                "im /configure-Workflow."
            )
            continue

        if yes_no(
            "Diese setup.exe als Microsoft Office Deployment Tool verwenden?",
            True,
        ):
            return candidate



def cmd_add_office_odt(
    args: argparse.Namespace,
    selected_installer: Path | None,
    catalog_name: str,
    config: dict[str, Any],
) -> None:
    print()
    print("MICROSOFT-PRODUKT")
    print("=================")
    print(f"Zielkatalog: {catalog_name}")
    print()
    print("Hinweis: Für die Installation wird später die echte ODT 'setup.exe'")
    print("verwendet, NICHT die Portal-Datei 'OfficeSetup.exe'.")
    print()

    # WICHTIG: Das Produkt wird bewusst vom Benutzer gewählt.
    # Eine generische setup.exe kann nicht zuverlässig sagen,
    # welche Microsoft-Lizenz bzw. welches Produkt bereitgestellt werden soll.
    profile = choose_office_profile()

    print()
    print("Gewählt:")
    print(f"  Produkt:     {profile['name']}")
    print(f"  Product ID:  {profile['product_id']}")

    use_existing_xml = yes_no(
        "Gibt es bereits eine passende .xml-Konfigurationsdatei?",
        False,
    )

    architecture = "64"
    language = "de-de"
    channel = profile.get("channel")
    xml_path: Path

    if use_existing_xml:
        preferred_dir = (
            selected_installer.parent
            if selected_installer is not None
            else None
        )

        xml_path = choose_xml_file(
            config,
            preferred_dir=preferred_dir,
        )

        if not xml_path.exists():
            die(f"XML-Datei nicht gefunden: {xml_path}")

        parsed = parse_office_xml(xml_path)
        xml_product_id = parsed.get("product_id", "")
        architecture = parsed.get("architecture", "") or "64"
        xml_channel = parsed.get("channel", "") or None
        languages = parsed.get("languages", [])
        language = languages[0] if languages else "unbekannt"

        print()
        print("Vorhandene XML erkannt:")
        print(f"  Product ID:   {xml_product_id or '(nicht erkannt)'}")
        print(f"  Architektur:  {architecture}")
        print(f"  Channel:      {xml_channel or '(nicht gesetzt)'}")
        print(
            f"  Sprache:      "
            f"{', '.join(languages) if languages else '(nicht erkannt)'}"
        )

        if (
            xml_product_id
            and xml_product_id.lower()
            != str(profile["product_id"]).lower()
        ):
            print()
            print("! ACHTUNG: Die XML passt nicht zur vorher gewählten Product-ID.")
            print(f"  Gewählt: {profile['product_id']}")
            print(f"  XML:     {xml_product_id}")

            if yes_no(
                "Die Product-ID aus der XML übernehmen?",
                False,
            ):
                detected = friendly_product_from_id(xml_product_id)
                if detected:
                    profile = detected
                else:
                    profile = {
                        "name": xml_product_id,
                        "product_id": xml_product_id,
                        "family": profile.get("family", "office"),
                        "channel": xml_channel,
                    }
            else:
                print("Vorhandene XML wird nicht verwendet.")
                use_existing_xml = False

        if use_existing_xml:
            channel = xml_channel or channel

            if not yes_no(
                "Diese XML unverändert mit /configure verwenden?",
                True,
            ):
                use_existing_xml = False

    if not use_existing_xml:
        print()
        print("Keine vorhandene XML wird verwendet.")
        print("Das Tool erzeugt eine neue ODT-Konfiguration.")

        architecture = choose_office_architecture()
        language = choose_office_language()
        channel = profile.get("channel")

        print()
        print("Neue ODT-Konfiguration:")
        print(f"  Produkt:       {profile['name']}")
        print(f"  Product ID:    {profile['product_id']}")
        print(f"  Architektur:   {architecture} Bit")
        print(f"  Sprache:       {language}")
        print(
            f"  Channel:       "
            f"{channel or '(nicht gesetzt / vorhandenen Office-Kanal verwenden)'}"
        )

        remove_msi = yes_no(
            "Alte MSI-basierte Office-Versionen per <RemoveMSI /> entfernen?",
            False,
        )
    else:
        remove_msi = False

    default_name = profile.get("name", "Microsoft Office")
    name = args.name or prompt("Anzeigename", default_name)
    key = validate_software_key(
        args.key or prompt("Katalog-Schlüssel", slugify(name))
    )

    if not use_existing_xml:
        xml_dir = (
            project_paths(args.project)["office_configs_dir"]
            / catalog_name
        )
        xml_path = xml_dir / f"{key}.xml"

        generate_office_xml(
            xml_path,
            product_id=str(profile["product_id"]),
            architecture=architecture,
            language=language,
            channel=channel,
            remove_msi=remove_msi,
        )

        print()
        print(f"✓ XML automatisch erzeugt: {xml_path}")

    # Erst nachdem Produkt und XML feststehen, wird ODT gewählt.
    odt_hint = selected_installer

    if getattr(args, "odt", None):
        odt_hint = normalize_path(args.odt, config)
        if not odt_hint.exists():
            die(f"Angegebene ODT-Datei existiert nicht: {odt_hint}")

    odt_setup = choose_odt_setup(
        odt_hint,
        config,
    )

    family = str(profile.get("family", "office"))
    default_creates = office_default_creates_path(
        family,
        architecture,
    )

    creates_path = prompt(
        "Erkennungspfad nach Installation",
        default_creates,
    )

    app = {
        "name": name,
        "installer": str(odt_setup),
        "type": "office_odt",
        "context": "machine",
        "installer_engine": "Microsoft Office Deployment Tool",
        "arguments": "/configure",
        "install_timeout_minutes": 30,
        "configuration_file": str(xml_path),
        "sha256": sha256_file(odt_setup),
        "creates_path": creates_path,
        "office": {
            "product_id": profile.get("product_id", "unbekannt"),
            "profile": profile.get("name", name),
            "family": family,
            "architecture": architecture,
            "language": language,
            "channel": channel or "",
            "xml_source": "existing" if use_existing_xml else "generated",
        },
        "analysis": {
            "confidence": "hoch",
            "admin_requirement": "ja",
            "reasons": [
                "Microsoft-Produkt wurde bewusst über den Microsoft-Assistenten gewählt.",
                "Installation erfolgt mit dem Office Deployment Tool und /configure.",
                f"Product ID: {profile.get('product_id', 'unbekannt')}",
            ],
        },
    }

    app = sanitize_catalog_data(app)

    catalog = get_catalog(args.project, catalog_name)
    sw = catalog["software_catalog"]

    if key in sw and not yes_no(
        f"'{key}' existiert bereits in '{catalog_name}'. Überschreiben?",
        False,
    ):
        print("Abgebrochen.")
        return

    print()
    print("Wird gespeichert:")
    print(
        redact_sensitive_text(
            yaml.safe_dump(
                {key: app},
                allow_unicode=True,
                sort_keys=False,
            ).rstrip()
        )
    )

    if not yes_no("Zum Katalog hinzufügen?", True):
        print("Abgebrochen.")
        return

    sw[key] = app
    save_catalog(args.project, catalog, catalog_name)

    print()
    print(
        f"✓ '{key}' wurde als Microsoft-ODT-Paket "
        f"zum Katalog '{catalog_name}' hinzugefügt."
    )
    print(f"  Produkt: {profile.get('name', name)}")
    print(f"  XML:     {xml_path}")
    print(f"  ODT:     {odt_setup}")


def cmd_microsoft_add(args: argparse.Namespace) -> None:
    """
    Expliziter Microsoft-Wizard.
    Kein Raten anhand eines setup.exe-Dateinamens nötig.
    """
    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)

    catalog_name = choose_catalog_interactive(
        args.project,
        getattr(args, "catalog", None),
        purpose="für das Microsoft-Produkt verwenden",
        ask_other=True,
    )

    selected_installer: Path | None = None
    if getattr(args, "odt", None):
        selected_installer = normalize_path(args.odt, config)

    cmd_add_office_odt(
        args,
        selected_installer,
        catalog_name,
        config,
    )




def cmd_software_scan(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)

    if args.path:
        path = resolve_installer_path(
            normalize_path(args.path, config),
            config,
        )
    else:
        path = choose_installer_path(config)
        path = resolve_installer_path(path, config)

    if not path.exists() or not path.is_file():
        die(f"Installer nicht gefunden: {path}")

    mode = getattr(args, "mode", "full") or "full"

    use_known_rules = mode == "full"
    use_learned_rules = mode == "full"

    analysis = analyze_installer(
        path,
        args.project,
        use_known_rules=use_known_rules,
        use_learned_rules=use_learned_rules,
    )

    print()
    print("INSTALLER DEEP-SCAN")
    print("===================")
    print(f"Modus:      {mode}")
    if mode == "heuristic":
        print("Regeln:     feste Produktregeln AUS, gelernte Regeln AUS")
        print("            nur PE/VersionInfo + Engine + eingebettete CLI-Strings")
    else:
        print("Regeln:     volle Produktionserkennung")
    print(f"Pfad:       {path}")
    print(f"Typ:        {analysis.get('type', '')}")
    print(f"Produkt:    {analysis.get('name_guess', '')}")
    print(f"Engine:     {analysis.get('engine', 'unbekannt')}")
    print(f"Silent:     {redact_sensitive_text(analysis.get('arguments')) or '(nicht sicher erkannt)'}")
    print(f"Kontext:    {analysis.get('context', 'unbekannt')}")
    print(f"Admin:      {analysis.get('admin_requirement', 'unbekannt')}")
    print(f"Konfidenz:  {analysis.get('confidence', 'niedrig')}")

    metadata = analysis.get("metadata", {}) or {}
    for key, label in (
        ("CompanyName", "Hersteller"),
        ("ProductName", "ProductName"),
        ("FileDescription", "Beschreibung"),
        ("ProductVersion", "Version"),
        ("OriginalFilename", "Originaldatei"),
        ("PEArchitecture", "Architektur"),
        ("SignatureSubject", "Signatur"),
        ("LearnedRule", "Gelernte Regel"),
    ):
        if metadata.get(key):
            print(f"{label + ':':<12} {metadata[key]}")

    print_silent_detection(analysis)

    reasons = analysis.get("reasons", [])
    if reasons:
        print()
        print("Warum")
        print("=====")
        for reason in reasons:
            print(f"  • {reason}")

    if analysis.get("note"):
        print()
        print("Hinweis:")
        print("  " + str(analysis["note"]))




def _neutralize_jinja_literal(value: str) -> str:
    """
    Katalogwerte sind Daten, keine Templates.
    Zufällige Jinja-Startsequenzen aus Binär-/Metadaten werden neutralisiert,
    damit Ansible sie später nicht als Template interpretiert.
    """
    # A single, deliberately narrow template form is supported for secrets:
    # {{ vault_name }} / {{ mavi_vault_name }}.  Filters, lookups, attributes
    # and expressions remain data and are neutralised.  This lets a catalog
    # reference an Ansible-Vault variable without ever storing its value.
    protected: list[tuple[str, str]] = []

    def protect(match: re.Match[str]) -> str:
        marker = f"__MAVI_ALLOWED_VAULT_REFERENCE_{len(protected)}__"
        while marker in value:
            marker = "_" + marker
        protected.append((marker, match.group(0)))
        return marker

    safe_value = VAULT_ARGUMENT_REFERENCE_RE.sub(protect, value)
    safe_value = (
        safe_value
        .replace("{{", "{ {")
        .replace("{%", "{ %")
        .replace("{#", "{ #")
    )
    for marker, reference in protected:
        safe_value = safe_value.replace(marker, reference)
    return safe_value


def sanitize_catalog_data(value: Any) -> Any:
    """
    Rekursiv literal-sichere Daten für YAML/Ansible erzeugen.
    """
    if isinstance(value, str):
        return _neutralize_jinja_literal(value)

    if isinstance(value, list):
        return [
            sanitize_catalog_data(item)
            for item in value
        ]

    if isinstance(value, dict):
        return {
            sanitize_catalog_data(key): sanitize_catalog_data(val)
            for key, val in value.items()
        }

    return value


def compact_silent_detection_for_catalog(
    detection: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Roh-Kontexte aus Binary-Scans gehören NICHT in produktive Katalogdateien.

    Persistiert werden nur die für Nachvollziehbarkeit nützlichen,
    kontrollierten Zusammenfassungsfelder.
    """
    detection = detection or {}

    allowed = (
        "arguments",
        "confidence",
        "method",
        "source_label",
        "reason",
    )

    return {
        key: sanitize_catalog_data(detection[key])
        for key in allowed
        if key in detection and detection[key] not in (None, "", [], {})
    }


def compact_analysis_for_catalog(
    analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Nur kuratierte Analyseinformationen speichern.
    Keine candidate/context/rejected-Dumps aus Binärdateien.
    """
    metadata = analysis.get("metadata", {}) or {}

    safe_metadata_keys = (
        "CompanyName",
        "ProductName",
        "FileDescription",
        "ProductVersion",
        "FileVersion",
        "OriginalFilename",
        "InternalName",
        "PEArchitecture",
        "SignatureSubject",
        "requestedExecutionLevel",
        "UACElevationRequestedByExe",
        "DetectedProduct",
        "LearnedRule",
        "ScanSources",
        "user_markers",
        "machine_markers",
    )

    safe_metadata = {
        key: sanitize_catalog_data(metadata[key])
        for key in safe_metadata_keys
        if key in metadata and metadata[key] not in (None, "", [], {})
    }

    return sanitize_catalog_data({
        "confidence": analysis.get("confidence", "niedrig"),
        "admin_requirement": analysis.get(
            "admin_requirement",
            "unbekannt",
        ),
        "metadata": safe_metadata,
        "silent_detection": compact_silent_detection_for_catalog(
            analysis.get("silent_detection")
        ),
        "scanner_version": VERSION,
        "reasons": analysis.get("reasons", []),
    })


def repair_catalog_jinja_noise(
    project: Path,
    catalog_name: str,
) -> tuple[int, Path]:
    """
    Repariert alte v0.7.x-Katalogeinträge:
    - entfernt rohe candidate/rejected_candidate Debugdaten
    - neutralisiert zufällige Jinja-Startsequenzen
    """
    path = catalog_path(project, catalog_name)
    catalog = get_catalog(project, catalog_name)
    sw = catalog.get("software_catalog", {})

    changed_entries = 0

    for key, app in list(sw.items()):
        if not isinstance(app, dict):
            continue

        original = yaml.safe_dump(
            app,
            allow_unicode=True,
            sort_keys=False,
        )

        analysis = app.get("analysis")
        if isinstance(analysis, dict):
            detection = analysis.get("silent_detection")

            if isinstance(detection, dict):
                detection.pop("candidates", None)
                detection.pop("rejected_candidates", None)

            # Alte Analyse ebenfalls auf die sichere kompakte Form bringen.
            rebuilt_analysis = {
                "confidence": analysis.get(
                    "confidence",
                    "niedrig",
                ),
                "admin_requirement": analysis.get(
                    "admin_requirement",
                    "unbekannt",
                ),
                "metadata": analysis.get("metadata", {}),
                "silent_detection": analysis.get(
                    "silent_detection",
                    {},
                ),
                "scanner_version": analysis.get(
                    "scanner_version",
                    VERSION,
                ),
                "reasons": analysis.get("reasons", []),
            }

            app["analysis"] = sanitize_catalog_data(
                rebuilt_analysis
            )

        # Den gesamten Paketdatensatz als Literal behandeln.
        sw[key] = sanitize_catalog_data(app)

        updated = yaml.safe_dump(
            sw[key],
            allow_unicode=True,
            sort_keys=False,
        )

        if updated != original:
            changed_entries += 1

    if changed_entries:
        save_catalog(
            project,
            catalog,
            catalog_name,
        )

    return changed_entries, path


def cmd_catalog_repair(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)

    if getattr(args, "all", False):
        names = list_catalog_names(args.project)

        total = 0
        for name in names:
            changed, path = repair_catalog_jinja_noise(
                args.project,
                name,
            )
            total += changed
            print(
                f"{name}: {changed} Eintrag/Einträge repariert"
                f"  [{path}]"
            )

        print()
        print(
            f"✓ Reparatur abgeschlossen. Insgesamt {total} "
            f"Eintrag/Einträge geändert."
        )
        return

    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )

    changed, path = repair_catalog_jinja_noise(
        args.project,
        catalog_name,
    )

    print()
    print(f"Katalog: {catalog_name}")
    print(f"Datei:   {path}")

    if changed:
        print(
            f"✓ {changed} Eintrag/Einträge wurden von "
            "rohen Scan-/Jinja-Daten bereinigt."
        )
    else:
        print("✓ Keine problematischen Scan-/Jinja-Daten gefunden.")





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
    if _is_msstore_app(app):
        return "STORE"
    return str(app.get("type", "?") or "?").upper()


def _winget_validate_identifier(value: str, *, label: str = "Paket-ID") -> str:
    value = str(value or "").strip()
    if not WINGET_PACKAGE_ID_RE.fullmatch(value):
        die(
            f"Ungültige WinGet-{label}: {value!r}. "
            "Erlaubt sind Buchstaben, Zahlen sowie . _ + - ohne Leerzeichen."
        )
    return value


def _winget_validate_source(value: str) -> str:
    value = str(value or "winget").strip() or "winget"
    if not WINGET_SOURCE_RE.fullmatch(value):
        die(f"Ungültige WinGet-Quelle: {value!r}")
    return value


def _winget_validate_version(value: str) -> str:
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
    args.source = "msstore"
    args.scope = "user"
    args.version = None
    cmd_winget_add(args)


def cmd_software_add(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)

    if args.path:
        path = normalize_path(args.path, config)
        if path.exists() and path.is_dir() and sys.stdin.isatty():
            path = browse_installer(
                path,
                _mavi_drive_label(
                    (config.get("software_source", {}) or {}).get("drive")
                ),
            )
    else:
        path = choose_installer_path(config)

    path = resolve_installer_path(path, config)

    if not path.exists():
        local_root = _mavi_source_root(config)
        die(
            f"Installer nicht gefunden: {path}\n"
            f"Bekannte Softwarequelle: {local_root or '(nicht eingerichtet)'}"
        )

    if not path.is_file():
        die(f"Pfad ist keine Datei: {path}")

    catalog_name = choose_catalog_interactive(
        args.project,
        getattr(args, "catalog", None),
        purpose="verwenden",
        ask_other=True,
    )
    print(f"Zielkatalog: {catalog_name}")

    if looks_like_office_candidate(path):
        print()
        print(
            "! Microsoft Office / Project / Visio erkannt."
        )
        if yes_no(
            "Zum Microsoft-Assistenten wechseln?",
            True,
        ):
            cmd_add_office_odt(
                args,
                path,
                catalog_name,
                config,
            )
            return

    analysis = analyze_installer(
        path,
        args.project,
        use_known_rules=True,
        use_learned_rules=False,
    )

    # Microsoft TeamsBootstrapper ist absichtlich eine headless CLI.
    # Für die Bereitstellung ist -p der normale Provisioning-Schalter.
    if path.name.lower() == "teamsbootstrapper.exe":
        analysis["arguments"] = analysis.get("arguments") or "-p"
        analysis["context"] = "machine"
        reasons = list(analysis.get("reasons", []) or [])
        reasons.append("Microsoft TeamsBootstrapper erkannt: Provisioning mit -p vorgeschlagen.")
        analysis["reasons"] = reasons
        print()
        print("✓ Microsoft TeamsBootstrapper erkannt.")
        print("  Empfehlung: Machine + Parameter -p (headless Provisioning).")
        print("  Falls der Aufruf im Benutzerkontext erhöhte Rechte verlangt,")
        print("  kann der Kontext 'USER → UAC FALLBACK' automatisch sichtbar nach UAC wechseln.")

    print()
    print("Installer-Grunddaten")
    print("====================")
    print(f"Pfad:    {path}")
    print(f"Typ:     {analysis['type']}")
    print(f"Regel:   {analysis['engine']}")
    print(
        "Flags:   "
        + (
            redact_sensitive_text(analysis["arguments"])
            or "(manuell / keine)"
        )
    )
    print()
    print(
        "Deep-Scan: AUS. Es werden keine Silent-Flags "
        "aus Binärdaten geraten."
    )

    name = args.name or prompt(
        "Anzeigename",
        analysis["name_guess"],
    )
    key = validate_software_key(
        args.key or prompt(
            "Katalog-Schlüssel",
            slugify(name),
        )
    )

    typ = analysis["type"]
    if typ not in {"msi", "exe"}:
        typ = prompt_choice(
            "Installer-Typ:",
            [("msi", "MSI"), ("exe", "EXE")],
            "exe",
        )

    catalog = get_catalog(args.project, catalog_name)
    sw = catalog["software_catalog"]
    existing = sw.get(key)
    preserve_existing = False

    if isinstance(existing, dict):
        print()
        print(f"! '{key}' existiert bereits.")
        print(
            f"  Aktueller Installer: "
            f"{existing.get('installer', '')}"
        )
        print(
            f"  Gespeicherte Flags:  "
            f"{redact_sensitive_text(existing.get('arguments')) or '(keine)'}"
        )
        print(
            f"  Kontext:             "
            f"{existing.get('context', 'machine')}"
        )

        if not yes_no(
            "Mit neuer Installer-Datei überschreiben?",
            False,
        ):
            print("Abgebrochen.")
            return

        # Vor JEDEM Versionswechsel automatisch sichern.
        backup_parameter_profile(
            args.project,
            catalog_name,
            key,
            existing,
        )
        print(
            "✓ Vorhandene Parameter automatisch gesichert."
        )

        same_type = (
            str(existing.get("type", "")).lower()
            == typ.lower()
        )

        if not same_type:
            print(
                "! Installer-Typ hat sich geändert. Alte Flags "
                "werden nicht blind übernommen."
            )
        else:
            preserve_existing = yes_no(
                "Vorhandene Parameter/Flags für die neue "
                "Version übernehmen?",
                True,
            )

    known_arguments = str(
        analysis.get("arguments", "")
    )

    if preserve_existing:
        arguments = str(
            existing.get("arguments", "")
        )
        context = str(
            existing.get("context", "machine")
        )
        creates_path = str(
            existing.get("creates_path", "")
        )
        desktop_shortcut = existing.get(
            "desktop_shortcut"
        )
        install_timeout_minutes = int(
            existing.get("install_timeout_minutes", 30)
            or 30
        )
        print()
        print("Übernommen:")
        print(
            f"  Flags:   {redact_sensitive_text(arguments) or '(keine)'}"
        )
        print(f"  Kontext: {context}")
        print(
            f"  Detect:  "
            f"{creates_path or '(keiner)'}"
        )
    else:
        if typ == "exe":
            if known_arguments:
                print()
                print(
                    "Feste Produktregel im Skript:"
                )
                print(f"  {redact_sensitive_text(known_arguments)}")
                if yes_no(
                    "Diese Parameter übernehmen?",
                    True,
                ):
                    arguments = known_arguments
                else:
                    arguments = prompt(
                        "Silent-Parameter "
                        "(Enter = keine)",
                        "",
                    )
            else:
                print()
                print(
                    "Keine feste Produktregel vorhanden."
                )
                arguments = prompt(
                    "Silent-Parameter "
                    "(Enter = keine)",
                    "",
                )
        else:
            arguments = ""

        recommended = str(
            analysis.get("context", "machine")
        )

        context = prompt_install_context(
            args.project,
            recommended,
        )

        install_timeout_minutes = 30
        if context in {
            "machine_detached",
            "machine_interactive",
            "user_interactive",
            "user_uac",
        }:
            timeout_label = (
                "DETACHED"
                if context == "machine_detached"
                else "INTERAKTIV"
            )
            while True:
                timeout_raw = prompt(
                    f"Timeout für {timeout_label}-Installation in Minuten",
                    "30",
                )

                try:
                    install_timeout_minutes = int(timeout_raw)
                except ValueError:
                    print("Bitte eine ganze Zahl in Minuten eingeben.")
                    continue

                if install_timeout_minutes < 1:
                    print("Timeout muss mindestens 1 Minute sein.")
                    continue

                break

        creates_path = prompt(
            "Optionaler Erkennungspfad nach Installation "
            "(Enter = keiner)",
            str(analysis.get("creates_path", "")),
        )

        is_forticlient = (
            analysis["engine"] == "FortiClient VPN"
        )
        shortcut_default_target = (
            r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"
            if is_forticlient
            else ""
        )

        create_shortcut = yes_no(
            "Desktop-Verknüpfung für ALLE Benutzer "
            "sicherstellen?",
            is_forticlient,
        )

        desktop_shortcut = None
        if create_shortcut:
            shortcut_name = prompt(
                "Name der Desktop-Verknüpfung",
                name,
            )
            shortcut_target = prompt(
                "Ziel-EXE der Desktop-Verknüpfung",
                shortcut_default_target,
            )
            if shortcut_target:
                desktop_shortcut = {
                    "enabled": True,
                    "name": shortcut_name,
                    "target": shortcut_target,
                }

    app = {
        "name": name,
        "installer": str(path),
        "type": typ,
        "context": context,
        "installer_engine": analysis["engine"],
        "analysis": {
            "mode": "manual_parameters",
            "scanner_version": VERSION,
            "reasons": analysis.get("reasons", []),
        },
    }

    if arguments:
        app["arguments"] = validate_installer_arguments(
            arguments,
            context=f"Katalogeintrag '{key}'",
        )

    if creates_path:
        app["creates_path"] = creates_path

    if desktop_shortcut:
        app["desktop_shortcut"] = desktop_shortcut

    if context in {
        "machine_detached",
        "machine_interactive",
        "user_interactive",
    }:
        app["install_timeout_minutes"] = int(
            install_timeout_minutes
        )

    if bool(getattr(args, "allow_unsafe_missing_sha256", False)):
        print(
            "! UNSICHERE AUSNAHME: Dieser Eintrag wird ausdrücklich ohne "
            "gebundenen Installer-Hash gespeichert."
        )
        app["allow_unsafe_missing_sha256"] = True
    else:
        print("Berechne verpflichtenden SHA-256 ...")
        app["sha256"] = sha256_file(path)

    app = sanitize_catalog_data(app)

    print()
    print("Wird gespeichert:")
    print(
        redact_sensitive_text(
            yaml.safe_dump(
                {key: app},
                allow_unicode=True,
                sort_keys=False,
            ).rstrip()
        )
    )

    if not yes_no(
        "Zum Katalog hinzufügen?",
        True,
    ):
        print("Abgebrochen.")
        return

    sw[key] = app
    save_catalog(
        args.project,
        catalog,
        catalog_name,
    )

    # Nach erfolgreichem Speichern direkt aktuellen Stand sichern.
    backup_parameter_profile(
        args.project,
        catalog_name,
        key,
        app,
    )

    print(
        f"\n✓ '{key}' wurde zum Katalog "
        f"'{catalog_name}' hinzugefügt."
    )
    print(
        "✓ Parameter-Profil wurde ebenfalls aktualisiert."
    )



REPORT_HTTP_PORT = 8765
REPORT_SERVER_MARKER = "Mavi-PROVISION-REPORT-SERVER-v1"
REPORT_HTTP_DEFAULT_TTL = 300


def _clip_cell(value: Any, width: int) -> str:
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ").strip()
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return "…"
    return text[: width - 1].rstrip() + "…"


def _software_mode_meta(app: dict[str, Any]) -> dict[str, str]:
    context = _normalize_context_value(str(app.get("context", "machine")))
    mapping = {
        "machine": ("Machine/Admin", "PC", "Direkt"),
        "system": ("SYSTEM", "SYSTEM", "Direkt"),
        "user_interactive": ("User interaktiv", "USER", "GUI"),
        "machine_detached": ("SYSTEM detached", "SYSTEM", "Task"),
        "machine_interactive": ("User + Highest", "USER", "GUI/Admin"),
        "user_uac": ("User → UAC Fallback", "USER", "GUI/User→UAC"),
    }
    mode, scope, execution = mapping.get(context, (context, "?", "?"))
    app_type = str(app.get("type", "")).lower()
    if app_type == "office_odt":
        # Der ODT-Pfad im Playbook läuft unabhängig vom historischen Kontextfeld
        # immer als SYSTEM über einen detached Scheduled Task.
        mode = "ODT SYSTEM detached"
        scope = "SYSTEM"
        execution = "Task/ODT"
    elif app_type == "winget":
        winget_scope = str(app.get("winget_scope", scope)).lower()
        scope = "USER" if winget_scope == "user" else "PC"
        if _is_msstore_app(app):
            mode = "Microsoft Store USER"
            scope = "USER"
            execution = "WinGet/msstore"
        else:
            mode = f"WinGet {scope}"
            execution = "WinGet"
    return {
        "context": context,
        "mode": mode,
        "scope": scope,
        "execution": execution,
        "long": _context_label(context),
    }


def _software_installer_display(app: dict[str, Any]) -> str:
    app_type = str(app.get("type", "?")).lower()
    if app_type == "winget":
        return str(app.get("winget_id") or app.get("installer") or "(WinGet-ID fehlt)")
    installer = str(app.get("installer", "") or "")
    if not installer:
        return "(kein Installer)"
    normalized = installer.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1] or installer


def _software_parameters_display(app: dict[str, Any]) -> str:
    app_type = str(app.get("type", "?")).lower()
    if app_type == "winget":
        if _is_msstore_app(app):
            return "source=msstore | scope=user"
        parts = [f"scope={app.get('winget_scope', 'machine')}"]
        if app.get("winget_version"):
            parts.append(f"v={app.get('winget_version')}")
        return " | ".join(parts)
    args = redact_sensitive_text(app.get("arguments", "")).strip()
    return args or "(keine)"


def _software_detection_display(app: dict[str, Any]) -> str:
    if str(app.get("type", "")).lower() == "winget":
        return "WinGet list · msstore" if _is_msstore_app(app) else "WinGet list"
    creates = str(app.get("creates_path", "") or "").strip()
    if creates:
        return creates
    return "Auto-Scan"


def _software_timeout_display(app: dict[str, Any]) -> str:
    context = _normalize_context_value(str(app.get("context", "machine")))
    if context in {
        "machine_detached",
        "machine_interactive",
        "user_interactive",
        "user_uac",
    } or (str(app.get("type", "")).lower() == "winget" and str(app.get("winget_scope", "machine")) == "user"):
        return f"{int(app.get('install_timeout_minutes', 30) or 30)}m"
    return "-"


def _render_catalog_terminal_table(catalog: dict[str, Any]) -> None:
    terminal_width = shutil.get_terminal_size((160, 30)).columns
    terminal_width = max(78, min(terminal_width, 220))

    rows: list[dict[str, str]] = []
    for index, (key, raw_app) in enumerate(catalog.items(), start=1):
        app = raw_app if isinstance(raw_app, dict) else {}
        meta = _software_mode_meta(app)
        rows.append({
            "nr": str(index),
            "key": str(key),
            "name": str(app.get("name", key)),
            "type": _software_type_label(app),
            "mode": meta["mode"],
            "scope": meta["scope"],
            "installer": _software_installer_display(app),
            "params": _software_parameters_display(app),
            "detect": _software_detection_display(app),
            "timeout": _software_timeout_display(app),
        })

    if terminal_width < 105:
        for row in rows:
            print(f"[{row['nr']}] {row['name']}  ({row['type']})")
            print(f"    Schlüssel: {row['key']}")
            print(f"    Modus:     {row['mode']} | Ziel: {row['scope']} | Timeout: {row['timeout']}")
            print(f"    Installer: {row['installer']}")
            print(f"    Parameter: {row['params']}")
            print(f"    Erkennung: {row['detect']}")
            print()
        return

    columns: list[tuple[str, str, int]] = [
        ("nr", "#", 3),
        ("name", "NAME", 25),
        ("type", "TYP", 8),
        ("mode", "INSTALL-MODUS", 18),
        ("scope", "ZIEL", 7),
        ("installer", "INSTALLER / ID", 25),
    ]
    if terminal_width >= 125:
        columns.insert(1, ("key", "SCHLÜSSEL", 20))
    if terminal_width >= 165:
        columns.append(("params", "PARAMETER", 23))
    if terminal_width >= 195:
        columns.append(("detect", "ERKENNUNG", 20))
        columns.append(("timeout", "TIMEOUT", 7))

    def table_width(cols: list[tuple[str, str, int]]) -> int:
        return sum(width for _, _, width in cols) + (3 * (len(cols) - 1)) + 4

    while table_width(columns) > terminal_width and len(columns) > 5:
        removable = next(
            (i for i, col in reversed(list(enumerate(columns))) if col[0] in {"detect", "params", "timeout", "key"}),
            None,
        )
        if removable is None:
            break
        columns.pop(removable)

    top = "┌" + "┬".join("─" * (width + 2) for _, _, width in columns) + "┐"
    mid = "├" + "┼".join("─" * (width + 2) for _, _, width in columns) + "┤"
    bottom = "└" + "┴".join("─" * (width + 2) for _, _, width in columns) + "┘"

    print(top)
    print("│" + "│".join(f" {_clip_cell(header, width):<{width}} " for _, header, width in columns) + "│")
    print(mid)
    for row in rows:
        print("│" + "│".join(f" {_clip_cell(row.get(field, ''), width):<{width}} " for field, _, width in columns) + "│")
    print(bottom)


_SENSITIVE_ARGUMENT_NAME = (
    r"(?:password|passwd|pass|passphrase|pwd|pin|token|access[-_]?token|"
    r"refresh[-_]?token|session[-_]?(?:id|token)|jwt|cookie|set[-_]?cookie|"
    r"secret|client[-_]?(?:secret|key)|consumer[-_]?secret|api[-_]?key|apikey|"
    r"aws[-_]?secret[-_]?access[-_]?key|aws[-_]?access[-_]?key[-_]?id|"
    r"vault[-_]?password|connection[-_]?string|"
    r"license[-_]?key|licensekey|product[-_]?key|serial(?:number)?|"
    r"authorization|credential|private[-_]?key)"
)
_SENSITIVE_ARGUMENT_VALUE = (
    r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s,;]+)'
)
_SENSITIVE_ARGUMENT_PATTERNS = (
    re.compile(
        r"(?i)(?P<prefix>\b(?:Proxy-)?Authorization\s*[:=]\s*)"
        r"(?P<secret>[^\r\n,]+)"
    ),
    re.compile(
        rf"(?i)(?P<prefix>\bBearer\s+)(?P<secret>{_SENSITIVE_ARGUMENT_VALUE})"
    ),
    re.compile(
        rf"(?i)(?P<prefix>(?<![A-Za-z0-9_])[\"']?"
        rf"{_SENSITIVE_ARGUMENT_NAME}[\"']?\s*(?:=|:)\s*)"
        rf"(?P<secret>{_SENSITIVE_ARGUMENT_VALUE})"
    ),
    re.compile(
        rf"(?i)(?P<prefix>(?<!\S)(?:(?:--?|/)"
        rf"{_SENSITIVE_ARGUMENT_NAME}|-p)\s+)"
        rf"(?P<secret>{_SENSITIVE_ARGUMENT_VALUE})"
    ),
    re.compile(
        r"(?i)(?P<prefix>://[^/\s:@]+:)(?P<secret>[^@/\s]+)(?=@)"
    ),
)

# Catalogs may reference only a plain, allow-listed Vault variable.  Complex
# Jinja expressions and lookups are deliberately not executable catalog data.
VAULT_ARGUMENT_REFERENCE_RE = re.compile(
    r"\{\{\s*(?:vault|mavi_vault)_[A-Za-z][A-Za-z0-9_]{0,127}\s*\}\}"
)


def _unquote_argument_value(value: str) -> str:
    value = str(value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value


def _literal_secret_argument_names(value: Any) -> list[str]:
    """Return sensitive option names whose value is not a strict Vault ref."""
    text_value = str(value or "")
    findings: list[str] = []
    for pattern in _SENSITIVE_ARGUMENT_PATTERNS:
        for match in pattern.finditer(text_value):
            secret_value = _unquote_argument_value(match.groupdict().get("secret", ""))
            if VAULT_ARGUMENT_REFERENCE_RE.fullmatch(secret_value):
                continue
            prefix = str(match.groupdict().get("prefix", "Geheimwert")).strip()
            prefix = redact_sensitive_text(prefix).strip(" :=") or "Geheimwert"
            if prefix not in findings:
                findings.append(prefix)
    return findings


def validate_installer_arguments(value: Any, *, context: str = "Installer-Parameter") -> str:
    """Reject literal credentials while permitting strict Ansible-Vault refs."""
    arguments = str(value or "")
    if any(ord(char) < 32 and char not in {"\t"} for char in arguments):
        die(f"{context}: Steuerzeichen und Zeilenumbrüche sind nicht erlaubt.")
    if "***REDACTED***" in arguments or "<REDACTED" in arguments.upper():
        die(f"{context}: Ein geschwärzter Platzhalter ist kein ausführbarer Geheimwert.")

    findings = _literal_secret_argument_names(arguments)
    if findings:
        die(
            f"{context}: Klartext-Geheimwerte in Installer-Argumenten sind verboten "
            f"({', '.join(findings)}). Lege den Wert mit 'credentials setup' in "
            "Ansible Vault ab und verwende eine streng einfache Referenz, z. B. "
            "--token \"{{ vault_example_token }}\"."
        )
    return arguments


def redact_sensitive_text(value: Any) -> str:
    """Zentrale Schwärzung für Pläne, Live-Ausgaben, Reports und Fehlertexte."""
    text_value = str(value or "")

    for pattern in _SENSITIVE_ARGUMENT_PATTERNS:
        text_value = pattern.sub(
            lambda match: match.group("prefix") + "***REDACTED***",
            text_value,
        )

    # Nach den quotierten Formen auch unquotierte Connection-String-Werte
    # mit Leerzeichen bis zum Semikolon vollständig abdecken.
    connection_pattern = re.compile(
        rf"(?i)(?P<prefix>\b{_SENSITIVE_ARGUMENT_NAME}\s*=\s*)"
        r"(?P<secret>[^;\r\n]+)(?=;)"
    )
    text_value = connection_pattern.sub(
        lambda match: match.group("prefix") + "***REDACTED***",
        text_value,
    )

    return text_value


def _report_safe_arguments(value: str) -> str:
    return redact_sensitive_text(value)


def _html_badge(text: str, kind: str = "neutral") -> str:
    return f'<span class="badge {html.escape(kind)}">{html.escape(str(text))}</span>'


def _generate_catalog_html_report(project: Path, catalog_name: str, catalog: dict[str, Any], default_name: str) -> Path:
    reports_dir = project_paths(project)["reports_dir"]
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", catalog_name).strip("-.") or "catalog"
    report_path = reports_dir / f"software-catalog-{safe_name}.html"

    type_counts: dict[str, int] = {}
    mode_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    table_rows: list[str] = []

    for index, (key, raw_app) in enumerate(catalog.items(), start=1):
        app = raw_app if isinstance(raw_app, dict) else {}
        raw_app_type = str(app.get("type", "?")).lower()
        app_type = "store" if _is_msstore_app(app) else raw_app_type
        type_counts[app_type] = type_counts.get(app_type, 0) + 1
        meta = _software_mode_meta(app)
        mode_counts[meta["mode"]] = mode_counts.get(meta["mode"], 0) + 1
        scope_counts[meta["scope"]] = scope_counts.get(meta["scope"], 0) + 1

        installer_short = _software_installer_display(app)
        params = _report_safe_arguments(_software_parameters_display(app))
        detection = _software_detection_display(app)
        timeout = _software_timeout_display(app)
        engine = str(app.get("installer_engine", "") or "-")
        sha256 = str(app.get("sha256", "") or "-")
        raw_config_file = str(app.get("configuration_file", "") or "").strip()
        config_file = (
            re.split(r"[\\/]", raw_config_file)[-1]
            if raw_config_file
            else "-"
        )
        source = str(app.get("winget_source", "") or "-") if raw_app_type == "winget" else "lokale Ablage"
        version = (
            "Store-aktuell" if _is_msstore_app(app) else str(app.get("winget_version", "") or "aktuell")
        ) if raw_app_type == "winget" else "-"
        shortcut = app.get("desktop_shortcut")
        if isinstance(shortcut, dict) and shortcut.get("enabled"):
            shortcut_text = f"{shortcut.get('name', app.get('name', key))} → {shortcut.get('target', '?')}"
        else:
            shortcut_text = "-"

        type_kind = "store" if app_type == "store" else "winget" if app_type == "winget" else "office" if app_type == "office_odt" else "package"
        mode_kind = "user" if meta["scope"] == "USER" else "system" if meta["scope"] == "SYSTEM" else "machine"
        search_blob = " ".join([
            str(key), str(app.get("name", key)), app_type, meta["mode"], meta["scope"],
            installer_short, params, detection,
        ]).casefold()

        details = (
            f"<div class='detail-grid'>"
            f"<div><span>Interner Kontext</span><strong>{html.escape(meta['context'])}</strong></div>"
            f"<div><span>Ausführung</span><strong>{html.escape(meta['execution'])}</strong></div>"
            f"<div><span>Installer</span><strong>{html.escape(installer_short or '-')}</strong></div>"
            f"<div><span>Engine</span><strong>{html.escape(engine)}</strong></div>"
            f"<div><span>Quelle</span><strong>{html.escape(source)}</strong></div>"
            f"<div><span>Version</span><strong>{html.escape(version)}</strong></div>"
            f"<div><span>SHA-256</span><strong class='mono'>{html.escape(sha256)}</strong></div>"
            f"<div><span>Konfiguration</span><strong>{html.escape(config_file)}</strong></div>"
            f"<div><span>Desktop-Shortcut</span><strong>{html.escape(shortcut_text)}</strong></div>"
            f"</div>"
        )

        table_rows.append(
            f"<tr class='app-row' data-search='{html.escape(search_blob, quote=True)}' "
            f"data-type='{html.escape(app_type, quote=True)}' data-mode='{html.escape(meta['mode'], quote=True)}' data-scope='{html.escape(meta['scope'], quote=True)}'>"
            f"<td class='num'>{index}</td>"
            f"<td><div class='app-name'>{html.escape(str(app.get('name', key)))}</div><div class='sub mono'>{html.escape(str(key))}</div></td>"
            f"<td>{_html_badge(app_type.upper(), type_kind)}</td>"
            f"<td>{_html_badge(meta['mode'], mode_kind)}<div class='sub'>{html.escape(meta['long'])}</div></td>"
            f"<td>{_html_badge(meta['scope'], mode_kind)}</td>"
            f"<td><div class='mono'>{html.escape(installer_short)}</div></td>"
            f"<td><div class='mono wrap'>{html.escape(params)}</div></td>"
            f"<td><div class='mono wrap'>{html.escape(detection)}</div></td>"
            f"<td>{html.escape(timeout)}</td>"
            f"<td><details><summary>Details</summary>{details}</details></td>"
            f"</tr>"
        )

    generated = time.strftime("%d.%m.%Y %H:%M:%S")
    default_suffix = " · DEFAULT" if catalog_name == default_name else ""
    types_summary = "".join(
        f"<span class='mini-stat'><b>{count}</b> {html.escape(kind.upper())}</span>"
        for kind, count in sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))
    ) or "<span class='mini-stat'>leer</span>"
    modes_options = "".join(
        f"<option value='{html.escape(mode, quote=True)}'>{html.escape(mode)} ({count})</option>"
        for mode, count in sorted(mode_counts.items())
    )
    type_options = "".join(
        f"<option value='{html.escape(kind, quote=True)}'>{html.escape(kind.upper())} ({count})</option>"
        for kind, count in sorted(type_counts.items())
    )
    scope_options = "".join(
        f"<option value='{html.escape(scope, quote=True)}'>{html.escape(scope)} ({count})</option>"
        for scope, count in sorted(scope_counts.items())
    )

    document = f'''<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mavi Software-Katalog · {html.escape(catalog_name)}</title>
<style>
:root{{--bg:#080b10;--panel:#10151d;--panel2:#151c26;--line:#273244;--text:#edf4ff;--muted:#8fa0b8;--accent:#76a9ff;--good:#6ee7b7;--warn:#fbbf24;--violet:#c4b5fd;--shadow:0 18px 55px rgba(0,0,0,.28)}}
*{{box-sizing:border-box}} body{{margin:0;background:radial-gradient(circle at 15% -10%,#172944 0,transparent 35%),var(--bg);color:var(--text);font:14px/1.45 Inter,Segoe UI,Arial,sans-serif}} .wrap-page{{max-width:1800px;margin:auto;padding:34px 28px 60px}} h1{{font-size:32px;margin:0 0 4px;letter-spacing:-.03em}} .eyebrow{{color:var(--accent);font-weight:800;letter-spacing:.16em;font-size:11px}} .muted,.sub{{color:var(--muted)}} .sub{{font-size:12px;margin-top:3px}} .hero{{display:flex;justify-content:space-between;gap:25px;align-items:flex-end;margin-bottom:24px}} .hero-right{{text-align:right}} .stats{{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:12px;margin:18px 0 20px}} .stat{{background:linear-gradient(145deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:16px;padding:16px 18px;box-shadow:var(--shadow)}} .stat b{{font-size:25px;display:block}} .stat span{{color:var(--muted);font-size:12px}} .type-line{{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 18px}} .mini-stat{{padding:7px 10px;background:#0d1219;border:1px solid var(--line);border-radius:10px;color:var(--muted)}} .mini-stat b{{color:var(--text)}} .toolbar{{position:sticky;top:0;z-index:4;display:grid;grid-template-columns:minmax(260px,1.5fr) repeat(3,minmax(150px,.55fr));gap:10px;background:rgba(8,11,16,.88);backdrop-filter:blur(12px);padding:12px 0}} input,select{{width:100%;background:#0e141d;color:var(--text);border:1px solid var(--line);border-radius:11px;padding:11px 12px;outline:none}} input:focus,select:focus{{border-color:var(--accent)}} .table-shell{{overflow:auto;border:1px solid var(--line);border-radius:16px;background:var(--panel);box-shadow:var(--shadow)}} table{{width:100%;border-collapse:separate;border-spacing:0;min-width:1450px}} th{{position:sticky;top:68px;z-index:3;background:#141b25;color:#aebbd0;text-align:left;font-size:11px;letter-spacing:.08em;padding:13px 12px;border-bottom:1px solid var(--line)}} td{{padding:13px 12px;border-bottom:1px solid #1e2836;vertical-align:top}} tr:hover td{{background:#131a24}} .num{{color:#61718a;width:50px}} .app-name{{font-weight:750;font-size:15px}} .mono{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}} .wrap{{max-width:330px;word-break:break-word}} .badge{{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;border:1px solid #334157;background:#1b2533;color:#dce8f9;font-size:11px;font-weight:800;white-space:nowrap}} .badge.machine{{background:#102a24;border-color:#1d5949;color:#8ff0cd}} .badge.system{{background:#30240e;border-color:#624918;color:#ffd978}} .badge.user{{background:#241b38;border-color:#4a376d;color:#d8c7ff}} .badge.winget{{background:#10263a;border-color:#1c4f79;color:#8dcbff}} .badge.store{{background:#102f23;border-color:#246b4d;color:#8ff0c2}} .badge.office{{background:#2b1728;border-color:#623255;color:#f5a8dd}} details{{min-width:110px}} summary{{cursor:pointer;color:var(--accent);font-weight:700}} .detail-grid{{display:grid;grid-template-columns:repeat(2,minmax(250px,1fr));gap:8px;margin-top:12px;min-width:620px;padding:12px;background:#0b1017;border:1px solid var(--line);border-radius:12px}} .detail-grid div{{display:flex;flex-direction:column;gap:2px}} .detail-grid span{{color:var(--muted);font-size:11px}} .detail-grid strong{{font-weight:600;word-break:break-all}} .empty{{display:none;text-align:center;padding:35px;color:var(--muted)}} footer{{margin-top:18px;color:var(--muted);font-size:12px}} @media(max-width:900px){{.stats{{grid-template-columns:repeat(2,1fr)}}.toolbar{{grid-template-columns:1fr 1fr;position:static}}th{{top:0}}.hero{{display:block}}.hero-right{{text-align:left;margin-top:10px}}}}
</style>
</head>
<body><div class="wrap-page">
<div class="hero"><div><div class="eyebrow">Mavi PROVISIONING · SOFTWARE INVENTORY</div><h1>{html.escape(catalog_name)}{html.escape(default_suffix)}</h1><div class="muted">Installationsquellen, Modi, Scope, Parameter und Erkennungslogik auf einen Blick.</div></div><div class="hero-right"><div class="muted">Erzeugt am</div><b>{generated}</b><div class="sub">Mavi Provisioner {VERSION}</div></div></div>
<div class="stats"><div class="stat"><b>{len(catalog)}</b><span>Programme gesamt</span></div><div class="stat"><b>{scope_counts.get('PC',0)}</b><span>PC / Machine</span></div><div class="stat"><b>{scope_counts.get('SYSTEM',0)}</b><span>LocalSystem</span></div><div class="stat"><b>{scope_counts.get('USER',0)}</b><span>User-Kontext</span></div></div>
<div class="type-line">{types_summary}</div>
<div class="toolbar"><input id="search" placeholder="Suchen: Name, Schlüssel, Installer, Parameter …"><select id="type"><option value="">Alle Typen</option>{type_options}</select><select id="mode"><option value="">Alle Install-Modi</option>{modes_options}</select><select id="scope"><option value="">Alle Ziele</option>{scope_options}</select></div>
<div class="table-shell"><table><thead><tr><th>#</th><th>PROGRAMM / SCHLÜSSEL</th><th>TYP</th><th>INSTALL-MODUS</th><th>ZIEL</th><th>INSTALLER / PAKET-ID</th><th>PARAMETER</th><th>ERKENNUNG</th><th>TIMEOUT</th><th>MEHR</th></tr></thead><tbody id="rows">{''.join(table_rows)}</tbody></table><div class="empty" id="empty">Keine Programme passen zu den Filtern.</div></div>
<footer>Der HTML-Bericht ist rein lesend. Häufige Secret-Parameter werden nur im Browser-Report geschwärzt; der Katalog selbst wird nicht verändert.</footer>
</div>
<script>
const q=id=>document.getElementById(id), rows=[...document.querySelectorAll('.app-row')];
function filterRows(){{let visible=0;const s=q('search').value.toLocaleLowerCase(),t=q('type').value,m=q('mode').value,sc=q('scope').value;for(const r of rows){{const ok=(!s||r.dataset.search.includes(s))&&(!t||r.dataset.type===t)&&(!m||r.dataset.mode===m)&&(!sc||r.dataset.scope===sc);r.style.display=ok?'':'none';if(ok)visible++}}q('empty').style.display=visible?'none':'block'}}
['search','type','mode','scope'].forEach(id=>q(id).addEventListener(id==='search'?'input':'change',filterRows));
</script></body></html>'''
    report_path.write_text(document, encoding="utf-8")
    return report_path


def _local_ipv4_for_target(target: str) -> str:
    """
    Die lokale IPv4 bestimmen, die das Betriebssystem für ein Ziel routen
    würde. Ein UDP-connect sendet dabei keine Nutzdaten. Kann keine Route
    bestimmt werden, bleibt der sichere Loopback-Fallback erhalten.
    """
    destination = str(target or "").strip() or "198.51.100.1"
    try:
        addresses = socket.getaddrinfo(
            destination,
            9,
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
        )
    except OSError:
        addresses = []

    for address in addresses:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(address[4])
            local_ip = str(probe.getsockname()[0] or "").strip()
            parsed = ipaddress.ip_address(local_ip)
            if parsed.version == 4 and not parsed.is_unspecified:
                return str(parsed)
        except (OSError, ValueError):
            continue
        finally:
            probe.close()
    return "127.0.0.1"


def _port_available_for_http(port: int, bind_ip: str = "127.0.0.1") -> bool:
    """Read-only Vorprüfung, ob die gewünschte TCP-Adresse gebunden werden kann."""
    try:
        parsed_port = int(port)
        parsed_ip = ipaddress.ip_address(str(bind_ip).strip())
    except (TypeError, ValueError):
        return False
    if not 1 <= parsed_port <= 65535 or parsed_ip.version != 4:
        return False

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((str(parsed_ip), parsed_port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _report_bind_ip(project: Path) -> str:
    try:
        inventory = load_inventory(project)
        windows = ensure_windows_tree(inventory)
        for host_data in (windows.get("hosts", {}) or {}).values():
            if isinstance(host_data, dict) and host_data.get("ansible_host"):
                return _local_ipv4_for_target(str(host_data.get("ansible_host")))
    except Exception:
        pass
    return _local_ipv4_for_target("")


def _report_server_is_ours(health_url: str) -> bool:
    try:
        with urllib.request.urlopen(
            health_url,
            timeout=0.6,
        ) as response:
            body = response.read(1024).decode("utf-8", errors="replace").strip()
        return body == REPORT_SERVER_MARKER
    except Exception:
        return False


def _catalog_report_bind_ip(project: Path, requested: str) -> str:
    """
    HTTP-Berichte binden standardmäßig ausschließlich an Loopback. Eine
    private LAN-Adresse erfordert die explizite Auswahl ``lan`` oder die
    Angabe einer konkreten privaten Adresse. Wildcard/public binds werden
    auch bei Opt-in abgelehnt.
    """
    value = str(requested or "loopback").strip().lower()
    if value in {"loopback", "localhost", "local"}:
        return "127.0.0.1"
    if value == "lan":
        value = _report_bind_ip(project)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Report-Bind muss 'loopback', 'lan' oder eine private IPv4 sein.") from exc
    if parsed.version != 4 or parsed.is_unspecified or parsed.is_multicast:
        raise ValueError("Wildcard-, Multicast- und IPv6-Binds sind für den HTTP-Report nicht erlaubt.")
    if not (parsed.is_loopback or parsed.is_private):
        raise ValueError("Der HTTP-Report darf nur an Loopback oder eine private IPv4 gebunden werden.")
    return str(parsed)


def _catalog_report_ttl(value: Any) -> int:
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        ttl = REPORT_HTTP_DEFAULT_TTL
    return max(30, min(ttl, 3600))


def _ensure_catalog_report_server(
    project: Path,
    report_path: Path,
    *,
    bind: str = "loopback",
    port: int = REPORT_HTTP_PORT,
    ttl: int = REPORT_HTTP_DEFAULT_TTL,
) -> tuple[str | None, str | None]:
    try:
        bind_ip = _catalog_report_bind_ip(project, bind)
        parsed_port = int(port)
    except (TypeError, ValueError) as exc:
        return None, str(exc)
    if not 1024 <= parsed_port <= 65535:
        return None, "Report-Port muss zwischen 1024 und 65535 liegen"
    if not _port_available_for_http(parsed_port, bind_ip):
        return None, f"Port {port} ist bereits durch einen anderen Dienst belegt"

    token = secrets.token_urlsafe(24)
    encoded_token = urllib.parse.quote(token, safe="")
    encoded_name = urllib.parse.quote(report_path.name, safe="")
    health_url = f"http://{bind_ip}:{parsed_port}/health/{encoded_token}"
    report_url = f"http://{bind_ip}:{parsed_port}/report/{encoded_token}/{encoded_name}"
    server_environment = os.environ.copy()
    server_environment["MAVI_REPORT_SERVER_TOKEN"] = token
    try:
        subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "_report-serve",
                "--file",
                str(report_path.resolve()),
                "--bind",
                bind_ip,
                "--port",
                str(parsed_port),
                "--ttl",
                str(_catalog_report_ttl(ttl)),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=server_environment,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        return None, f"Reportserver konnte nicht gestartet werden: {exc}"

    deadline = time.time() + 2.0
    while time.time() < deadline:
        if _report_server_is_ours(health_url):
            return report_url, None
        time.sleep(0.1)

    return None, "Reportserver antwortet nach dem Start nicht"


def cmd_internal_report_serve(args: argparse.Namespace) -> None:
    """Interner, zeitlich begrenzter Einzeldatei-Server ohne Verzeichnislisting."""
    import http.server

    report_path = Path(args.file).resolve()
    bind_ip = _catalog_report_bind_ip(Path.cwd(), str(args.bind))
    port = int(args.port)
    ttl = _catalog_report_ttl(args.ttl)
    token = str(os.environ.pop("MAVI_REPORT_SERVER_TOKEN", "") or "")
    if not token or not report_path.is_file():
        raise SystemExit(2)

    encoded_token = urllib.parse.quote(token, safe="")
    report_route = (
        f"/report/{encoded_token}/"
        f"{urllib.parse.quote(report_path.name, safe='')}"
    )
    health_route = f"/health/{encoded_token}"

    class ReportHandler(http.server.BaseHTTPRequestHandler):
        server_version = "MaviReport/1"

        def _send_body(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _handle(self) -> None:
            route = urllib.parse.urlsplit(self.path).path
            if route == health_route:
                self._send_body(200, REPORT_SERVER_MARKER.encode("ascii"), "text/plain; charset=utf-8")
                return
            if route == report_route:
                try:
                    body = report_path.read_bytes()
                except OSError:
                    self._send_body(404, b"Not found", "text/plain; charset=utf-8")
                    return
                self._send_body(200, body, "text/html; charset=utf-8")
                return
            self._send_body(404, b"Not found", "text/plain; charset=utf-8")

        def do_GET(self) -> None:
            self._handle()

        def do_HEAD(self) -> None:
            self._handle()

        def log_message(self, _format: str, *args: Any) -> None:
            del args

    server = http.server.ThreadingHTTPServer((bind_ip, port), ReportHandler)
    server.timeout = 0.5
    deadline = time.monotonic() + ttl
    try:
        while time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()


def _print_catalog_summary(catalog: dict[str, Any]) -> None:
    type_counts: dict[str, int] = {}
    scope_counts = {"PC": 0, "SYSTEM": 0, "USER": 0, "?": 0}
    for raw_app in catalog.values():
        app = raw_app if isinstance(raw_app, dict) else {}
        app_type = _software_type_label(app)
        type_counts[app_type] = type_counts.get(app_type, 0) + 1
        scope = _software_mode_meta(app)["scope"]
        scope_counts[scope if scope in scope_counts else "?"] += 1
    types = " · ".join(f"{name}: {count}" for name, count in sorted(type_counts.items()))
    print(f"Programme: {len(catalog)}  |  PC: {scope_counts['PC']}  |  SYSTEM: {scope_counts['SYSTEM']}  |  USER: {scope_counts['USER']}")
    print(f"Typen:     {types}")


def cmd_software_list(args: argparse.Namespace) -> None:
    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(args.project, catalog_name)["software_catalog"]
    default_name = get_default_catalog_name(args.project)

    suffix = " [DEFAULT]" if catalog_name == default_name else ""
    print()
    print(f"SOFTWARE-KATALOG · {catalog_name}{suffix}")
    print("=" * min(78, max(32, len(catalog_name) + 22)))

    if not catalog:
        print("Katalog ist leer.")
        return

    print()
    _render_catalog_terminal_table(catalog)
    print()
    _print_catalog_summary(catalog)

    try:
        report_path = _generate_catalog_html_report(
            args.project,
            catalog_name,
            catalog,
            default_name,
        )
        environment_opt_in = str(
            os.environ.get("MAVI_REPORT_HTTP", "") or ""
        ).strip().lower() in {"1", "true", "yes", "on"}
        serve_report = bool(
            getattr(args, "serve_report", False) or environment_opt_in
        )
        report_url: str | None = None
        server_error: str | None = None
        if serve_report:
            report_url, server_error = _ensure_catalog_report_server(
                args.project,
                report_path,
                bind=str(getattr(args, "report_bind", "loopback") or "loopback"),
                port=int(getattr(args, "report_port", REPORT_HTTP_PORT)),
                ttl=int(getattr(args, "report_ttl", REPORT_HTTP_DEFAULT_TTL)),
            )
        print()
        print("HTML-DASHBOARD")
        print("--------------")
        if report_url:
            print(f"Browser-Link: {report_url}")
            print(
                "Hinweis:      Der tokenisierte HTTP-Link ist nur kurzzeitig "
                "verfügbar; HTTP im LAN ist nicht verschlüsselt."
            )
        else:
            print(f"Datei-Link:   {report_path.resolve().as_uri()}")
            if server_error:
                print(f"Hinweis:      {server_error}")
            elif not serve_report:
                print(
                    "Hinweis:      HTTP ist standardmäßig aus. Optional bewusst "
                    "mit --serve-report aktivieren."
                )
        print(f"HTML-Datei:   {report_path}")
    except OSError as exc:
        print()
        print(f"! HTML-Report konnte nicht erzeugt werden: {exc}")


def cmd_software_show(args: argparse.Namespace) -> None:
    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(args.project, catalog_name)["software_catalog"]
    if args.key not in catalog:
        die(f"'{args.key}' ist nicht im Katalog '{catalog_name}'.")

    print(f"Katalog: {catalog_name}\n")
    print(
        redact_sensitive_text(
            yaml.safe_dump(
                {args.key: catalog[args.key]},
                allow_unicode=True,
                sort_keys=False,
            )
        )
    )


def cmd_software_remove(args: argparse.Namespace) -> None:
    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(args.project, catalog_name)

    if args.key not in catalog["software_catalog"]:
        die(f"'{args.key}' ist nicht im Katalog '{catalog_name}'.")

    app = catalog["software_catalog"][args.key]
    label = app.get("name", args.key)

    print()
    print(f"Programm: {label} ({args.key})")
    print(f"Katalog:  {catalog_name}")
    print()
    print(
        "Hinweis: Dadurch wird NUR der Katalogeintrag entfernt. "
        "Auf bereits provisionierten PCs wird nichts deinstalliert."
    )

    if not args.yes and not yes_no(
        f"'{label}' wirklich aus dem Katalog entfernen?",
        False,
    ):
        print("Abgebrochen.")
        return

    del catalog["software_catalog"][args.key]
    save_catalog(args.project, catalog, catalog_name)
    print(
        f"✓ '{label}' ({args.key}) wurde aus "
        f"'{catalog_name}' entfernt."
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


def get_printer_catalog(project: Path) -> dict[str, Any]:
    ensure_initialized(project, quiet=True)
    path = project_paths(project)["printer_catalog"]
    data = load_yaml(path, PRINTER_CATALOG_TEMPLATE) or {}
    if not isinstance(data, dict):
        die(f"Druckerkatalog ist kein gültiges YAML-Dictionary: {path}")
    if "printers" not in data:
        data = {"printers": data}
    if not isinstance(data.get("printers"), dict):
        die(f"'printers' im Druckerkatalog ist kein Dictionary: {path}")
    return data


def save_printer_catalog(project: Path, data: dict[str, Any]) -> None:
    atomic_write_yaml(project_paths(project)["printer_catalog"], data)


def choose_printer_interactive(project: Path) -> str:
    printers = get_printer_catalog(project)["printers"]
    if not printers:
        die("Keine Drucker im Druckerkatalog vorhanden.")
    items: list[tuple[str, str]] = []
    for key, cfg in printers.items():
        cfg = cfg or {}
        label = f"{cfg.get('name', key)}  [{cfg.get('ip', '?')}]"
        items.append((key, label))
    return select_from_list("Drucker auswählen", items, allow_name=True)


def cmd_printer_add(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)
    catalog = get_printer_catalog(args.project)
    printers = catalog["printers"]

    name = getattr(args, "name", None) or prompt("Druckername auf Windows")
    key_default = slugify(name)
    if key_default == "software":
        key_default = "drucker"
    key = getattr(args, "key", None) or prompt("Drucker-Schlüssel", key_default)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
        die("Drucker-Schlüssel enthält ungültige Zeichen.")

    ip_raw = getattr(args, "ip", None) or prompt("Drucker IPv4-Adresse")
    try:
        parsed_ip = ipaddress.ip_address(ip_raw)
    except ValueError:
        die(f"Ungültige IP-Adresse: {ip_raw}")
    if parsed_ip.version != 4:
        die("Aktuell werden nur IPv4-TCP/IP-Drucker unterstützt.")
    printer_ip = str(parsed_ip)

    inf_path, selected_driver_dir = resolve_printer_driver_source(args, config)
    print()
    print(f"Gewählte Treiber-INF: {inf_path}")

    (
        package_root,
        missing_package_files,
        packed_package_files,
        referenced_package_files,
    ) = choose_driver_package_root(inf_path, config)

    if referenced_package_files:
        resolved_count = len(referenced_package_files) - len(missing_package_files)
        print()
        print(
            f"Treiberpaket-Prüfung: {resolved_count} von "
            f"{len(referenced_package_files)} referenzierten Datei(en) auflösbar."
        )
        if packed_package_files:
            print(
                f"  ✓ {len(packed_package_files)} Payload-Datei(en) liegen laut INF "
                "in vorhandenen CAB-Archiven."
            )
        print(f"Ermittelter Paketordner: {package_root}")

    if missing_package_files:
        print()
        print("! Das Treiberpaket wirkt UNVOLLSTÄNDIG.")
        print("  Die INF referenziert Dateien, die im Paketordner nicht gefunden wurden:")
        for missing_name in missing_package_files[:20]:
            print(f"    - {missing_name}")
        if len(missing_package_files) > 20:
            print(f"    ... und {len(missing_package_files) - 20} weitere")
        print()
        print(
            "  Bitte den VOLLSTÄNDIG entpackten Hersteller-Treiber verwenden, "
            "nicht nur die einzelne INF-Datei."
        )
        force_incomplete = bool(getattr(args, "yes", False))
        if not force_incomplete:
            if not sys.stdin.isatty() or not yes_no(
                "Unvollständiges Paket trotzdem in den Katalog übernehmen?",
                False,
            ):
                die("Drucker wurde wegen unvollständigem Treiberpaket nicht gespeichert.")

    driver_name = getattr(args, "driver_name", None)
    if not driver_name:
        driver_name = _choose_driver_name_from_inf(inf_path)
    driver_name = str(driver_name).strip()
    if not driver_name:
        die("Windows-Treibername darf nicht leer sein.")

    port_number = int(getattr(args, "port_number", 9100) or 9100)
    if not 1 <= port_number <= 65535:
        die("Portnummer muss zwischen 1 und 65535 liegen.")

    port_name = getattr(args, "port_name", None) or f"IP_{printer_ip}"

    if key in printers and not bool(getattr(args, "yes", False)):
        if not sys.stdin.isatty():
            die(f"Drucker '{key}' existiert bereits. Mit --yes überschreiben.")
        if not yes_no(f"Drucker '{key}' existiert bereits. Überschreiben?", False):
            print("Abgebrochen.")
            return

    try:
        inf_relative = inf_path.resolve().relative_to(package_root.resolve()).as_posix()
    except ValueError:
        inf_relative = inf_path.name

    printers[key] = {
        "name": name,
        "ip": printer_ip,
        "port_name": port_name,
        "port_number": port_number,
        "driver_name": driver_name,
        "driver_inf": str(inf_path),
        "driver_source_dir": str(selected_driver_dir or inf_path.parent),
        "driver_package_dir": str(package_root),
        "driver_inf_relative": inf_relative,
    }
    save_printer_catalog(args.project, catalog)

    print()
    print(f"✓ Drucker '{key}' gespeichert.")
    print(f"  Name:       {name}")
    print(f"  IP/Port:    {printer_ip}:{port_number}")
    print(f"  TCP-Port:   {port_name}")
    print(f"  Treiber:    {driver_name}")
    print(f"  INF:        {inf_path}")
    print(f"  Paketordner:{package_root}")
    print(f"  INF relativ:{inf_relative}")


def cmd_printer_list(args: argparse.Namespace) -> None:
    printers = get_printer_catalog(args.project)["printers"]
    if not printers:
        print("Keine Drucker im Druckerkatalog.")
        return

    print(f"{'KEY':<24} {'NAME':<30} {'IP':<16} TREIBER")
    print("-" * 105)
    for key, cfg in printers.items():
        cfg = cfg or {}
        print(
            f"{key:<24} "
            f"{str(cfg.get('name', key)):<30} "
            f"{str(cfg.get('ip', '')):<16} "
            f"{cfg.get('driver_name', '')}"
        )


def cmd_printer_show(args: argparse.Namespace) -> None:
    printers = get_printer_catalog(args.project)["printers"]
    if args.key not in printers:
        die(f"Drucker '{args.key}' ist nicht im Druckerkatalog.")
    print(
        yaml.safe_dump(
            {args.key: printers[args.key]},
            allow_unicode=True,
            sort_keys=False,
        )
    )


def cmd_printer_remove(args: argparse.Namespace) -> None:
    catalog = get_printer_catalog(args.project)
    printers = catalog["printers"]
    if args.key not in printers:
        die(f"Drucker '{args.key}' ist nicht im Druckerkatalog.")

    if not bool(getattr(args, "yes", False)) and not yes_no(
        f"Drucker '{args.key}' wirklich nur aus dem Katalog entfernen?",
        False,
    ):
        print("Abgebrochen.")
        return

    del printers[args.key]
    save_printer_catalog(args.project, catalog)
    print(f"✓ Drucker '{args.key}' aus dem Katalog entfernt.")
    print("  Auf bereits eingerichteten PCs wurde nichts entfernt.")


def cmd_printer_install(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    p = project_paths(args.project)
    catalog = get_printer_catalog(args.project)
    printers = catalog["printers"]

    inv = load_inventory(args.project)
    windows = ensure_windows_tree(inv)
    hosts = windows.get("hosts", {}) or {}
    if args.host not in hosts:
        die(f"Host '{args.host}' ist nicht im Windows-Inventory vorhanden.")

    requested = list(getattr(args, "printers", []) or [])
    install_all = bool(getattr(args, "all", False))
    if install_all:
        if not printers:
            die("Druckerkatalog ist leer.")
        requested = []
    elif not requested:
        die("Drucker-Schlüssel angeben oder --all verwenden.")
    else:
        missing = [key for key in requested if key not in printers]
        if missing:
            die("Nicht im Druckerkatalog: " + ", ".join(missing))

    extra = {
        "printer_catalog_file": str(p["printer_catalog"]),
        "install_all_printers": install_all,
        "printer_names": requested,
        # Unbekannten Publisher niemals in einem unbeaufsichtigten Lauf blind vertrauen.
        # Interaktiv darf das Ansible-Playbook Subject/Issuer/Thumbprint anzeigen
        # und explizit nach einer Freigabe fragen.
        "printer_prompt_publisher_trust": bool(sys.stdin.isatty()),
    }

    selected = list(printers.keys()) if install_all else requested

    # Lokaler Treiber-Preflight, bevor wir hunderte MB auf den Ziel-PC kopieren.
    # Gleichzeitig migriert v0.8.17-Einträge auf Paket-Root + relativen INF-Pfad.
    config = get_config(args.project)
    catalog_changed = False
    print()
    print("Mavi DRUCKER-PREFLIGHT")
    print("=====================")
    for key in selected:
        cfg = printers[key] or {}
        inf_raw = str(cfg.get("driver_inf") or "").strip()
        if not inf_raw:
            die(f"Drucker '{key}' hat keine driver_inf im Katalog.")
        inf_path = Path(inf_raw)
        if not inf_path.exists() or not inf_path.is_file():
            die(f"Drucker '{key}': Treiber-INF fehlt lokal: {inf_path}")

        package_root, missing_files, packed_files, referenced_files = choose_driver_package_root(
            inf_path, config
        )
        if missing_files:
            print(f"\n! {key}: Treiberpaket ist unvollständig.")
            print(
                f"  {len(referenced_files) - len(missing_files)} von "
                f"{len(referenced_files)} referenzierten Datei(en) auflösbar."
            )
            for missing_name in missing_files[:20]:
                print(f"    FEHLT: {missing_name}")
            if len(missing_files) > 20:
                print(f"    ... und {len(missing_files) - 20} weitere")
            die(
                "Druckerinstallation abgebrochen. Vollständig entpackten "
                f"Treiberordner für '{key}' bereitstellen und Drucker neu hinzufügen."
            )

        try:
            inf_relative = inf_path.resolve().relative_to(
                package_root.resolve()
            ).as_posix()
        except ValueError:
            inf_relative = inf_path.name

        if str(cfg.get("driver_package_dir") or "") != str(package_root):
            cfg["driver_package_dir"] = str(package_root)
            catalog_changed = True
        if str(cfg.get("driver_inf_relative") or "") != inf_relative:
            cfg["driver_inf_relative"] = inf_relative
            catalog_changed = True

        driver_name = str(cfg.get("driver_name") or "").strip()
        candidates = find_inf_driver_name_candidates(inf_path, driver_name)
        exact = [x for x in candidates if x.casefold() == driver_name.casefold()]
        if not exact and driver_name:
            contained = [
                x for x in candidates
                if driver_name.casefold() in x.casefold()
            ]
            if len(contained) == 1:
                old_name = driver_name
                driver_name = contained[0]
                cfg["driver_name"] = driver_name
                catalog_changed = True
                print(
                    f"  {key}: Treibername präzisiert: "
                    f"'{old_name}' -> '{driver_name}'"
                )

        if referenced_files:
            found_text = f"{len(referenced_files)} Referenz(en) geprüft"
            if packed_files:
                found_text += f", davon {len(packed_files)} in CAB"
        else:
            found_text = "keine SourceDisksFiles-Liste in INF"
        print(
            f"  ✓ {key}: {found_text} | Paket: {package_root.name} | "
            f"Treiber: {cfg.get('driver_name')}"
        )

    if catalog_changed:
        save_printer_catalog(args.project, catalog)
        print("  ✓ Druckerkatalog automatisch auf aktuelle Drucker-Metadaten aktualisiert.")

    print()
    print("Mavi DRUCKERPLAN")
    print("================")
    for index, key in enumerate(selected, 1):
        cfg = printers[key]
        print(
            f"  {index:02d}. {key}: {cfg.get('name', key)} | "
            f"{cfg.get('ip')}:{cfg.get('port_number', 9100)} | "
            f"{cfg.get('driver_name')}"
        )

    cmd = [
        "ansible-playbook",
        "-i",
        str(p["inventory"]),
        str(p["printer_playbook"]),
        "--limit",
        args.host,
        "--ask-vault-pass",
        "-e",
        json.dumps(extra, ensure_ascii=False),
    ]
    raise SystemExit(run_subprocess(cmd, args.project))


def printer_menu(project: Path) -> None:
    while True:
        print()
        print("DRUCKER")
        print("=======")
        print("  1) TCP/IP-Drucker + Treiberordner zum Katalog hinzufügen")
        print("  2) Druckerkatalog anzeigen")
        print("  3) Einen Drucker auf PC installieren")
        print("  4) ALLE Drucker auf PC installieren")
        print("  5) Drucker aus Katalog entfernen")
        print("  0) Zurück")
        print()

        choice = input("> ").strip()
        if choice == "1":
            cmd_printer_add(
                argparse.Namespace(
                    project=project,
                    name=None,
                    key=None,
                    ip=None,
                    driver_dir=None,
                    driver_inf=None,
                    driver_name=None,
                    port_name=None,
                    port_number=9100,
                    yes=False,
                )
            )
        elif choice == "2":
            cmd_printer_list(argparse.Namespace(project=project))
        elif choice in {"3", "4"}:
            host = choose_host_interactive(project)
            if choice == "3":
                key = choose_printer_interactive(project)
                selected = [key]
                all_ = False
            else:
                selected = []
                all_ = True
            try:
                cmd_printer_install(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        printers=selected,
                        all=all_,
                    )
                )
            except SystemExit as exc:
                if exc.code not in (0, None):
                    print(f"\nDruckerinstallation beendet mit Code {exc.code}.")
        elif choice == "5":
            key = choose_printer_interactive(project)
            cmd_printer_remove(
                argparse.Namespace(project=project, key=key, yes=False)
            )
        elif choice == "0":
            return
        else:
            print("Ungültige Auswahl.")



def get_ssh_settings(project: Path) -> dict[str, Any]:
    """Mavi-SSH-Einstellungen laden, ohne bestehende Projekte zu verbiegen."""
    p = project_paths(project)
    config = load_yaml(p["config"], {}) or {}
    ssh_cfg = config.get("ssh", {}) or {}

    raw_key = str(ssh_cfg.get("private_key", "") or "").strip()
    key_path = Path(raw_key).expanduser() if raw_key else p["ssh_key"]

    try:
        port = int(ssh_cfg.get("port", 22) or 22)
    except (TypeError, ValueError):
        port = 22

    if not 1 <= port <= 65535:
        port = 22

    raw_known_hosts = str(ssh_cfg.get("known_hosts", "") or "").strip()
    known_hosts = Path(raw_known_hosts).expanduser() if raw_known_hosts else p["ssh_known_hosts"]

    return {
        "private_key": key_path,
        "public_key": Path(str(key_path) + ".pub"),
        "known_hosts": known_hosts,
        "port": port,
    }


def _ssh_environment_marker(project: Path) -> str:
    """Stable project-scoped marker; never matches keys from another project."""
    project_identity = str(project.expanduser().resolve()).casefold().encode("utf-8")
    digest = hashlib.sha256(project_identity).hexdigest()[:16]
    return f"mavi-provisioner-{digest}"


def _host_inventory_entry(project: Path, host: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    inv = load_inventory(project)
    windows = ensure_windows_tree(inv)
    hosts = windows.get("hosts", {}) or {}
    if host not in hosts:
        die(f"PC '{host}' ist nicht im Inventory vorhanden.")
    data = hosts[host] or {}
    if not isinstance(data, dict):
        data = {}
        hosts[host] = data
    return inv, windows, data


def _effective_host_var(windows: dict[str, Any], host_data: dict[str, Any], key: str, default: Any = None) -> Any:
    if key in host_data:
        return host_data.get(key)
    return (windows.get("vars", {}) or {}).get(key, default)


def _connection_label(windows: dict[str, Any], host_data: dict[str, Any]) -> str:
    connection = str(_effective_host_var(windows, host_data, "ansible_connection", "psrp") or "psrp").lower()
    if connection == "ssh":
        return "SSH"
    if connection == "winrm":
        return "WinRM"
    if connection == "psrp":
        return "PSRP"
    return connection.upper()


def _clear_host_transport_vars(host_data: dict[str, Any]) -> None:
    for key in (
        "ansible_connection",
        "ansible_port",
        "ansible_shell_type",
        "ansible_ssh_private_key_file",
        "ansible_ssh_common_args",
        "ansible_ssh_host_key_checking",
        "ansible_ssh_password_mechanism",
        "ansible_password",
        "ansible_ssh_pass",
        "ansible_ssh_password",
        "ansible_psrp_protocol",
        "ansible_psrp_auth",
        "ansible_psrp_cert_validation",
        "ansible_psrp_ca_cert",
        "ansible_psrp_cert_trust_path",
        "ansible_psrp_message_encryption",
        "ansible_psrp_ignore_proxy",
        "ansible_psrp_negotiate_hostname_override",
        "ansible_psrp_negotiate_service",
        "ansible_psrp_negotiate_send_cbt",
    ):
        host_data.pop(key, None)


def _apply_ssh_transport(
    project: Path,
    host_data: dict[str, Any],
    *,
    key_path: Path | None = None,
    port: int | None = None,
) -> tuple[Path, int]:
    settings = get_ssh_settings(project)
    resolved_key = (key_path or settings["private_key"]).expanduser().resolve()
    resolved_port = int(port or settings["port"] or 22)
    if not 1 <= resolved_port <= 65535:
        die("SSH-Port muss zwischen 1 und 65535 liegen.")

    _clear_host_transport_vars(host_data)
    known_hosts = Path(settings["known_hosts"]).expanduser().resolve()

    host_data["ansible_connection"] = "ssh"
    host_data["ansible_shell_type"] = "powershell"
    host_data["ansible_port"] = resolved_port
    host_data["ansible_ssh_private_key_file"] = str(resolved_key)

    # SSH muss bei Mavi wirklich Key-only sein. Der Windows-Gruppenbereich enthält
    # häufig ein geerbtes/vaulted ansible_password für PSRP. Ohne expliziten
    # Host-Override interpretiert das SSH-Plugin dieses Passwort ebenfalls als
    # SSH-Passwort und startet den Passwortmechanismus statt sauber nur den Key
    # zu verwenden. Leere SSH-Password-Aliase überschreiben das Gruppenpasswort
# für diesen Host; beim Wechsel auf den verifizierten PSRP-HTTPS-Endpunkt werden
# sie wieder entfernt.
    host_data["ansible_password"] = ""
    host_data["ansible_ssh_pass"] = ""
    host_data["ansible_ssh_password"] = ""

    # Host-Key-Prüfung bleibt absichtlich aktiv. Mavi verwendet eine eigene
    # known_hosts-Datei, damit keine globale ~/.ssh-Konfiguration verändert wird.
    host_data["ansible_ssh_host_key_checking"] = True
    host_data["ansible_ssh_common_args"] = (
        f"-o UserKnownHostsFile={shlex_quote(str(known_hosts))} "
        "-o StrictHostKeyChecking=yes -o IdentitiesOnly=yes"
    )
    host_data.pop("mavi_remote_management_disabled", None)
    return resolved_key, resolved_port


def _apply_psrp_transport(host_data: dict[str, Any]) -> None:
    """Legacy-Transport absichtlich sperren: Mavi erzeugt kein HTTP/NTLM mehr."""
    del host_data
    die(
        "PSRP über HTTP/5985 mit NTLM ist in Mavi v0.8.48 deaktiviert. "
        "Zuerst OpenSSH einrichten und danach 'mavi-provisioner ssh winrm-https <HOST>' verwenden."
    )


def _psrp_https_inventory_vars(
    settings: dict[str, Any],
    *,
    fqdn: str,
    ca_cert: Path,
) -> dict[str, Any]:
    """Nur sichere PSRP-Variablen für einen einzelnen Windows-Host erzeugen."""
    return {
        "ansible_connection": "psrp",
        "ansible_port": int(settings["port"]),
        "ansible_psrp_protocol": "https",
        "ansible_psrp_auth": str(settings["auth"]),
        "ansible_psrp_cert_validation": "validate",
        "ansible_psrp_ca_cert": str(ca_cert.resolve()),
        "ansible_psrp_message_encryption": str(settings["message_encryption"]),
        # PSRP darf für den internen Verwaltungsverkehr nie einen Proxy
        # verwenden. Die TLS-Verbindung geht direkt zum Inventory-Host.
        "ansible_psrp_ignore_proxy": True,
        # Bei Inventory-IP bleibt der Kerberos-SPN trotzdem der echte FQDN.
        "ansible_psrp_negotiate_hostname_override": fqdn,
        # Ansible-core 2.21 verwendet zwar bereits `host` als Standard. Mavi
        # speichert ihn trotzdem explizit, damit der vorgeschaltete
        # Kerberos-Dienstticketnachweis exakt denselben SPN verwendet.
        "ansible_psrp_negotiate_service": "host",
        # Explizit setzen, damit der Schutz auch bei älteren Defaultwerten gilt.
        "ansible_psrp_negotiate_send_cbt": True,
    }


def _apply_psrp_https_transport(
    host_data: dict[str, Any],
    *,
    settings: dict[str, Any],
    fqdn: str,
    ca_cert: Path,
    kerberos_principal: str = "",
) -> None:
    """Host erst nach positiver HTTPS-Prüfung dauerhaft auf PSRP TLS umstellen."""
    # Ein eventuell host-spezifisch in Vault hinterlegtes PSRP-Passwort darf
    # beim Transportwechsel nicht verloren gehen. SSH-Leerwerte werden nur
    # übernommen, wenn sie zuvor tatsächlich gesetzt waren.
    preserved_credentials = {
        key: host_data[key]
        for key in (
            "ansible_password",
            "ansible_psrp_password",
            "ansible_winrm_pass",
            "ansible_winrm_password",
        )
        if key in host_data and str(host_data[key] or "").strip()
    }
    _clear_host_transport_vars(host_data)
    host_data.update(preserved_credentials)
    host_data.update(_psrp_https_inventory_vars(settings, fqdn=fqdn, ca_cert=ca_cert))
    host_data.pop("mavi_remote_management_disabled", None)
    if kerberos_principal:
        host_data["ansible_user"] = kerberos_principal


def _remember_winrm_https_state(
    host_data: dict[str, Any],
    *,
    settings: dict[str, Any],
    fqdn: str,
    ca_cert: Path,
    kerberos_principal: str,
) -> None:
    """Nur nach doppeltem Kerberos-Nachweis persistierte Transport-Metadaten."""
    host_data["mavi_winrm_https"] = {
        "version": 1,
        "kerberos_verified": True,
        "auth": "kerberos",
        "fqdn": fqdn,
        "port": int(settings["port"]),
        "kerberos_principal": kerberos_principal,
        "ca_sha256": _sha256_file(ca_cert).lower(),
    }


def _saved_winrm_https_transport(
    project: Path,
    host_data: dict[str, Any],
) -> tuple[dict[str, Any], str, Path, str]:
    """Gespeicherte Kerberos-HTTPS-Endstufe eng prüfen, nie raten oder downgraden."""
    state = host_data.get("mavi_winrm_https")
    if not isinstance(state, dict) or state.get("kerberos_verified") is not True:
        raise ValueError(
            "Für diesen Host ist kein erfolgreich geprüfter Mavi-WinRM-HTTPS/Kerberos-Endzustand gespeichert. "
            "HTTP/NTLM wird nicht als Ersatz aktiviert."
        )
    settings = _winrm_https_settings(project)
    if str(state.get("auth", "")).strip().lower() != "kerberos":
        raise ValueError("Der gespeicherte WinRM-Status ist nicht Kerberos-only und wird nicht verwendet.")
    try:
        saved_port = int(state.get("port"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Der gespeicherte WinRM-HTTPS-Port ist ungültig.") from exc
    if saved_port != int(settings["port"]):
        raise ValueError(
            "Der gespeicherte WinRM-HTTPS-Port passt nicht zur aktuellen Mavi-Konfiguration. "
            "Mavi schaltet nicht still auf einen anderen Transport um."
        )
    fqdn = _normalize_winrm_dns_name(str(state.get("fqdn", "") or ""), label="gespeicherter WinRM-FQDN")
    suffix = "." + str(settings["domain_suffix"])
    if not fqdn.endswith(suffix) or fqdn == str(settings["domain_suffix"]):
        raise ValueError("Der gespeicherte WinRM-FQDN liegt nicht in der Mavi-Domäne.")
    ca_cert = _winrm_pki_paths(project)["ca_cert"]
    if not ca_cert.is_file():
        raise ValueError("Die lokale Mavi-WinRM-CA fehlt; Mavi ersetzt eine Vertrauenswurzel niemals still.")
    expected_hash = str(state.get("ca_sha256", "") or "").lower()
    actual_hash = _sha256_file(ca_cert).lower()
    if not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or not secrets.compare_digest(expected_hash, actual_hash):
        raise ValueError("Die lokale Mavi-WinRM-CA stimmt nicht mit dem geprüften Host-Status überein.")
    kerberos_principal = str(state.get("kerberos_principal", "") or "").strip()
    if not kerberos_principal:
        raise ValueError("Der geprüfte Kerberos-Principal für diesen Host fehlt.")
    return settings, fqdn, ca_cert, kerberos_principal


def _apply_saved_winrm_https_transport(project: Path, host_data: dict[str, Any]) -> None:
    """Inventory ausschließlich auf einen zuvor verifizierten Kerberos-TLS-Transport umstellen."""
    settings, fqdn, ca_cert, kerberos_principal = _saved_winrm_https_transport(project, host_data)
    _apply_psrp_https_transport(
        host_data,
        settings=settings,
        fqdn=fqdn,
        ca_cert=ca_cert,
        kerberos_principal=kerberos_principal,
    )


def _normalize_winrm_dns_name(value: str, *, label: str) -> str:
    """DNS-Namen für Zertifikate und Kerberos-Overrides eng validieren."""
    raw = str(value or "").strip().rstrip(".")
    if not raw or len(raw) > 253 or any(ord(char) < 33 or ord(char) == 127 for char in raw):
        raise ValueError(f"{label} fehlt oder enthält ungültige Zeichen.")
    try:
        normalized = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"{label} ist kein gültiger DNS-Name.") from exc
    labels = normalized.split(".")
    if any(
        not item
        or len(item) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", item)
        for item in labels
    ):
        raise ValueError(f"{label} ist kein gültiger DNS-Name.")
    return normalized


def _winrm_https_settings(project: Path) -> dict[str, Any]:
    """Zentrale, sichere PSRP-HTTPS-Konfiguration laden und prüfen."""
    config = get_config(project)
    raw = config.get("winrm_https", {}) or {}
    if not isinstance(raw, dict):
        raise ValueError("winrm_https muss ein Konfigurationsobjekt sein.")

    suffix = _normalize_winrm_dns_name(
        str(raw.get("domain_suffix", "") or ""),
        label="winrm_https.domain_suffix",
    )
    if "." not in suffix:
        raise ValueError("winrm_https.domain_suffix muss eine Domäne wie example.invalid sein.")

    try:
        port = int(raw.get("port", 5986) or 5986)
    except (TypeError, ValueError) as exc:
        raise ValueError("winrm_https.port muss eine gültige TCP-Portnummer sein.") from exc
    if port != 5986:
        raise ValueError(
            "winrm_https.port muss 5986 sein. Mavi verwendet den dokumentierten "
            "WinRM-HTTPS-Standardport und erstellt keinen abweichenden Listener."
        )

    auth = str(raw.get("auth", "kerberos") or "kerberos").strip().lower()
    if auth != "kerberos":
        raise ValueError(
            "winrm_https.auth muss 'kerberos' sein. Mavi aktiviert weder "
            "Negotiate- noch NTLM-Fallbacks."
        )
    message_encryption = str(raw.get("message_encryption", "always") or "always").strip().lower()
    if message_encryption not in {"auto", "always"}:
        raise ValueError("winrm_https.message_encryption darf nur auto oder always sein.")
    kerberos_principal = str(raw.get("kerberos_principal", "") or "").strip()
    if kerberos_principal and (
        any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in kerberos_principal)
        or kerberos_principal.count("@") != 1
    ):
        raise ValueError("winrm_https.kerberos_principal muss ein einzelner UPN wie admin@example.invalid sein.")
    kerberos_dns_server = str(raw.get("kerberos_dns_server", "") or "").strip()
    if kerberos_dns_server:
        try:
            parsed_dns_server = ipaddress.ip_address(kerberos_dns_server)
        except ValueError as exc:
            raise ValueError("winrm_https.kerberos_dns_server muss eine einzelne DNS-Server-IP sein.") from exc
        if (
            parsed_dns_server.is_unspecified
            or parsed_dns_server.is_multicast
            or parsed_dns_server.is_link_local
        ):
            raise ValueError("winrm_https.kerberos_dns_server darf keine Sonder- oder Link-Local-IP sein.")
        kerberos_dns_server = str(parsed_dns_server)
    if raw.get("disable_http_after_verified") is False:
        raise ValueError(
            "disable_http_after_verified darf nicht false sein: Mavi behält keinen HTTP/NTLM-Rückweg."
        )

    return {
        "domain_suffix": suffix,
        "port": port,
        "auth": auth,
        "kerberos_principal": kerberos_principal,
        "kerberos_dns_server": kerberos_dns_server,
        "message_encryption": message_encryption,
        "disable_http_after_verified": True,
    }


def _kerberos_runtime_config_path(project: Path) -> Path:
    """Den festen, nicht systemweiten KRB5-Pfad eines Mavi-Projekts liefern."""
    return project_paths(project)["kerberos_runtime_dir"] / "krb5.conf"


def _normalize_kerberos_dns_server(value: str) -> str | None:
    """Eine für direkte AD-DNS-Abfragen sichere Resolver-IP normalisieren."""
    raw = str(value or "").strip().strip("[]")
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if (
        parsed.is_unspecified
        or parsed.is_multicast
        or parsed.is_link_local
    ):
        return None
    return str(parsed)


def _configured_kerberos_dns_servers(settings: dict[str, Any]) -> list[str]:
    """Echte Controller-DNS-Server ohne DNS-Suchpfad-Mehrdeutigkeit ermitteln."""
    candidates: list[tuple[int, int, str]] = []
    seen: set[str] = set()
    sequence = 0

    def add(raw_value: str, priority: int) -> None:
        nonlocal sequence
        server = _normalize_kerberos_dns_server(raw_value)
        if not server or server in seen:
            return
        parsed = ipaddress.ip_address(server)
        # Ein lokaler Stub kann ein sinnvoller Fallback sein, darf aber einen
        # echten Link-/Global-Resolver aus resolvectl nie verdrängen.
        if parsed.is_loopback:
            priority += 100
        seen.add(server)
        sequence += 1
        candidates.append((priority, sequence, server))

    configured = str(settings.get("kerberos_dns_server", "") or "").strip()
    if configured:
        add(configured, 0)

    resolvectl = shutil.which("resolvectl")
    if resolvectl:
        try:
            result = subprocess.run(
                [resolvectl, "dns"],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None:
            resolver_output = (result.stdout or "") + "\n" + (result.stderr or "")
            for token in re.findall(r"[0-9A-Fa-f:.%]+", resolver_output):
                add(token, 10)

    resolv_conf = Path("/etc/resolv.conf")
    try:
        for line in resolv_conf.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"^\s*nameserver\s+(\S+)", line, flags=re.IGNORECASE)
            if match:
                add(match.group(1), 20)
    except OSError:
        pass

    return [server for _, _, server in sorted(candidates)]


def _direct_dns_query(
    dig_executable: str,
    dns_server: str,
    query_name: str,
    record_type: str,
) -> list[str]:
    """Eine kurze, shell-freie DNS-Abfrage direkt an einen vertrauten Resolver senden."""
    try:
        result = subprocess.run(
            [
                dig_executable,
                f"@{dns_server}",
                "+time=2",
                "+tries=1",
                "+short",
                query_name,
                record_type,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    return [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]


def _discover_kerberos_kdc_endpoints(settings: dict[str, Any]) -> tuple[str, ...]:
    """AD-KDCs via SRV und A direkt am tatsächlich konfigurierten DNS auflösen."""
    domain = _normalize_winrm_dns_name(
        str(settings.get("domain_suffix", "") or ""),
        label="winrm_https.domain_suffix",
    )
    dig_executable = shutil.which("dig")
    if not dig_executable:
        raise RuntimeError(
            "Für die sichere direkte AD-KDC-Ermittlung fehlt 'dig' auf dem Controller. "
            "Mavi aktiviert ohne bestätigten KDC keinen WinRM-Kerberos-Transport."
        )
    dns_servers = _configured_kerberos_dns_servers(settings)
    if not dns_servers:
        raise RuntimeError(
            "Kein verwendbarer DNS-Server für die direkte AD-KDC-Ermittlung gefunden. "
            "Mavi aktiviert ohne bestätigten KDC keinen WinRM-Kerberos-Transport."
        )

    srv_records: list[tuple[int, int, int, str, int, str]] = []
    for resolver_index, dns_server in enumerate(dns_servers):
        for service in ("_kerberos._tcp", "_kerberos._udp"):
            query_name = f"{service}.{domain}"
            for line in _direct_dns_query(dig_executable, dns_server, query_name, "SRV"):
                parts = line.split()
                if len(parts) != 4:
                    continue
                try:
                    priority = int(parts[0])
                    weight = int(parts[1])
                    port = int(parts[2])
                except ValueError:
                    continue
                if not (0 <= priority <= 65535 and 0 <= weight <= 65535 and 1 <= port <= 65535):
                    continue
                try:
                    target = _normalize_winrm_dns_name(parts[3], label="AD-KDC aus DNS-SRV")
                except ValueError:
                    continue
                if target == domain or not target.endswith("." + domain):
                    continue
                srv_records.append((priority, -weight, resolver_index, target, port, dns_server))

    endpoints: list[str] = []
    seen_endpoints: set[str] = set()
    for _, _, _, target, port, dns_server in sorted(srv_records):
        for answer in _direct_dns_query(dig_executable, dns_server, target, "A"):
            try:
                address = ipaddress.ip_address(answer)
            except ValueError:
                continue
            if (
                address.version != 4
                or address.is_unspecified
                or address.is_multicast
                or address.is_loopback
                or address.is_link_local
            ):
                continue
            endpoint = str(address) if port == 88 else f"{address}:{port}"
            if endpoint not in seen_endpoints:
                seen_endpoints.add(endpoint)
                endpoints.append(endpoint)

    if not endpoints:
        raise RuntimeError(
            "Der AD-DNS lieferte keinen verwendbaren IPv4-KDC für "
            f"{domain}. Mavi aktiviert WinRM-Kerberos ohne bestätigten KDC nicht."
        )
    return tuple(endpoints)


def _activate_existing_kerberos_runtime_config(project: Path) -> Path | None:
    """Vorhandene Mavi-Kerberos-Konfiguration nur für diesen Mavi-Prozess binden."""
    path = _kerberos_runtime_config_path(project)
    if not path.is_file():
        return None
    # KRB5_CONFIG wird nur in diesem Python-Prozess und dessen Kindern gesetzt;
    # die Login-Shell, /etc/krb5.conf und sonstige Programme bleiben unverändert.
    os.environ["KRB5_CONFIG"] = str(path)
    return path


def _prepare_kerberos_runtime_config(
    project: Path,
    settings: dict[str, Any],
) -> tuple[Path, tuple[str, ...]]:
    """Eine restriktive KRB5-Konfiguration mit direkt bestätigten AD-KDCs schreiben."""
    domain = _normalize_winrm_dns_name(
        str(settings.get("domain_suffix", "") or ""),
        label="winrm_https.domain_suffix",
    )
    if "." not in domain:
        raise ValueError("winrm_https.domain_suffix muss eine AD-Domäne wie example.invalid sein.")

    # Kerberos-Realm-Namen sind konventionsgemäß großgeschrieben. Der direkte
    # SRV-Lookup erfolgt hier einmal an den echten AD-DNS-Server; danach nutzt
    # der Ansible-Worker nur numerisch bestätigte KDC-Endpunkte und hängt nicht
    # an einem fehlerhaften lokalen Resolver-/Stub-Pfad.
    realm = domain.upper()
    kdc_endpoints = _discover_kerberos_kdc_endpoints(settings)
    path = _kerberos_runtime_config_path(project)
    kdc_lines = "".join(f"        kdc = {endpoint}\n" for endpoint in kdc_endpoints)
    content = (
        "# Mavi-managed Kerberos runtime configuration; contains no secrets.\n"
        "# Used only by Mavi and its child processes; never copied to /etc.\n"
        "[libdefaults]\n"
        f"    default_realm = {realm}\n"
        "    dns_lookup_kdc = false\n"
        "    dns_lookup_realm = false\n"
        "    rdns = false\n"
        "\n"
        "[realms]\n"
        f"    {realm} = {{\n"
        f"{kdc_lines}"
        "    }\n"
        "\n"
        "[domain_realm]\n"
        f"    {domain} = {realm}\n"
        f"    .{domain} = {realm}\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)
    _atomic_write_bytes(path, content.encode("utf-8"), mode=0o600)
    os.environ["KRB5_CONFIG"] = str(path)
    return path, kdc_endpoints


def _winrm_https_target_identity(
    host: str,
    host_data: dict[str, Any],
    settings: dict[str, Any],
) -> dict[str, Any]:
    """FQDN und SANs aus dem vorhandenen Inventory-Host sicher ableiten."""
    raw_host = str(host or "").strip().rstrip(".")
    if not raw_host:
        raise ValueError("Der Inventory-Hostname für WinRM HTTPS fehlt.")
    base_label = raw_host.split(".", 1)[0]
    short_name = _normalize_winrm_dns_name(base_label, label="Windows-Computername")

    configured_fqdn = str(host_data.get("mavi_winrm_fqdn", "") or "").strip()
    if configured_fqdn:
        fqdn = _normalize_winrm_dns_name(configured_fqdn, label="mavi_winrm_fqdn")
    elif "." in raw_host:
        fqdn = _normalize_winrm_dns_name(raw_host, label="Inventory-Hostname")
    else:
        fqdn = f"{short_name}.{settings['domain_suffix']}"

    suffix = "." + str(settings["domain_suffix"])
    if not fqdn.endswith(suffix) or fqdn == str(settings["domain_suffix"]):
        raise ValueError(
            f"WinRM-FQDN '{fqdn}' liegt nicht in der konfigurierten Domäne {settings['domain_suffix']}."
        )

    endpoint = str(host_data.get("ansible_host", "") or host).strip().rstrip(".")
    if not endpoint:
        raise ValueError("ansible_host fehlt für den Windows-PC.")

    dns_sans: list[str] = []
    ip_sans: list[str] = []
    for name in (fqdn, short_name):
        if name not in dns_sans:
            dns_sans.append(name)
    try:
        parsed_endpoint = ipaddress.ip_address(endpoint)
    except ValueError:
        endpoint_dns = _normalize_winrm_dns_name(endpoint, label="ansible_host")
        if endpoint_dns not in dns_sans:
            dns_sans.append(endpoint_dns)
    else:
        if (
            parsed_endpoint.is_unspecified
            or parsed_endpoint.is_multicast
            or parsed_endpoint.is_loopback
            or parsed_endpoint.is_link_local
        ):
            raise ValueError("ansible_host für WinRM HTTPS darf keine Sonder- oder Wildcard-IP sein.")
        ip_sans.append(str(parsed_endpoint))

    return {
        "fqdn": fqdn,
        "short_name": short_name,
        "endpoint": endpoint,
        "dns_sans": dns_sans,
        "ip_sans": ip_sans,
    }


def _kerberos_principal_for_host(
    windows: dict[str, Any],
    host_data: dict[str, Any],
    settings: dict[str, Any],
    *,
    vault_ansible_user: str = "",
) -> str:
    """UPN aus Konfiguration oder dem bereits entschlüsselten Inventory bestimmen."""
    configured = str(settings.get("kerberos_principal", "") or "").strip()
    source = (
        configured
        or str(_effective_host_var(windows, host_data, "ansible_user", "") or "").strip()
        or str(vault_ansible_user or "").strip()
    )
    if not source:
        raise ValueError(
            "Kein Kerberos-Principal auffindbar. ansible_user als UPN setzen oder "
            "winrm_https.kerberos_principal konfigurieren."
        )
    if "@" in source:
        principal = source
    else:
        account = source.rsplit("\\", 1)[-1].strip()
        if not account:
            raise ValueError("ansible_user enthält keinen verwendbaren Kerberos-Kontonamen.")
        principal = f"{account}@{settings['domain_suffix']}"
    if (
        any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in principal)
        or principal.count("@") != 1
    ):
        raise ValueError("Der Kerberos-Principal ist ungültig.")
    account, realm = principal.rsplit("@", 1)
    if not account or realm.casefold().rstrip(".") != str(settings["domain_suffix"]).casefold():
        raise ValueError(
            f"Der Kerberos-Principal muss zur Mavi-Domäne {settings['domain_suffix']} gehören."
        )
    # DNS-Domänennamen sind nicht case-sensitiv, Kerberos-Realm-Namen jedoch
    # schon. Der gültige AD-Realm bleibt deshalb immer das kanonische Uppercase
    # der zentral geprüften Mavi-Domäne — unabhängig davon, wie ein Vault-UPN
    # oder ansible_user geschrieben wurde.
    return f"{account}@{str(settings['domain_suffix']).upper()}"


def _vault_host_context(
    project: Path,
    host: str,
    vault_password_file: Path,
    *,
    inventory_path: Path | None = None,
) -> dict[str, Any]:
    """Hostvariablen ausschließlich durch Ansible selbst entschlüsseln.

    group_vars (auch Vault-Dateien) stehen absichtlich nicht im Roh-YAML des
    Inventars. Die
    vollständige JSON-Antwort wird nie ausgegeben, weil sie Secrets enthalten
    kann.
    """
    ansible_python = _ansible_controller_python()
    executable = _ansible_inventory_executable()
    effective_inventory = inventory_path or project_paths(project)["inventory"]
    try:
        result = subprocess.run(
            [
                str(ansible_python),
                "-I",
                str(executable),
                "-i", str(effective_inventory),
                "--host", host,
                "--vault-password-file", str(vault_password_file),
            ],
            cwd=str(project),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=_ansible_runtime_environment(ansible_python),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            "Der entschlüsselte Ansible-Hostkontext konnte nicht gelesen werden."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            "Ansible konnte den Hostkontext mit dem eingegebenen Vault-Passwort nicht entschlüsseln."
        )
    try:
        resolved = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Ansible lieferte keinen lesbaren entschlüsselten Hostkontext.") from exc
    if not isinstance(resolved, dict):
        raise RuntimeError("Ansible lieferte einen ungültigen entschlüsselten Hostkontext.")
    return resolved


def _vault_ansible_user_for_host(project: Path, host: str, vault_password_file: Path) -> str:
    """Liest ausschließlich ansible_user aus dem von Ansible entschlüsselten Host-Kontext."""
    resolved = _vault_host_context(project, host, vault_password_file)
    value = resolved.get("ansible_user", "")
    return value if isinstance(value, str) else ""


def _winrm_pki_paths(project: Path) -> dict[str, Path]:
    """Pfadlayout der separaten, nie veröffentlichten Mavi-WinRM-CA."""
    root = project_paths(project)["winrm_pki_dir"]
    return {
        "root": root,
        "ca_key": root / "mavi-winrm-root-ca.key.pem",
        "ca_cert": root / "mavi-winrm-root-ca.cert.pem",
        "ca_der": root / "mavi-winrm-root-ca.cer",
        "requests": root / "requests",
        "certs": root / "certs",
        "profiles": root / "profiles",
        "state": root / "state",
    }


def _winrm_local_command(command: list[str], *, description: str) -> str:
    """Lokalen OpenSSL-Schritt ohne Geheimnisse in der Ausgabe ausführen."""
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(f"{description} konnte nicht gestartet werden: {redact_sensitive_text(exc)}") from exc
    if result.returncode != 0:
        detail = redact_sensitive_text((result.stderr or result.stdout or "").strip())
        raise RuntimeError(
            f"{description} ist mit Exit-Code {result.returncode} fehlgeschlagen"
            + (f": {detail}" if detail else ".")
        )
    return (result.stdout or "").strip()


def _ensure_winrm_ca(project: Path) -> dict[str, Path]:
    """Einmalig eine von der Bootstrap-CA isolierte WinRM-CA erzeugen."""
    paths = _winrm_pki_paths(project)
    root = paths["root"]
    root.mkdir(parents=True, exist_ok=True)
    for directory_key in ("root", "requests", "certs", "profiles", "state"):
        directory = paths[directory_key]
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass

    ca_key = paths["ca_key"]
    ca_cert = paths["ca_cert"]
    if ca_cert.exists() and not ca_key.exists():
        raise RuntimeError(
            "Die Mavi-WinRM-CA existiert, aber ihr privater Schlüssel fehlt. "
            "Mavi ersetzt eine Vertrauenswurzel niemals still; Backup wiederherstellen."
        )
    if not shutil.which("openssl"):
        raise RuntimeError("OpenSSL fehlt auf dem Ansible-Server; die Mavi-WinRM-CA kann nicht sicher erzeugt werden.")

    if not ca_key.exists():
        _winrm_local_command(
            [
                "openssl", "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(ca_key),
            ],
            description="Privaten Schlüssel der Mavi-WinRM-CA erzeugen",
        )
    try:
        os.chmod(ca_key, 0o600)
    except OSError:
        pass

    if not ca_cert.exists():
        _winrm_local_command(
            [
                "openssl", "req", "-x509", "-new", "-sha256",
                "-key", str(ca_key), "-out", str(ca_cert), "-days", "3650",
                "-subj", "/CN=Mavi WinRM TLS Root CA/O=Mavi/OU=Internal Automation",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
            ],
            description="Mavi-WinRM-CA-Zertifikat erzeugen",
        )
    ca_der = paths["ca_der"]
    if not ca_der.exists():
        temporary_der = ca_der.with_name("." + ca_der.name + ".new")
        try:
            _winrm_local_command(
                ["openssl", "x509", "-in", str(ca_cert), "-outform", "DER", "-out", str(temporary_der)],
                description="Öffentliches Mavi-WinRM-CA-Zertifikat für Windows erzeugen",
            )
            os.replace(temporary_der, ca_der)
        finally:
            temporary_der.unlink(missing_ok=True)
    if not ca_der.is_file() or not ca_der.stat().st_size:
        raise RuntimeError("Das öffentliche Mavi-WinRM-CA-Zertifikat fehlt oder ist leer.")
    try:
        os.chmod(ca_cert, 0o644)
        os.chmod(ca_der, 0o644)
    except OSError:
        pass
    return paths


def _winrm_leaf_openssl_config(dns_sans: list[str], ip_sans: list[str]) -> str:
    """Zertifikatserweiterungen werden lokal festgelegt, niemals aus der CSR kopiert."""
    alt_lines: list[str] = []
    for index, name in enumerate(dns_sans, start=1):
        alt_lines.append(f"DNS.{index} = {name}")
    for index, value in enumerate(ip_sans, start=1):
        alt_lines.append(f"IP.{index} = {value}")
    if not alt_lines:
        raise ValueError("Für das WinRM-Zertifikat fehlt ein zulässiger SAN-Eintrag.")
    return "\n".join([
        "[server_ext]",
        "basicConstraints = critical, CA:FALSE",
        "keyUsage = critical, digitalSignature, keyEncipherment",
        "extendedKeyUsage = serverAuth",
        "subjectKeyIdentifier = hash",
        "authorityKeyIdentifier = keyid,issuer",
        "subjectAltName = @alt_names",
        "",
        "[alt_names]",
        *alt_lines,
        "",
    ])


def _issue_winrm_server_certificate(
    project: Path,
    *,
    host: str,
    identity: dict[str, Any],
    csr_pem: bytes,
) -> dict[str, Any]:
    """Eine auf Windows erzeugte CSR prüfen und mit der Mavi-WinRM-CA signieren."""
    paths = _ensure_winrm_ca(project)
    safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(host or "WINDOWS")).strip("._-") or "WINDOWS"
    request_id = secrets.token_hex(12)
    csr_path = paths["requests"] / f"{safe_host}-{request_id}.csr.pem"
    profile_path = paths["profiles"] / f"{safe_host}-{request_id}.cnf"
    cert_pem = paths["certs"] / f"{safe_host}-{request_id}.cert.pem"
    cert_der = paths["certs"] / f"{safe_host}-{request_id}.cer"
    temporary_pem = paths["certs"] / f".{safe_host}-{request_id}.cert.new"

    _atomic_write_bytes(csr_path, csr_pem, mode=0o600)
    _atomic_write_bytes(
        profile_path,
        _winrm_leaf_openssl_config(identity["dns_sans"], identity["ip_sans"]).encode("utf-8"),
        mode=0o600,
    )
    try:
        _winrm_local_command(
            ["openssl", "req", "-in", str(csr_path), "-noout", "-verify"],
            description="WinRM-Zertifikatsanfrage auf gültige Signatur prüfen",
        )
        subject = _winrm_local_command(
            ["openssl", "req", "-in", str(csr_path), "-noout", "-subject"],
            description="WinRM-Zertifikatsanfrage auslesen",
        )
        if identity["fqdn"].casefold() not in subject.casefold():
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Die Windows-CSR gehört nicht zum erwarteten WinRM-FQDN "
                f"{identity['fqdn']}."
            )

        _winrm_local_command(
            [
                "openssl", "x509", "-req", "-sha256", "-in", str(csr_path),
                "-CA", str(paths["ca_cert"]), "-CAkey", str(paths["ca_key"]),
                "-set_serial", "0x" + secrets.token_hex(16),
                "-out", str(temporary_pem), "-days", "825",
                "-extfile", str(profile_path), "-extensions", "server_ext",
            ],
            description="WinRM-Serverzertifikat mit der Mavi-WinRM-CA signieren",
        )
        _winrm_local_command(
            ["openssl", "verify", "-CAfile", str(paths["ca_cert"]), str(temporary_pem)],
            description="Signiertes WinRM-Serverzertifikat gegen die Mavi-WinRM-CA prüfen",
        )
        purpose = _winrm_local_command(
            ["openssl", "x509", "-in", str(temporary_pem), "-noout", "-purpose"],
            description="Server-Authentifizierung des WinRM-Zertifikats prüfen",
        )
        if not re.search(r"^SSL server\s*:\s*Yes\s*$", purpose, flags=re.IGNORECASE | re.MULTILINE):
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Das signierte WinRM-Zertifikat besitzt keine gültige "
                "Server-Authentication-Verwendung."
            )
        _winrm_local_command(
            ["openssl", "x509", "-in", str(temporary_pem), "-outform", "DER", "-out", str(cert_der)],
            description="WinRM-Serverzertifikat für Windows bereitstellen",
        )
        os.replace(temporary_pem, cert_pem)
        try:
            os.chmod(cert_pem, 0o600)
            os.chmod(cert_der, 0o600)
        except OSError:
            pass
    finally:
        temporary_pem.unlink(missing_ok=True)

    return {
        "ca_cert": paths["ca_cert"],
        "ca_der": paths["ca_der"],
        "ca_der_sha256": _sha256_file(paths["ca_der"]).lower(),
        "cert_pem": cert_pem,
        "cert_der": cert_der,
        "cert_sha256": _sha256_file(cert_der).lower(),
        "request_id": request_id,
    }


def _remove_host_winrm_certificate_artifacts(
    project: Path,
    host: str,
) -> tuple[int, list[str]]:
    """Nur die eindeutig diesem Host zugeordneten WinRM-PKI-Dateien löschen."""
    paths = _winrm_pki_paths(project)
    safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(host or "WINDOWS")).strip("._-") or "WINDOWS"
    escaped_host = re.escape(safe_host)
    file_patterns = {
        "requests": re.compile(rf"^{escaped_host}-[a-f0-9]{{24}}\.csr\.pem$"),
        "profiles": re.compile(rf"^{escaped_host}-[a-f0-9]{{24}}\.cnf$"),
        "certs": re.compile(
            rf"^(?:{escaped_host}-[a-f0-9]{{24}}\.(?:cert\.pem|cer)|"
            rf"\.{escaped_host}-[a-f0-9]{{24}}\.cert\.new)$"
        ),
    }
    removed = 0
    warnings: list[str] = []
    if paths["root"].is_symlink():
        warnings.append(f"Verknüpfte WinRM-PKI-Basis wurde nicht bereinigt: {paths['root']}")
        return removed, warnings
    try:
        expected_root = paths["root"].resolve(strict=True)
    except OSError as exc:
        if paths["root"].exists():
            warnings.append(f"WinRM-PKI-Basis konnte nicht geprüft werden: {redact_sensitive_text(exc)}")
        return removed, warnings

    for directory_key, filename_pattern in file_patterns.items():
        directory = paths[directory_key]
        if not directory.exists():
            continue
        if directory.is_symlink():
            warnings.append(f"Verknüpfter WinRM-PKI-Ordner wurde nicht bereinigt: {directory}")
            continue
        try:
            resolved_directory = directory.resolve(strict=True)
            if resolved_directory.parent != expected_root:
                warnings.append(
                    f"Unerwarteter WinRM-PKI-Pfad wurde nicht bereinigt: {resolved_directory}"
                )
                continue
            candidates = list(directory.iterdir())
        except OSError as exc:
            warnings.append(
                f"WinRM-PKI-Ordner {directory} konnte nicht gelesen werden: "
                f"{redact_sensitive_text(exc)}"
            )
            continue

        for candidate in candidates:
            if filename_pattern.fullmatch(candidate.name) is None:
                continue
            try:
                if candidate.is_dir() and not candidate.is_symlink():
                    warnings.append(f"Unerwarteter Ordner wurde nicht entfernt: {candidate}")
                    continue
                candidate.unlink()
                removed += 1
            except OSError as exc:
                warnings.append(
                    f"Hostbezogene WinRM-PKI-Datei {candidate} konnte nicht entfernt werden: "
                    f"{redact_sensitive_text(exc)}"
                )

    return removed, warnings


def _absolute_without_symlink(path: Path) -> Path:
    """Absoluten Pfad bilden, ohne die für venv essenzielle Symlink-Identität zu verlieren."""
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _ansible_playbook_candidates() -> list[Path]:
    """Bevorzugte Ansible-Startpunkte ohne PATH-/sudo-Mehrdeutigkeit liefern."""
    raw_candidates: list[Path] = []

    # Bei einem sudo-Start bleibt die Benutzer-pipx-Installation der korrekte
    # Ansible-Kontext. /root/.local oder /usr/bin dürfen sie nicht verdrängen.
    sudo_user = str(os.environ.get("SUDO_USER", "") or "").strip()
    if sudo_user and sudo_user != "root" and re.fullmatch(r"[A-Za-z0-9_.-]+", sudo_user):
        try:
            import pwd

            sudo_home = Path(pwd.getpwnam(sudo_user).pw_dir)
            raw_candidates.append(sudo_home / ".local" / "bin" / "ansible-playbook")
        except (ImportError, KeyError, OSError):
            pass

    raw_candidates.append(Path.home() / ".local" / "bin" / "ansible-playbook")
    path_executable = shutil.which("ansible-playbook")
    if path_executable:
        raw_candidates.append(Path(path_executable))

    candidates: list[Path] = []
    seen: set[Path] = set()
    for candidate in raw_candidates:
        try:
            if not candidate.is_file():
                continue
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        candidates.append(resolved)
    return candidates


_ANSIBLE_RUNTIME_CACHE: tuple[Path, Path] | None = None


def _ansible_playbook_runtime() -> tuple[Path, Path]:
    """Exakten Ansible-Startpunkt und dessen wirklichen Python-Interpreter koppeln."""
    global _ANSIBLE_RUNTIME_CACHE
    if _ANSIBLE_RUNTIME_CACHE is not None:
        executable, interpreter = _ANSIBLE_RUNTIME_CACHE
        if executable.is_file() and interpreter.is_file():
            return _ANSIBLE_RUNTIME_CACHE

    candidates = _ansible_playbook_candidates()
    if not candidates:
        raise RuntimeError("ansible-playbook fehlt auf dem Controller.")

    for executable in candidates:
        # `ansible-playbook --version` wird vom tatsächlichen Ansible-Prozess
        # erzeugt und nennt dessen Python samt absolutem Pfad.
        try:
            version_result = subprocess.run(
                [str(executable), "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            version_result = None
        if version_result is not None and version_result.returncode == 0:
            version_output = (version_result.stdout or "") + "\n" + (version_result.stderr or "")
            for line in version_output.splitlines():
                match = re.search(
                    r"^\s*python\s+version\s*=.*\((/[^)]+)\)\s*$",
                    line,
                    re.IGNORECASE,
                )
                if not match:
                    continue
                reported = Path(match.group(1).strip()).expanduser()
                if reported.is_file():
                    # NIEMALS resolve(): venv/bin/python ist absichtlich ein
                    # Symlink auf das Basis-Python. Nur der logische Venv-Pfad
                    # aktiviert pyvenv.cfg und damit dessen site-packages.
                    _ANSIBLE_RUNTIME_CACHE = (
                        executable,
                        _absolute_without_symlink(reported),
                    )
                    return _ANSIBLE_RUNTIME_CACHE

        # Fallback nur auf den Shebang genau dieses Startpunkts. Es gibt keinen
        # Rückfall auf sys.executable, da dies erneut zwei Umgebungen vermischen würde.
        try:
            first_line = executable.open("r", encoding="utf-8", errors="replace").readline().strip()
        except OSError:
            first_line = ""
        if not first_line.startswith("#!"):
            continue
        shebang = first_line[2:].strip().split()
        if not shebang:
            continue
        interpreter = shebang[0]
        if Path(interpreter).name == "env" and len(shebang) > 1:
            env_arguments = shebang[1:]
            if env_arguments and env_arguments[0] == "-S":
                env_arguments = env_arguments[1:]
            interpreter_name = next(
                (value for value in env_arguments if value and not value.startswith("-")),
                "",
            )
            interpreter = shutil.which(interpreter_name) or ""
        if interpreter and Path(interpreter).is_file():
            _ANSIBLE_RUNTIME_CACHE = (
                executable,
                _absolute_without_symlink(Path(interpreter)),
            )
            return _ANSIBLE_RUNTIME_CACHE

    raise RuntimeError(
        "Der Python-Interpreter des verfügbaren ansible-playbook konnte nicht eindeutig ermittelt werden."
    )


def _ansible_playbook_executable() -> Path:
    return _ansible_playbook_runtime()[0]


def _ansible_controller_python() -> Path:
    return _ansible_playbook_runtime()[1]


def _ansible_inventory_executable() -> Path:
    """ansible-inventory aus exakt derselben Installation wie ansible-playbook."""
    candidate = _ansible_playbook_executable().with_name("ansible-inventory")
    if not candidate.is_file():
        raise RuntimeError(
            "ansible-inventory fehlt in der erkannten Ansible-Umgebung."
        )
    return candidate


def _ansible_runtime_environment(ansible_python: Path) -> dict[str, str]:
    """Saubere Prozessumgebung für den gebundenen venv-/pipx-Interpreter."""
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PATH"] = str(ansible_python.parent) + os.pathsep + environment.get("PATH", "")
    venv_root = ansible_python.parent.parent
    if (venv_root / "pyvenv.cfg").is_file():
        environment["VIRTUAL_ENV"] = str(venv_root)
    return environment


def _python_imports_gssapi(python_executable: Path) -> bool:
    """Die vollständige PSRP-/pyspnego-Kerberos-Kette im Ansible-Venv prüfen."""
    probe = (
        "import gssapi, krb5, pypsrp\n"
        "from spnego import _gss\n"
        "assert _gss.HAS_GSSAPI, _gss.GSSAPI_IMP_ERR\n"
        "assert _gss.HAS_IOV, _gss.GSSAPI_IOV_IMP_ERR\n"
    )
    try:
        result = subprocess.run(
            [str(python_executable), "-I", "-c", probe],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
            env=_ansible_runtime_environment(python_executable),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _controller_root_prefix() -> list[str]:
    """Root-Prefix für die einmalige Controller-Paketinstallation."""
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if not sudo:
        raise RuntimeError(
            "GSSAPI fehlt und sudo ist für die automatische Controller-Einrichtung nicht verfügbar."
        )
    return [sudo]


def _ansible_pipx_venv_root(ansible_python: Path) -> Path | None:
    """pipx-Venv-Wurzel ausschließlich aus dem unaufgelösten Interpreterpfad ableiten."""
    lexical_python = _absolute_without_symlink(ansible_python)
    for parent in lexical_python.parents:
        if parent.parent.name != "venvs" or parent.parent.parent.name != "pipx":
            continue
        if re.fullmatch(r"[A-Za-z0-9_.-]+", parent.name) and (parent / "pyvenv.cfg").is_file():
            return parent
    return None


def _ansible_pipx_package(ansible_python: Path) -> str:
    """pipx-Paketname aus .../pipx/venvs/<paket>/bin/python ableiten."""
    venv_root = _ansible_pipx_venv_root(ansible_python)
    return venv_root.name if venv_root is not None else ""


def _pipx_command_for_ansible(ansible_python: Path) -> list[str]:
    """pipx im Besitz genau der erkannten Ansible-Umgebung ausführen."""
    pipx_path: Path | None = None
    lexical_python = _absolute_without_symlink(ansible_python)
    venv_root = _ansible_pipx_venv_root(lexical_python)
    for parent in lexical_python.parents:
        if parent.name != ".local":
            continue
        associated = parent / "bin" / "pipx"
        if associated.is_file():
            pipx_path = _absolute_without_symlink(associated)
            break
    if pipx_path is None:
        discovered = shutil.which("pipx")
        if discovered:
            pipx_path = _absolute_without_symlink(Path(discovered))
    if pipx_path is None:
        raise RuntimeError("Die erkannte Ansible-pipx-Umgebung kann nicht repariert werden, weil pipx fehlt.")

    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid):
        return [str(pipx_path)]
    try:
        # Nicht den Python-Symlink statten: dessen Ziel /usr/bin gehört root.
        runtime_owner = (venv_root or lexical_python.parent.parent).stat().st_uid
    except OSError:
        runtime_owner = geteuid()
    if runtime_owner == geteuid():
        return [str(pipx_path)]

    # Wurde das gesamte Mavi-Skript mit sudo gestartet, muss pipx trotzdem als
    # Besitzer der Benutzerumgebung laufen. Sonst sucht pipx irrtümlich unter /root.
    if geteuid() == 0:
        try:
            import pwd

            owner_name = pwd.getpwuid(runtime_owner).pw_name
        except (ImportError, KeyError, OSError) as exc:
            raise RuntimeError("Der Besitzer der Ansible-pipx-Umgebung konnte nicht ermittelt werden.") from exc
        sudo = shutil.which("sudo")
        if not sudo:
            raise RuntimeError("sudo fehlt für die Reparatur der Benutzer-pipx-Umgebung.")
        return [sudo, "-u", owner_name, "-H", str(pipx_path)]

    raise RuntimeError("Die Ansible-pipx-Umgebung gehört einem anderen Benutzer und ist nicht sicher änderbar.")


def _ensure_psrp_kerberos_controller_dependencies(*, force_pipx_inject: bool = False) -> None:
    """Offizielle PSRP-Kerberos-Abhängigkeiten vor jeder Windows-Änderung bereitstellen."""
    ansible_executable, ansible_python = _ansible_playbook_runtime()
    pipx_package = _ansible_pipx_package(ansible_python)
    gssapi_available = _python_imports_gssapi(ansible_python)
    if gssapi_available and not force_pipx_inject:
        return

    print("\nMavi KERBEROS-CONTROLLER-SETUP")
    print("================================")
    if gssapi_available:
        print("  → Der Ansible-Worker meldete GSSAPI trotz Vorprüfung als fehlend; Mavi repariert die pipx-Umgebung einmalig.")
    else:
        print("  → GSSAPI fehlt im Python-Kontext von Ansible und wird einmalig eingerichtet.")
    print(f"  → Ansible-Start:  {ansible_executable}")
    print(f"  → Ansible-Python: {ansible_python}")
    if pipx_package:
        print(f"  → pipx-Paket:      {pipx_package}")

    if not gssapi_available:
        apt_get = shutil.which("apt-get")
        if apt_get:
            root_prefix = _controller_root_prefix()
            noninteractive = ["env", "DEBIAN_FRONTEND=noninteractive"]
            _root_command(
                [*root_prefix, *noninteractive, apt_get, "update"],
                description="Kerberos-Paketlisten aktualisieren",
            )
            _root_command(
                [
                    *root_prefix,
                    *noninteractive,
                    apt_get,
                    "install",
                    "-y",
                    "--no-install-recommends",
                    "krb5-user",
                    "libkrb5-dev",
                    "python3-dev",
                    "gcc",
                    "python3-gssapi",
                ],
                description="Kerberos, GSSAPI und Python-Buildabhängigkeiten installieren",
            )
        else:
            raise RuntimeError(
                "GSSAPI fehlt. Die automatische Einrichtung unterstützt hier Debian/Ubuntu mit apt-get."
            )

    if _python_imports_gssapi(ansible_python) and not force_pipx_inject:
        print("  ✓ GSSAPI, Kerberos und WinRM-IOV sind im Ansible-Python verfügbar.")
        return

    # pipx-Umgebungen werden ausschließlich über die dafür vorgesehene
    # Injection erweitert. Ein direktes `venv/bin/python -m pip` kann zwar
    # funktionieren, umgeht aber pipx' Paketverwaltung und war bei der realen
    # Mavi-Ansible-Installation mit Python 3.14 nicht zuverlässig.
    ansible_python_text = str(_absolute_without_symlink(ansible_python))
    system_python_candidates = {
        _absolute_without_symlink(candidate)
        for directory in (Path("/usr/bin"), Path("/bin"))
        for candidate in directory.glob("python*")
        if candidate.is_file()
        and re.fullmatch(r"python\d+(?:\.\d+)*", candidate.name)
    }
    if pipx_package:
        pipx_command = _pipx_command_for_ansible(ansible_python)
        _root_command(
            [
                *pipx_command,
                "inject",
                "--force",
                pipx_package,
                "pypsrp[kerberos]>=0.4.0,<1.0.0",
            ],
            description=f"PSRP-Kerberos-Extra in pipx-Paket {pipx_package} injizieren",
        )
    elif _absolute_without_symlink(ansible_python) not in system_python_candidates:
        _root_command(
            [
                ansible_python_text,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "pypsrp[kerberos]>=0.4.0,<1.0.0",
            ],
            description="PSRP-Kerberos-Extra in die isolierte Ansible-Umgebung installieren",
        )

    # `inject` ist der vorgesehene pipx-Weg. Sollte dessen Extra-Auflösung die
    # vollständige pyspnego-Kette dennoch nicht bereitstellen, installiert Mavi
    # die vier konkreten Kerberos-Komponenten direkt in exakt dieselbe Venv.
    if pipx_package and not _python_imports_gssapi(ansible_python):
        pipx_command = _pipx_command_for_ansible(ansible_python)
        _root_command(
            [
                *pipx_command,
                "runpip",
                pipx_package,
                "install",
                "--upgrade",
                "--force-reinstall",
                "--no-cache-dir",
                "gssapi>=1.6.0",
                "krb5>=0.3.0",
                "pyspnego[kerberos]>=0.7.0,<1.0.0",
                "pypsrp[kerberos]>=0.4.0,<1.0.0",
            ],
            description=f"Kerberos-Komponenten im pipx-Paket {pipx_package} vollständig reparieren",
        )

    if not _python_imports_gssapi(ansible_python):
        raise RuntimeError(
            "Die vollständige GSSAPI-/Kerberos-/IOV-Kette ist nach der Einrichtung "
            f"im Ansible-Python {ansible_python} weiterhin nicht verfügbar."
        )
    print("  ✓ GSSAPI, Kerberos und WinRM-IOV sind im Ansible-Python verfügbar.")


def _is_missing_gssapi_failure(exc: BaseException) -> bool:
    """Eindeutige Ausfälle der lokalen GSSAPI-/Kerberos-Kette erkennen."""
    folded = str(exc).casefold()
    return (
        "gssapiproxy requires the python gssapi library" in folded
        or (
            "no module named" in folded
            and any(module in folded for module in ("gssapi", "krb5"))
        )
        or "gssapi iov extension not available" in folded
    )


def _temporary_psrp_vault_inventory(project: Path, host: str) -> Path | None:
    """Leere SSH-Credential-Overrides nur für einen PSRP-Probe-Lauf ausblenden.

    Beim SSH-Umbau setzt Mavi absichtlich leere Hostwerte, damit das SSH-Plugin
    niemals auf ein geerbtes Vault-Passwort zurückgreift. Für PSRP/Kerberos
    wären genau diese leeren Werte aber ein Host-Override über das echte
    Gruppen-Vault-Passwort. Diese private Inventarkopie entfernt deshalb
    ausschließlich leere SSH-Maskierungen; sie enthält nie entschlüsselte
    Zugangsdaten und wird nach dem einzelnen Probe-Lauf gelöscht.
    """
    inventory, _windows, host_data = _host_inventory_entry(project, host)
    removed = False
    for key in (
        "ansible_password",
        "ansible_ssh_pass",
        "ansible_ssh_password",
        "ansible_psrp_password",
        "ansible_winrm_pass",
        "ansible_winrm_password",
    ):
        value = host_data.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            if key in host_data:
                host_data.pop(key, None)
                removed = True
    if not removed:
        return None

    source_path = project_paths(project)["inventory"]
    descriptor, raw_path = tempfile.mkstemp(
        prefix=".mavi-psrp-vault-",
        suffix=".yml",
        dir=str(source_path.parent),
    )
    os.close(descriptor)
    temporary_path = Path(raw_path)
    try:
        # Derselbe Inventarordner ist wichtig: Ansible findet dort weiterhin
        # die vorhandenen group_vars und damit den verschlüsselten Vault-Wert.
        atomic_write_yaml(temporary_path, inventory)
        if os.name != "nt":
            os.chmod(temporary_path, 0o600)
        return temporary_path
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _vault_psrp_password_for_host(project: Path, host: str, vault_password_file: Path) -> str:
    """Das bestehende Vault-Passwort nur im Speicher für einen Kerberos-TGT lesen.

    Das SSH-Inventar darf absichtlich leere Passwortwerte enthalten. Für diese
    eine Abfrage werden ausschließlich solche leeren Maskierungen entfernt,
    damit Ansible den regulären Vault-Wert auflöst. Die entschlüsselte Antwort
    bleibt im Arbeitsspeicher und wird nie protokolliert oder gespeichert.
    """
    temporary_inventory_path: Path | None = None
    try:
        temporary_inventory_path = _temporary_psrp_vault_inventory(project, host)
        resolved = _vault_host_context(
            project,
            host,
            vault_password_file,
            inventory_path=temporary_inventory_path or project_paths(project)["inventory"],
        )
    finally:
        if temporary_inventory_path is not None:
            temporary_inventory_path.unlink(missing_ok=True)

    for key in ("ansible_password", "ansible_winrm_pass", "ansible_winrm_password"):
        value = resolved.get(key)
        if isinstance(value, str) and value:
            # `kinit` bekommt die Kennung über stdin; Zeilenumbrüche würden
            # dessen Passwortdialog mehrdeutig machen und sind für dieses
            # automatisierte Verfahren absichtlich nicht zugelassen.
            if "\r" in value or "\n" in value:
                raise RuntimeError(
                    "Das entschlüsselte Ansible-Passwort enthält einen Zeilenumbruch und kann nicht sicher "
                    "für den automatischen Kerberos-Ticket-Schritt verwendet werden."
                )
            return value
    raise RuntimeError(
        "Im entschlüsselten Ansible-Vault fehlt ein nichtleeres ansible_password "
        "(alternativ ansible_winrm_pass/ansible_winrm_password) für Kerberos."
    )


def _discard_kerberos_ticket_cache(cache_directory: Path, cache_path: Path) -> None:
    """Den ausschließlich von Mavi angelegten Datei-Cache bestmöglich entfernen."""
    try:
        cache_path.unlink(missing_ok=True)
    finally:
        try:
            cache_directory.rmdir()
        except OSError:
            # Ein fehlgeschlagener Cleanup darf keinen möglicherweise
            # erfolgreichen, bereits sicher abgeschlossenen Nachweis verfälschen.
            pass


def _verify_kerberos_ticket_cache(
    *,
    cache_path: Path,
    ansible_python: Path,
    target_fqdn: str,
) -> str:
    """TGT und passenden host/FQDN-Dienstticketpfad im echten Ansible-Python prüfen.

    `creds=None` ist hier absichtlich: Genau diesen Default-CCache-Pfad benutzt
    pyspnego für einen leeren CredentialCache ebenfalls. Ein expliziter
    Benutzername würde GSSAPI dagegen auf eine benannte Cache-Credential
    festlegen und kann bei AD-Namenskanonisierung an "Matching credential not
    found" scheitern, obwohl das TGT gültig ist.
    """
    fqdn = _normalize_winrm_dns_name(target_fqdn, label="Kerberos-Ziel-FQDN")
    if not cache_path.is_file() or cache_path.stat().st_size <= 0:
        raise RuntimeError("Der private Kerberos-Ticket-Cache fehlt oder ist leer.")

    target_literal = json.dumps(f"host@{fqdn}")
    probe = (
        "import gssapi\n"
        "mech = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')\n"
        "credential = gssapi.Credentials(usage='initiate', mechs=[mech])\n"
        "principal = str(credential.name).strip()\n"
        "if not principal: raise RuntimeError('Kerberos-Cache enthält keinen Initiator-Principal')\n"
        f"target = gssapi.Name({target_literal}, name_type=gssapi.NameType.hostbased_service)\n"
        "context = gssapi.SecurityContext(name=target, mech=mech, usage='initiate')\n"
        "token = context.step()\n"
        "if not token: raise RuntimeError('KDC lieferte kein Dienstticket für den WinRM-SPN')\n"
        "print(principal)\n"
    )
    environment = _ansible_runtime_environment(ansible_python)
    environment["KRB5CCNAME"] = f"FILE:{cache_path}"
    try:
        result = subprocess.run(
            [str(ansible_python), "-I", "-c", probe],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Der Kerberos-Dienstticketnachweis hat nicht rechtzeitig geantwortet."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            "Der Kerberos-Dienstticketnachweis konnte nicht gestartet werden: "
            f"{redact_sensitive_text(exc)}"
        ) from exc

    if result.returncode != 0:
        detail = redact_sensitive_text((result.stderr or result.stdout or "").strip())
        raise RuntimeError(
            f"Der private Kerberos-Ticket-Cache konnte kein host/{fqdn}-Dienstticket verwenden"
            + (f": {detail}" if detail else ".")
        )
    principal = (result.stdout or "").strip()
    if not re.fullmatch(r"[^@\s]+@[A-Za-z0-9.-]+", principal):
        raise RuntimeError(
            "Der Kerberos-Dienstticketnachweis lieferte keinen gültigen Cache-Principal."
        )
    return principal


def _acquire_vault_kerberos_ticket(
    project: Path,
    *,
    host: str,
    vault_password_file: Path,
    kerberos_principal: str,
    ansible_python: Path,
    target_fqdn: str,
) -> tuple[Path, Path, str]:
    """TGT in einem privaten Einmal-Cache erzeugen, nie in der Login-Session."""
    principal = str(kerberos_principal or "").strip()
    if not principal or principal.count("@") != 1:
        raise ValueError("Für den automatischen Kerberos-Nachweis fehlt ein gültiger UPN-Principal.")
    kinit = shutil.which("kinit")
    if not kinit:
        raise RuntimeError(
            "kinit fehlt auf dem Ansible-Server. Mavi kann ohne einen echten Kerberos-TGT keinen "
            "Kerberos-only-WinRM-Transport aktivieren."
        )

    password = _vault_psrp_password_for_host(project, host, vault_password_file)
    cache_directory = Path(tempfile.mkdtemp(prefix=".mavi-kerberos-ticket-"))
    cache_path = cache_directory / "krb5cc"
    cache_name = f"FILE:{cache_path}"
    try:
        if os.name != "nt":
            os.chmod(cache_directory, 0o700)
        environment = _ansible_runtime_environment(ansible_python)
        environment["KRB5CCNAME"] = cache_name
        try:
            result = subprocess.run(
                [str(kinit), "-c", cache_name, principal],
                input=password + "\n",
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Der automatische Kerberos-Ticket-Schritt hat nicht rechtzeitig geantwortet.") from exc
        except OSError as exc:
            raise RuntimeError(
                f"Der automatische Kerberos-Ticket-Schritt konnte nicht gestartet werden: "
                f"{redact_sensitive_text(exc)}"
            ) from exc
        finally:
            # Keine Referenz auf das entschlüsselte Vault-Passwort länger als
            # bis zur unmittelbaren stdin-Übergabe behalten.
            password = ""

        if result.returncode != 0:
            detail = redact_sensitive_text((result.stderr or result.stdout or "").strip())
            raise RuntimeError(
                "Der automatische Kerberos-Ticket-Schritt wurde vom AD abgelehnt"
                + (f": {detail}" if detail else ".")
            )
        if not cache_path.is_file() or cache_path.stat().st_size <= 0:
            raise RuntimeError("Der automatische Kerberos-Ticket-Schritt hat keinen verwendbaren Ticket-Cache erzeugt.")
        if os.name != "nt":
            os.chmod(cache_path, 0o600)
        cache_principal = _verify_kerberos_ticket_cache(
            cache_path=cache_path,
            ansible_python=ansible_python,
            target_fqdn=target_fqdn,
        )
        return cache_directory, cache_path, cache_principal
    except BaseException:
        _discard_kerberos_ticket_cache(cache_directory, cache_path)
        raise


def _kerberos_cache_connection_overrides() -> dict[str, str]:
    """PSRP auf die Default-Credential des privaten Kerberos-Caches festlegen."""
    return {
        "ansible_user": "",
        "ansible_psrp_user": "",
        "ansible_password": "",
        "ansible_psrp_password": "",
        "ansible_winrm_pass": "",
        "ansible_winrm_password": "",
    }


def _ansible_command_with_kerberos_cache(
    command: list[str],
    *,
    enabled: bool,
) -> list[str]:
    """Cache-only-Credentials mit höchster Ansible-Variablenpriorität setzen."""
    if not enabled:
        return command
    return [
        *command,
        "--extra-vars",
        json.dumps(
            _kerberos_cache_connection_overrides(),
            ensure_ascii=True,
            separators=(",", ":"),
        ),
    ]


def _prepare_client_runner_runtime(
    project: Path,
    *,
    host: str,
    vault_password_file: Path,
) -> tuple[dict[str, str], Path | None, Path | None]:
    """Den normalen Client-Runner an den bewährten privaten CCache binden."""
    _inventory, windows, host_data = _host_inventory_entry(project, host)
    connection = str(
        _effective_host_var(windows, host_data, "ansible_connection", "") or ""
    ).strip().lower()
    if connection != "psrp":
        return os.environ.copy(), None, None

    protocol = str(
        _effective_host_var(windows, host_data, "ansible_psrp_protocol", "") or ""
    ).strip().lower()
    auth = str(
        _effective_host_var(windows, host_data, "ansible_psrp_auth", "") or ""
    ).strip().lower()
    if auth != "kerberos":
        return os.environ.copy(), None, None
    if protocol != "https":
        raise RuntimeError(
            "Der Client-Runner verwendet PSRP/Kerberos nur mit dem gespeicherten HTTPS-Endpunkt."
        )

    _ansible_executable, ansible_python = _ansible_playbook_runtime()
    runtime_environment = _ansible_runtime_environment(ansible_python)
    _settings, fqdn, _ca_cert, kerberos_principal = _saved_winrm_https_transport(
        project,
        host_data,
    )
    cache_directory, cache_path, cache_principal = _acquire_vault_kerberos_ticket(
        project,
        host=host,
        vault_password_file=vault_password_file,
        kerberos_principal=kerberos_principal,
        ansible_python=ansible_python,
        target_fqdn=fqdn,
    )
    try:
        runtime_environment["KRB5CCNAME"] = f"FILE:{cache_path}"
        print(
            f"  ✓ Client-Runner nutzt privaten Kerberos-Cache: {cache_principal}; "
            f"host/{fqdn} ist bestätigt."
        )
        return runtime_environment, cache_directory, cache_path
    except BaseException:
        _discard_kerberos_ticket_cache(cache_directory, cache_path)
        raise


def _run_winrm_temporary_play(
    project: Path,
    *,
    host: str,
    play: list[dict[str, Any]],
    vault_password_file: Path,
    description: str,
    extra_vars: dict[str, Any] | None = None,
    inherit_vault_psrp_credentials: bool = False,
    use_vault_kerberos_ticket: bool = False,
    kerberos_principal: str = "",
    kerberos_target_fqdn: str = "",
    timeout: float = 180.0,
) -> str:
    """Kurzlebigen Ansible-Play sicher ausführen und Fehler kompakt schwärzen."""
    playbook_path: Path | None = None
    temporary_inventory_path: Path | None = None
    kerberos_ticket_directory: Path | None = None
    kerberos_ticket_path: Path | None = None
    effective_extra_vars = dict(extra_vars or {})
    try:
        fd, raw_path = tempfile.mkstemp(prefix=".mavi-winrm-tls-", suffix=".yml")
        os.close(fd)
        playbook_path = Path(raw_path)
        atomic_write_yaml(playbook_path, play)

        if inherit_vault_psrp_credentials:
            temporary_inventory_path = _temporary_psrp_vault_inventory(project, host)
        inventory_path = temporary_inventory_path or project_paths(project)["inventory"]

        ansible_executable, ansible_python = _ansible_playbook_runtime()
        runtime_environment = _ansible_runtime_environment(ansible_python)
        if use_vault_kerberos_ticket:
            kerberos_ticket_directory, kerberos_ticket_path, cache_principal = _acquire_vault_kerberos_ticket(
                project,
                host=host,
                vault_password_file=vault_password_file,
                kerberos_principal=kerberos_principal,
                ansible_python=ansible_python,
                target_fqdn=kerberos_target_fqdn,
            )
            runtime_environment["KRB5CCNAME"] = f"FILE:{kerberos_ticket_path}"
            # pyspnego verwendet bei einem nichtleeren Benutzernamen eine
            # benannte Cache-Credential. Das war der Auslöser für den echten
            # "Matching credential not found"-Fehler. Leere Werte sind hier
            # kein Fallback: Sie zwingen ausschließlich den vorher geprüften
            # Standard-CCache; weder Passwort noch NTLM stehen diesem Proof
            # zur Verfügung.
            effective_extra_vars.update(_kerberos_cache_connection_overrides())
            print(
                f"  ✓ Privater Kerberos-Cache: {cache_principal}; "
                f"host/{kerberos_target_fqdn} ist bestätigt."
            )
        command = [
            str(ansible_python),
            "-I",
            str(ansible_executable),
            "-i", str(inventory_path),
            str(playbook_path),
            "--limit", host,
            "--vault-password-file", str(vault_password_file),
        ]
        if effective_extra_vars:
            # Die Overlay-Variablen enthalten ausschließlich Transport- und
            # Zertifikatspfade sowie explizit leere Credential-Sperren, nie
            # ein Passwort oder privates Schlüsselmaterial.
            command.extend([
                "--extra-vars",
                json.dumps(effective_extra_vars, ensure_ascii=True, separators=(",", ":")),
            ])
        try:
            completed = subprocess.run(
                command,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=runtime_environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{description} hat nach {int(timeout)} Sekunden nicht geantwortet.") from exc
        except OSError as exc:
            raise RuntimeError(f"{description} konnte nicht gestartet werden: {redact_sensitive_text(exc)}") from exc

        combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
        if completed.returncode != 0:
            folded = combined.casefold()
            if "decryption failed" in folded or "no vault secrets" in folded:
                raise RuntimeError(
                    "Der Ansible-Vault konnte nicht entschlüsselt werden. "
                    "Bitte das Mavi-Vault-Passwort eingeben, nicht das Domänen-/Windows-Passwort."
                )
            lines = [
                redact_sensitive_text(line.strip())
                for line in strip_ansi(combined).splitlines()
                if line.strip()
            ]
            detail = " | ".join(lines[-12:])
            raise RuntimeError(
                f"{description} ist fehlgeschlagen"
                + (f": {detail}" if detail else f" (Ansible-Code {completed.returncode})")
            )
        return combined
    finally:
        if kerberos_ticket_directory is not None and kerberos_ticket_path is not None:
            _discard_kerberos_ticket_cache(kerberos_ticket_directory, kerberos_ticket_path)
        if playbook_path is not None:
            playbook_path.unlink(missing_ok=True)
        if temporary_inventory_path is not None:
            temporary_inventory_path.unlink(missing_ok=True)


def _winrm_csr_play(
    *,
    identity: dict[str, Any],
    request_id: str,
) -> list[dict[str, Any]]:
    """Play, der den privaten Schlüssel ausschließlich auf Windows erzeugt."""
    ip_san = str((identity.get("ip_sans") or [""])[0] or "")
    powershell = r'''[CmdletBinding()]
param(
    [string]$Fqdn,
    [string]$ShortName,
    [string]$IpSan,
    [string]$RequestId
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Fqdn) -or [string]::IsNullOrWhiteSpace($ShortName)) {
    throw 'Mavi WinRM TLS: FQDN oder Kurzname fehlt.'
}
if ($RequestId -notmatch '^[a-f0-9]{16,64}$') {
    throw 'Mavi WinRM TLS: interne Request-ID ist ungültig.'
}
if ($IpSan) {
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($IpSan, [ref]$parsedIp)) {
        throw "Mavi WinRM TLS: IP-SAN ist ungültig: $IpSan"
    }
}

$certreq = Join-Path $env:WINDIR 'System32\certreq.exe'
if (-not (Test-Path -LiteralPath $certreq -PathType Leaf)) {
    throw "certreq.exe fehlt: $certreq"
}
$workDir = Join-Path $env:ProgramData 'Mavi\WinRM-TLS'
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
$infPath = Join-Path $workDir ("request-$RequestId.inf")
$csrPath = Join-Path $workDir ("request-$RequestId.req")
Remove-Item -LiteralPath $infPath, $csrPath -Force -ErrorAction SilentlyContinue

$sanParts = @("dns=$Fqdn", "dns=$ShortName")
if (-not [string]::IsNullOrWhiteSpace($IpSan)) {
    $sanParts += "ipaddress=$IpSan"
}
$sanText = $sanParts -join '&'
$infLines = @(
    '[Version]',
    'Signature="$Windows NT$"',
    '',
    '[NewRequest]',
    ('Subject = "CN=' + $Fqdn + '"'),
    'KeyAlgorithm = RSA',
    'KeyLength = 3072',
    'HashAlgorithm = sha256',
    'MachineKeySet = TRUE',
    'Exportable = FALSE',
    'ProviderName = "Microsoft Software Key Storage Provider"',
    'RequestType = PKCS10',
    'KeyUsage = 0xa0',
    ('FriendlyName = "Mavi WinRM HTTPS ' + $Fqdn + '"'),
    '',
    '[Extensions]',
    '2.5.29.17 = "{text}"',
    ('_continue_ = "' + $sanText + '"'),
    '2.5.29.37 = "{text}"',
    '_continue_ = "1.3.6.1.5.5.7.3.1"'
)
Set-Content -LiteralPath $infPath -Value $infLines -Encoding ascii -Force
& $certreq -new $infPath $csrPath | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $csrPath -PathType Leaf)) {
    throw "certreq -new konnte keine CSR erzeugen (Exit-Code $LASTEXITCODE)."
}

$csrText = [System.IO.File]::ReadAllText($csrPath, [System.Text.Encoding]::ASCII)
if ($csrText -notmatch 'BEGIN (NEW )?CERTIFICATE REQUEST') {
    throw 'certreq lieferte keine PEM-kodierte Zertifikatsanfrage.'
}
$marker = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($csrText))
$Ansible.Result = @{ CsrMarker = $marker; RequestPath = $csrPath }
$Ansible.Changed = $true
'''
    return [{
        "name": "Mavi WinRM TLS CSR sicher auf Windows erzeugen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Nicht exportierbaren WinRM-Serverschlüssel und CSR erstellen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "Fqdn": identity["fqdn"],
                        "ShortName": identity["short_name"],
                        "IpSan": ip_san,
                        "RequestId": request_id,
                    },
                },
                "register": "mavi_winrm_csr",
            },
            {
                "name": "Mavi WinRM CSR an den Controller zurückgeben",
                "ansible.builtin.debug": {
                    "msg": "Mavi_WINRM_CSR_B64_BEGIN={{ mavi_winrm_csr.result.CsrMarker }}_END",
                },
            },
        ],
    }]


def _extract_winrm_csr(play_output: str) -> bytes:
    """Die nur öffentliche CSR aus der Ansible-Ausgabe eindeutig entnehmen."""
    match = re.search(
        r"Mavi_WINRM_CSR_B64_BEGIN=([A-Za-z0-9+/=\s]+?)_END",
        str(play_output or ""),
    )
    if not match:
        raise RuntimeError("Die Windows-CSR wurde nicht vollständig an Mavi zurückgegeben.")
    encoded = re.sub(r"\s+", "", match.group(1))
    try:
        csr = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError("Die Windows-CSR ist nicht gültig Base64-kodiert.") from exc
    decoded = csr.decode("ascii", errors="replace")
    if "BEGIN CERTIFICATE REQUEST" not in decoded and "BEGIN NEW CERTIFICATE REQUEST" not in decoded:
        raise RuntimeError("Die zurückgegebene Windows-CSR hat kein erwartetes PEM-Format.")
    return csr


def _winrm_install_https_play(
    *,
    certificate_path: str,
    certificate_sha256: str,
    ca_certificate_path: str,
    ca_certificate_sha256: str,
    identity: dict[str, Any],
    settings: dict[str, Any],
    ansible_server_ip: str,
) -> list[dict[str, Any]]:
    """Play für Zertifikatsannahme, HTTPS-Listener und enges Firewall-Scoping."""
    powershell = r'''[CmdletBinding()]
param(
    [string]$CertificatePath,
    [string]$ExpectedSha256,
    [string]$RootCertificatePath,
    [string]$ExpectedRootSha256,
    [string]$Fqdn,
    [string]$AnsibleServerIp,
    [int]$Port,
    [string]$RuleName
)

$ErrorActionPreference = 'Stop'
if ($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Mavi WinRM TLS: erwarteter Zertifikats-SHA-256 ist ungültig.'
}
if ($ExpectedRootSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Mavi WinRM TLS: erwarteter Root-CA-SHA-256 ist ungültig.'
}
if ($Port -lt 1 -or $Port -gt 65535) {
    throw 'Mavi WinRM TLS: Port ist ungültig.'
}
$parsedAnsibleIp = $null
if (-not [System.Net.IPAddress]::TryParse($AnsibleServerIp, [ref]$parsedAnsibleIp)) {
    throw "Mavi WinRM TLS: ansible_server_ip ist ungültig: $AnsibleServerIp"
}
if ($parsedAnsibleIp.Equals([System.Net.IPAddress]::Any) -or $parsedAnsibleIp.Equals([System.Net.IPAddress]::IPv6Any)) {
    throw 'Mavi WinRM TLS: ansible_server_ip darf kein Wildcard-Wert sein.'
}
if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
    throw "Mavi WinRM TLS: signiertes Zertifikat fehlt: $CertificatePath"
}
if (-not (Test-Path -LiteralPath $RootCertificatePath -PathType Leaf)) {
    throw "Mavi WinRM TLS: öffentliche Mavi-Root-CA fehlt: $RootCertificatePath"
}
$actualSha256 = [string](Get-FileHash -LiteralPath $CertificatePath -Algorithm SHA256 -ErrorAction Stop).Hash
if (-not $actualSha256.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "SICHERHEITSABBRUCH: WinRM-Zertifikat wurde vor der Annahme verändert. Erwartet=$ExpectedSha256 Ist=$actualSha256"
}
$actualRootSha256 = [string](Get-FileHash -LiteralPath $RootCertificatePath -Algorithm SHA256 -ErrorAction Stop).Hash
if (-not $actualRootSha256.Equals($ExpectedRootSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "SICHERHEITSABBRUCH: Mavi-WinRM-Root-CA wurde vor der Annahme verändert. Erwartet=$ExpectedRootSha256 Ist=$actualRootSha256"
}

$rootCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($RootCertificatePath)
$basicConstraints = @($rootCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
if ($basicConstraints.Count -ne 1) {
    throw 'Mavi WinRM TLS: die bereitgestellte Root-CA hat keine eindeutige Basic-Constraints-Erweiterung.'
}
$decodedConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()
$decodedConstraints.CopyFrom($basicConstraints[0])
if (-not $decodedConstraints.CertificateAuthority) {
    throw 'Mavi WinRM TLS: die bereitgestellte Root-CA ist kein CA-Zertifikat.'
}
Import-Certificate -FilePath $RootCertificatePath -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null

$certreq = Join-Path $env:WINDIR 'System32\certreq.exe'
& $certreq -accept $CertificatePath | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "certreq -accept konnte das Mavi-WinRM-Zertifikat nicht annehmen (Exit-Code $LASTEXITCODE)."
}

$selected = $null
foreach ($candidate in @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop)) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $candidateHash = ([System.BitConverter]::ToString($sha.ComputeHash($candidate.RawData))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
    if ($candidateHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        $selected = $candidate
        break
    }
}
if ($null -eq $selected) {
    throw 'Mavi WinRM TLS: das exakt signierte Zertifikat wurde nicht im LocalMachine\\My Store gefunden.'
}
if (-not $selected.HasPrivateKey) {
    throw 'Mavi WinRM TLS: das angenommene Zertifikat hat keinen lokalen privaten Schlüssel.'
}
if (-not $selected.Issuer.Equals($rootCertificate.Subject, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Mavi WinRM TLS: das Serverzertifikat wurde nicht von der erwarteten Mavi-Root-CA ausgestellt.'
}
if ($selected.NotAfter -le (Get-Date).AddDays(1)) {
    throw 'Mavi WinRM TLS: das angenommene Zertifikat läuft zu früh ab.'
}
$hasServerAuth = $false
foreach ($extension in @($selected.Extensions)) {
    if ([string]$extension.Oid.Value -ne '2.5.29.37') { continue }
    $ekuExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension
    foreach ($usage in @($ekuExtension.EnhancedKeyUsages)) {
        if ([string]$usage.Value -eq '1.3.6.1.5.5.7.3.1') {
            $hasServerAuth = $true
            break
        }
    }
    if ($hasServerAuth) { break }
}
if (-not $hasServerAuth) {
    throw 'Mavi WinRM TLS: dem Zertifikat fehlt Server Authentication EKU.'
}
$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
if (-not $chain.Build($selected)) {
    $chainStatus = (@($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }) -join '; ')
    throw "Mavi WinRM TLS: die lokale Windows-Zertifikatskette ist nicht gültig: $chainStatus"
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
if (-not $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "SICHERHEITSABBRUCH: Die OpenSSH-Sitzung von $($currentIdentity.Name) besitzt keinen erhöhten lokalen Administrator-Token."
}

$httpBlockRuleName = 'Mavi-WinRM-HTTP-Dauerhaft-Block-TCP'
$setupIsolationRuleName = 'Mavi-WinRM-HTTPS-Setup-Isolation-TCP'
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'

# Ein früherer, abgebrochener Lauf kann Negotiate bereits deaktiviert haben.
# Der lokale WSMan:-Provider verwaltet selbst localhost:47001 und würde sich
# dann selbst aussperren. Vor der ausschließlich lokalen Reparatur werden
# deshalb beide Netzwerkports vollständig abgeschottet. Block-Regeln haben
# unter Windows Vorrang vor eventuell vorhandenen Allow-Regeln.
Get-NetFirewallRule -DisplayName $httpBlockRuleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $httpBlockRuleName -Group 'Mavi Provisioner' -Direction Inbound -Action Block -Profile Any -Protocol TCP -LocalPort 5985 -RemoteAddress Any -EdgeTraversalPolicy Block | Out-Null
Get-NetFirewallRule -DisplayName $setupIsolationRuleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $setupIsolationRuleName -Group 'Mavi Provisioner' -Direction Inbound -Action Block -Profile Any -Protocol TCP -LocalPort $Port -RemoteAddress Any -EdgeTraversalPolicy Block | Out-Null

New-Item -Path $policyPath -Force | Out-Null
# Nur während vollständig blockierter 5985/5986-Ports darf der lokale
# WSMan-Provider wieder administrieren. Von außen ist Negotiate dabei niemals
# erreichbar. Der finally-Block erzwingt anschließend wieder Kerberos-only.
Set-ItemProperty -Path $policyPath -Name AllowNegotiate -Type DWord -Value 1 -Force
Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
Restart-Service -Name WinRM -Force -ErrorAction Stop

try {
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $true -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $false -Force -ErrorAction Stop

    $httpsListeners = @(
        Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
        Where-Object { $_.Keys -contains 'Transport=HTTPS' }
    )
    if ($httpsListeners.Count -gt 0) {
        $managedExistingListeners = @()
        foreach ($listener in $httpsListeners) {
            # WSMan-Listener stellen Hostname, Port und Fingerabdruck als
            # Kindelemente bereit, nicht verlässlich als direkte Eigenschaften
            # des Listener-Containers. Direkter Property-Zugriff lieferte bei
            # einem vorhandenen Listener einen leeren Fingerabdruck; der daraus
            # gebildete Cert:-Pfad zeigte dann auf den gesamten X509Store.
            $listenerValues = @{}
            foreach ($listenerValue in @(Get-ChildItem -LiteralPath $listener.PSPath -ErrorAction Stop)) {
                $listenerValueName = [string]$listenerValue.Name
                if (-not [string]::IsNullOrWhiteSpace($listenerValueName)) {
                    $listenerValues[$listenerValueName] = [string]$listenerValue.Value
                }
            }
            $listenerThumbprint = ([string]$listenerValues['CertificateThumbprint']).Trim() -replace '\s', ''
            $listenerHostname = ([string]$listenerValues['Hostname']).Trim()
            $listenerPort = 0
            $listenerPortIsValid = [int]::TryParse(
                ([string]$listenerValues['Port']).Trim(),
                [ref]$listenerPort
            )
            if ($listenerThumbprint -notmatch '^[a-fA-F0-9]{40}$') {
                throw 'SICHERHEITSABBRUCH: Ein vorhandener WinRM-HTTPS-Listener enthält keinen gültigen Zertifikatfingerabdruck. Mavi verändert diesen TLS-Endpunkt nicht.'
            }
            $listenerCertificate = Get-Item -LiteralPath ("Cert:\LocalMachine\My\$listenerThumbprint") -ErrorAction SilentlyContinue
            $listenerChainIsMavi = $false
            if ($listenerCertificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                $listenerChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                $listenerChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                try {
                    if ($listenerChain.Build($listenerCertificate) -and $listenerChain.ChainElements.Count -gt 0) {
                        $listenerRoot = $listenerChain.ChainElements[$listenerChain.ChainElements.Count - 1].Certificate
                        $listenerChainIsMavi = $listenerRoot.Thumbprint.Equals(
                            $rootCertificate.Thumbprint,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }
                }
                finally {
                    $listenerChain.Dispose()
                }
            }
            $expectedFriendlyName = "Mavi WinRM HTTPS $Fqdn"
            $listenerIsMaviManaged = (
                $listenerPortIsValid -and
                ($listenerPort -eq $Port) -and
                $listenerHostname.Equals($Fqdn, [System.StringComparison]::OrdinalIgnoreCase) -and
                ($listenerCertificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) -and
                ([string]$listenerCertificate.FriendlyName).Equals($expectedFriendlyName, [System.StringComparison]::Ordinal) -and
                $listenerChainIsMavi
            )
            if (-not $listenerIsMaviManaged) {
                throw 'SICHERHEITSABBRUCH: Es existiert bereits ein fremder WinRM-HTTPS-Listener. Mavi ersetzt fremde TLS-Endpunkte nie still.'
            }
            $managedExistingListeners += [PSCustomObject]@{
                Listener = $listener
                CertificateThumbprint = $listenerThumbprint
            }
        }

        $alreadyCurrent = @(
            $managedExistingListeners | Where-Object {
                ([string]$_.CertificateThumbprint).Equals($selected.Thumbprint, [System.StringComparison]::OrdinalIgnoreCase)
            }
        )
        if ($managedExistingListeners.Count -ne 1 -or $alreadyCurrent.Count -ne 1) {
            foreach ($listener in $managedExistingListeners) {
                Remove-Item -LiteralPath $listener.Listener.PSPath -Recurse -Force -ErrorAction Stop
            }
            New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Transport = 'HTTPS'; Address = '*' } -ValueSet @{ Hostname = $Fqdn; CertificateThumbprint = $selected.Thumbprint } -ErrorAction Stop | Out-Null
        }
    }
    else {
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Transport = 'HTTPS'; Address = '*' } -ValueSet @{ Hostname = $Fqdn; CertificateThumbprint = $selected.Thumbprint } -ErrorAction Stop | Out-Null
    }

$existingAllowRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    $portFilter = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
    foreach ($filter in $portFilter) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains [string]$Port) {
            if ([string]$rule.DisplayName -ne $RuleName) { $existingAllowRules += $rule }
        }
    }
}
if ($existingAllowRules.Count -gt 0) {
    $names = ($existingAllowRules | Select-Object -ExpandProperty DisplayName -Unique) -join ', '
    throw "SICHERHEITSABBRUCH: Bereits aktive Firewall-Freigabe(n) für TCP/$Port gefunden: $names. Mavi lässt keinen breiteren parallelen HTTPS-Zugang stehen."
}
Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $RuleName -Group 'Mavi Provisioner' -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort $Port -RemoteAddress $AnsibleServerIp -EdgeTraversalPolicy Block | Out-Null
$managedRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
$managedPort = @($managedRule | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object -First 1)
$managedAddress = @($managedRule | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object -First 1)
if ($managedPort.Count -ne 1 -or [string]$managedPort[0].Protocol -ne 'TCP' -or -not (@($managedPort[0].LocalPort) -contains [string]$Port)) {
    throw 'Mavi WinRM TLS: die eigene TCP-Port-Firewallregel konnte nicht exakt geprüft werden.'
}
$managedRemoteAddresses = @($managedAddress[0].RemoteAddress)
if ($managedAddress.Count -ne 1 -or $managedRemoteAddresses.Count -ne 1 -or [string]$managedRemoteAddresses[0] -ne $AnsibleServerIp) {
    throw 'Mavi WinRM TLS: die eigene Firewallregel ist nicht exakt auf die Ansible-IP beschränkt.'
}

# HTTP vollständig entfernen, solange der lokale Provider in der isolierten
# Phase noch erreichbar ist. Die dauerhafte Block-Regel für 5985 bleibt auch
# danach bestehen.
$httpListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
foreach ($listener in $httpListeners) {
    Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
}
$remainingHttpListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
if ($remainingHttpListeners.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens ein WinRM-HTTP-Listener ist weiterhin aktiv.'
}
$httpFirewallAllowRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $httpFirewallAllowRules += $rule
            break
        }
    }
}
foreach ($rule in @($httpFirewallAllowRules | Select-Object -Unique)) {
    Disable-NetFirewallRule -InputObject $rule -ErrorAction Stop | Out-Null
}
}
finally {
    # Diese ADMX-gestützten Dienstwerte sind die fail-closed Endstellung.
    # Der Block für 5986 bleibt bei jedem Fehler erhalten. Damit ist während
    # und nach einem fehlgeschlagenen Lauf weder HTTP noch Negotiate von außen
    # erreichbar; OpenSSH bleibt als Reparaturkanal bestehen.
    New-Item -Path $policyPath -Force | Out-Null
    Set-ItemProperty -Path $policyPath -Name AllowUnencryptedTraffic -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name AllowKerberos -Type DWord -Value 1 -Force
    Set-ItemProperty -Path $policyPath -Name AllowNegotiate -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name AllowBasic -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name AllowCredSSP -Type DWord -Value 0 -Force
    Restart-Service -Name WinRM -Force -ErrorAction Stop
}

$finalPolicy = Get-ItemProperty -Path $policyPath -ErrorAction Stop
if ([int]$finalPolicy.AllowUnencryptedTraffic -ne 0 -or
    [int]$finalPolicy.AllowKerberos -ne 1 -or
    [int]$finalPolicy.AllowNegotiate -ne 0 -or
    [int]$finalPolicy.AllowBasic -ne 0 -or
    [int]$finalPolicy.AllowCredSSP -ne 0) {
    throw 'SICHERHEITSABBRUCH: Die WinRM-Dienstrichtlinie ist nicht Kerberos-only.'
}
$remainingHttpAllowRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $remainingHttpAllowRules += $rule
            break
        }
    }
}
if ($remainingHttpAllowRules.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens eine TCP/5985-Firewallfreigabe ist weiterhin aktiv.'
}

# Erst nach dem finalen Service-Neustart fällt die Setup-Isolation für 5986.
# Die enge Allow-Regel von ausschließlich der Ansible-IP bleibt bestehen.
Get-NetFirewallRule -DisplayName $setupIsolationRuleName -ErrorAction Stop |
    Remove-NetFirewallRule -ErrorAction Stop

$result = [ordered]@{
    Thumbprint = $selected.Thumbprint
    CertificateSha256 = $actualSha256.ToLowerInvariant()
    Fqdn = $Fqdn
    Port = $Port
    FirewallRule = $RuleName
    Http5985Blocked = $true
    KerberosOnly = $true
}
$marker = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress)))
$Ansible.Result = @{ Marker = $marker }
$Ansible.Changed = $true
'''
    remote_dir = r"C:\ProgramData\Mavi\WinRM-TLS"
    remote_path = remote_dir + r"\mavi-winrm-server.cer"
    remote_ca_path = remote_dir + r"\mavi-winrm-root-ca.cer"
    return [{
        "name": "Mavi WinRM HTTPS sicher einrichten",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Mavi WinRM TLS-Arbeitsordner sicherstellen",
                "ansible.windows.win_file": {"path": remote_dir, "state": "directory"},
            },
            {
                "name": "Öffentliche Mavi-WinRM-Root-CA nach Windows kopieren",
                "ansible.windows.win_copy": {
                    "src": ca_certificate_path,
                    "dest": remote_ca_path,
                    "force": True,
                },
            },
            {
                "name": "Signiertes Mavi-WinRM-Zertifikat nach Windows kopieren",
                "ansible.windows.win_copy": {
                    "src": certificate_path,
                    "dest": remote_path,
                    "force": True,
                },
            },
            {
                "name": "WinRM HTTPS-Listener und enge Firewallregel konfigurieren",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "CertificatePath": remote_path,
                        "ExpectedSha256": certificate_sha256,
                        "RootCertificatePath": remote_ca_path,
                        "ExpectedRootSha256": ca_certificate_sha256,
                        "Fqdn": identity["fqdn"],
                        "AnsibleServerIp": ansible_server_ip,
                        "Port": int(settings["port"]),
                        "RuleName": "Mavi-WinRM-HTTPS-Ansible-In-TCP",
                    },
                },
                "register": "mavi_winrm_https_install",
            },
            {
                "name": "Mavi WinRM HTTPS-Ergebnis auslesen",
                "ansible.builtin.debug": {
                    "msg": "Mavi_WINRM_HTTPS_B64={{ mavi_winrm_https_install.result.Marker }}",
                },
            },
        ],
    }]


def _winrm_remove_http_play() -> list[dict[str, Any]]:
    """HTTP-Listener ausschließlich über die bereits geprüfte TLS-Verbindung entfernen."""
    powershell = r'''[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$httpListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
foreach ($listener in $httpListeners) {
    Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
}
$remaining = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
if ($remaining.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens ein WinRM-HTTP-Listener ist weiterhin aktiv.'
}
$httpFirewallRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $httpFirewallRules += $rule
            break
        }
    }
}
foreach ($rule in @($httpFirewallRules | Select-Object -Unique)) {
    Disable-NetFirewallRule -InputObject $rule -ErrorAction Stop | Out-Null
}
$stillEnabled = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $stillEnabled += $rule
            break
        }
    }
}
if ($stillEnabled.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens eine TCP/5985-Firewallfreigabe ist weiterhin aktiv.'
}
$Ansible.Result = @{ RemovedHttpListeners = $httpListeners.Count }
$Ansible.Changed = ($httpListeners.Count -gt 0)
'''
    return [{
        "name": "Mavi WinRM HTTP nach HTTPS-Nachweis abschalten",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Alte WinRM-HTTP-Listener entfernen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                },
            },
        ],
    }]


def _winrm_reset_play(
    *,
    root_thumbprint: str,
    disable_openssh: bool = False,
    public_key_prefix: str = "",
    key_marker: str = "",
    openssh_firewall_rule: str = "",
) -> list[dict[str, Any]]:
    """Mavi-WinRM über den unabhängigen OpenSSH-Kanal auf Stand 0 setzen."""
    powershell = r'''[CmdletBinding()]
param(
    [string]$RootThumbprint = '',
    [int]$DisableOpenSshValue = 0,
    [string]$CurrentKeyPrefix = '',
    [string]$CurrentKeyMarker = '',
    [string]$OpenSshFirewallRuleName = ''
)

$ErrorActionPreference = 'Stop'
$disableOpenSsh = ($DisableOpenSshValue -eq 1)
$RootThumbprint = ($RootThumbprint -replace '\s', '').ToUpperInvariant()
if (-not [string]::IsNullOrWhiteSpace($RootThumbprint) -and $RootThumbprint -notmatch '^[A-F0-9]{40}$') {
    throw 'Mavi WinRM Reset: Der Root-CA-Fingerabdruck ist ungültig.'
}
if ($disableOpenSsh -and $OpenSshFirewallRuleName -notmatch '^[A-Za-z0-9_.-]{1,255}$') {
    throw 'Mavi Remote-Aus: Der Name der OpenSSH-Firewallregel ist ungültig.'
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Mavi WinRM Reset benötigt einen erhöhten lokalen Administrator-Token; aktuell: $($identity.Name)"
}

$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
$policyNames = @(
    'AllowUnencryptedTraffic',
    'AllowKerberos',
    'AllowNegotiate',
    'AllowBasic',
    'AllowCredSSP'
)
$firewallNames = @(
    'Mavi-WinRM-HTTPS-Ansible-In-TCP',
    'Mavi-WinRM-HTTP-Dauerhaft-Block-TCP',
    'Mavi-WinRM-HTTPS-Setup-Isolation-TCP'
)
$workDirectory = Join-Path $env:ProgramData 'Mavi\WinRM-TLS'
$removedListeners = 0
$removedCertificates = 0
$removedFirewallRules = 0
$removedOpenSshKeys = 0
$openSshDisableScheduled = $false
$cleanupError = $null

try {
    # Ein Mavi-Endzustand blockiert Negotiate per Richtlinie. Für die lokale
    # WSMan:-Verwaltung über die unabhängige SSH-Sitzung wird es kurz aktiviert.
    New-Item -Path $policyPath -Force | Out-Null
    Set-ItemProperty -Path $policyPath -Name AllowNegotiate -Type DWord -Value 1 -Force
    Set-Service -Name WinRM -StartupType Manual -ErrorAction Stop
    Start-Service -Name WinRM -ErrorAction SilentlyContinue
    Restart-Service -Name WinRM -Force -ErrorAction Stop

    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $true -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false -Force -ErrorAction Stop

    $listeners = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop)
    foreach ($listener in $listeners) {
        Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
        $removedListeners++
    }

    foreach ($name in $firewallNames) {
        $rules = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
        foreach ($rule in $rules) {
            Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
            $removedFirewallRules++
        }
    }

    $effectiveRootThumbprint = $RootThumbprint
    $remoteRootPath = Join-Path $workDirectory 'mavi-winrm-root-ca.cer'
    if ([string]::IsNullOrWhiteSpace($effectiveRootThumbprint) -and (Test-Path -LiteralPath $remoteRootPath -PathType Leaf)) {
        $remoteRoot = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($remoteRootPath)
        $effectiveRootThumbprint = ([string]$remoteRoot.Thumbprint).ToUpperInvariant()
    }

    $rootSubject = ''
    if ($effectiveRootThumbprint -match '^[A-F0-9]{40}$') {
        $rootCertificate = Get-Item -LiteralPath ("Cert:\LocalMachine\Root\$effectiveRootThumbprint") -ErrorAction SilentlyContinue
        if ($null -ne $rootCertificate) {
            $rootSubject = [string]$rootCertificate.Subject
        }
    }

    foreach ($storePath in @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Request')) {
        if (-not (Test-Path -LiteralPath $storePath)) { continue }
        foreach ($certificate in @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue)) {
            $isMaviLeaf = ([string]$certificate.FriendlyName) -like 'Mavi WinRM HTTPS *'
            if (-not [string]::IsNullOrWhiteSpace($rootSubject)) {
                $isMaviLeaf = $isMaviLeaf -or ([string]$certificate.Issuer).Equals(
                    $rootSubject,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            }
            if ($isMaviLeaf) {
                Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
                $removedCertificates++
            }
        }
    }

    if ($effectiveRootThumbprint -match '^[A-F0-9]{40}$') {
        $rootPath = "Cert:\LocalMachine\Root\$effectiveRootThumbprint"
        if (Test-Path -LiteralPath $rootPath) {
            Remove-Item -LiteralPath $rootPath -Force -ErrorAction Stop
            $removedCertificates++
        }
    }

    if (Test-Path -LiteralPath $workDirectory) {
        Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction Stop
    }
}
catch {
    $cleanupError = $_.Exception.Message
}
finally {
    if (Test-Path -LiteralPath $policyPath) {
        foreach ($name in $policyNames) {
            Remove-ItemProperty -LiteralPath $policyPath -Name $name -Force -ErrorAction SilentlyContinue
        }
    }
    Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
    Set-Service -Name WinRM -StartupType Disabled -ErrorAction Stop
}

if (-not [string]::IsNullOrWhiteSpace($cleanupError)) {
    throw "Mavi WinRM Reset wurde nicht vollständig ausgeführt: $cleanupError"
}

$remainingListeners = 0
try {
    $remainingListeners = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop).Count
}
catch {
    # Der Dienst ist jetzt absichtlich deaktiviert. Die zuvor erfolgreiche
    # Entfernung ist der maßgebliche Listener-Nachweis.
    $remainingListeners = 0
}
$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
if ($remainingListeners -ne 0 -or [string]$service.State -ne 'Stopped' -or [string]$service.StartMode -ne 'Disabled') {
    throw 'Mavi WinRM Reset: Der abschließende Stand-0-Nachweis ist fehlgeschlagen.'
}

if ($disableOpenSsh) {
    $sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($null -eq $sshdService) {
        throw 'Mavi Remote-Aus: Der OpenSSH-Serverdienst sshd wurde nicht gefunden.'
    }

    # Der laufende SSH-Kanal darf seine Erfolgsmeldung noch zurückgeben. Der
    # Dienst wird bereits jetzt für jeden Neustart deaktiviert und wenige
    # Sekunden später durch einen einmaligen SYSTEM-Task gestoppt.
    Set-Service -Name sshd -StartupType Disabled -ErrorAction Stop

    $keyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    if (Test-Path -LiteralPath $keyFile -PathType Leaf) {
        $keyLines = @(Get-Content -LiteralPath $keyFile -ErrorAction Stop)
        $keptKeyLines = New-Object 'System.Collections.Generic.List[string]'
        foreach ($keyLineObject in $keyLines) {
            $keyLine = [string]$keyLineObject
            $trimmedKeyLine = $keyLine.Trim()
            $isMaviKey = $false
            if (-not [string]::IsNullOrWhiteSpace($CurrentKeyMarker)) {
                $markerPattern = '(^|\s)' + [regex]::Escape($CurrentKeyMarker) + '(\s|$)'
                $isMaviKey = $trimmedKeyLine -match $markerPattern
            }
            if (
                -not $isMaviKey -and
                -not [string]::IsNullOrWhiteSpace($CurrentKeyPrefix) -and
                ($trimmedKeyLine -eq $CurrentKeyPrefix -or $trimmedKeyLine.StartsWith($CurrentKeyPrefix + ' '))
            ) {
                $isMaviKey = $true
            }
            if ($isMaviKey) {
                $removedOpenSshKeys++
                continue
            }
            $keptKeyLines.Add($keyLine)
        }
        if ($removedOpenSshKeys -gt 0) {
            [System.IO.File]::WriteAllLines(
                $keyFile,
                [string[]]$keptKeyLines,
                [System.Text.Encoding]::ASCII
            )
        }
    }

    $taskName = 'Mavi-Disable-RemoteAccess-' + [Guid]::NewGuid().ToString('N')
    $childScript = @'
$ErrorActionPreference = 'SilentlyContinue'
Start-Sleep -Seconds 20
Get-NetFirewallRule -Name '__MAVI_FIREWALL_RULE_NAME__' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
Set-Service -Name sshd -StartupType Disabled -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName '__MAVI_TASK_NAME__' -Confirm:$false -ErrorAction SilentlyContinue
'@
    $childScript = $childScript.Replace('__MAVI_TASK_NAME__', $taskName)
    $childScript = $childScript.Replace('__MAVI_FIREWALL_RULE_NAME__', $OpenSshFirewallRuleName)
    $encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $taskAction = New-ScheduledTaskAction `
        -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encodedScript"
    $taskPrincipal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 2) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $taskAction `
        -Principal $taskPrincipal `
        -Settings $taskSettings `
        -Force | Out-Null
    $beforeTaskRun = (Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop).LastRunTime
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $taskStartDeadline = (Get-Date).AddSeconds(6)
    do {
        Start-Sleep -Milliseconds 250
        $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $scheduledTaskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        if ($scheduledTask.State -eq 'Running' -or $scheduledTaskInfo.LastRunTime -gt $beforeTaskRun) {
            $openSshDisableScheduled = $true
            break
        }
    } while ((Get-Date) -lt $taskStartDeadline)
    if (-not $openSshDisableScheduled) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        throw 'Mavi Remote-Aus: Der verzögerte sshd-Stopp konnte nicht gestartet werden.'
    }
}

$Ansible.Result = @{
    RemovedListeners = $removedListeners
    RemovedCertificates = $removedCertificates
    RemovedFirewallRules = $removedFirewallRules
    RemovedOpenSshKeys = $removedOpenSshKeys
    OpenSshDisableScheduled = $openSshDisableScheduled
    WinRMState = [string]$service.State
    WinRMStartMode = [string]$service.StartMode
}
$Ansible.Changed = $true
'''
    return [{
        "name": "Mavi WinRM und Kerberos-Transport auf Stand 0 zurücksetzen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "WinRM-Listener, Mavi-Zertifikate, Regeln und Richtlinien entfernen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "RootThumbprint": root_thumbprint,
                        "DisableOpenSshValue": 1 if disable_openssh else 0,
                        "CurrentKeyPrefix": public_key_prefix,
                        "CurrentKeyMarker": key_marker,
                        "OpenSshFirewallRuleName": openssh_firewall_rule,
                    },
                },
            },
        ],
    }]


def _winrm_kerberos_https_ping_play() -> list[dict[str, Any]]:
    """Minimaler echter PSRP-Test; die Aufrufer legen die TLS/Kerberos-Variablen als Overlay fest."""
    return [{
        "name": "Mavi Kerberos-HTTPS-Nachweis",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "PSRP über strikt validiertes HTTPS und Kerberos prüfen",
                "ansible.windows.win_ping": {},
            },
        ],
    }]


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


def _powershell_single_quote(value: str) -> str:
    return value.replace("'", "''")


def _windows_msi_path_for_ssh_guide(project: Path, raw: str, *, announce: bool = True) -> str:
    """
    Einen vom Admin eingegebenen OpenSSH-MSI-Pfad für den Windows-Bootstrap
    aufbereiten. Windows-Laufwerks- und Linux-Pfade aus der Mavi-Softwareablage werden, wenn
    möglich, in den UNC-Pfad der Softwareablage übersetzt. Das ist für eine
    erhöhte PowerShell robuster, weil gemappte Laufwerke dort fehlen können.
    """
    value = str(raw or "").strip().strip('"').strip("'")
    if not value:
        return ""

    config = get_config(project)
    source = config.get("software_source", {}) or {}
    drive = str(source.get("drive", "") or "").strip()
    unc_root = str(source.get("unc_root", "") or "").strip().rstrip("\\/")
    local_root = str(source.get("local_root", "") or "").strip().rstrip("/")

    # S:\foo\bar.msi -> \\server\share\foo\bar.msi
    if drive and unc_root:
        drive_norm = drive.replace("/", "\\")
        value_norm = value.replace("/", "\\")
        if value_norm.lower().startswith(drive_norm.lower()):
            rel = value_norm[len(drive_norm):].lstrip("\\/")
            converted = unc_root + ("\\" + rel if rel else "")
            if announce:
                print("\n✓ MSI-Pfad für Admin-PowerShell als UNC verwendet:")
                print(f"  {value}")
                print("  →")
                print(f"  {converted}")
            return converted

    # /mnt/.../Install/foo.msi -> \\server\share\foo.msi
    if local_root and unc_root:
        try:
            local_candidate = Path(value).expanduser()
            root_candidate = Path(local_root).expanduser()
            rel = local_candidate.relative_to(root_candidate)
        except (ValueError, OSError):
            rel = None
        if rel is not None:
            converted = unc_root + "\\" + str(rel).replace("/", "\\")
            if announce:
                print("\n✓ Serverpfad für Windows als UNC verwendet:")
                print(f"  {value}")
                print("  →")
                print(f"  {converted}")
            return converted

    return value


def _ssh_bootstrap_ps1(
    public_key: str,
    *,
    bundled_msi: bool,
    msi_path: str = "",
    msi_download_url: str = "",
    msi_sha256: str = "",
    expected_signer: str = "",
    ansible_server_ip: str = "",
    bootstrap_instance_id: str = "",
    bootstrap_ca_thumbprint: str = "",
) -> str:
    """Gehärteten PowerShell-Bootstrap für OpenSSH auf Windows erzeugen."""
    public_key = str(public_key or "").strip()
    if (
        len(public_key) > 16384
        or "\r" in public_key
        or "\n" in public_key
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9@._+-]*[ \t]+[A-Za-z0-9+/]+={0,3}(?:[ \t]+[^\x00-\x1f\x7f]+)?",
            public_key,
        )
    ):
        raise ValueError("Der Mavi-Public-Key ist nicht genau eine gültige OpenSSH-Public-Key-Zeile.")
    for label, value in (
        ("MSI-Pfad", msi_path),
        ("MSI-URL", msi_download_url),
        ("erwarteter MSI-Signer", expected_signer),
    ):
        if "\r" in str(value or "") or "\n" in str(value or ""):
            raise ValueError(f"{label} darf keine Zeilenumbrüche enthalten.")
    if msi_download_url and urllib.parse.urlsplit(msi_download_url).scheme.lower() != "https":
        raise ValueError("Die OpenSSH-MSI darf nur über HTTPS geladen werden.")
    if msi_sha256 and not re.fullmatch(r"[0-9A-Fa-f]{64}", str(msi_sha256)):
        raise ValueError("Der OpenSSH-MSI-Hash muss aus exakt 64 Hex-Zeichen bestehen.")
    if not re.fullmatch(r"[a-z0-9-]{1,64}", str(bootstrap_instance_id or "")):
        raise ValueError("Die Bootstrap-Instanzkennung ist ungültig.")
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", str(bootstrap_ca_thumbprint or "")):
        raise ValueError("Der Bootstrap-CA-Thumbprint ist ungültig.")
    ps_key = _powershell_single_quote(public_key)
    ps_msi = _powershell_single_quote(msi_path)
    ps_msi_url = _powershell_single_quote(msi_download_url)
    ps_msi_sha256 = _powershell_single_quote(msi_sha256.lower())
    ps_expected_signer = _powershell_single_quote(expected_signer)
    ps_ansible_ip = _powershell_single_quote(ansible_server_ip)
    ps_instance_id = _powershell_single_quote(bootstrap_instance_id)
    ps_ca_thumbprint = _powershell_single_quote(bootstrap_ca_thumbprint.upper())

    if msi_download_url:
        msi_assignment_lines = [
            f"$maviMsiUrl = '{ps_msi_url}'",
            "$maviMsiDir = Join-Path $env:TEMP 'Mavi-OpenSSH-Bootstrap'",
            "New-Item -ItemType Directory -Path $maviMsiDir -Force | Out-Null",
            "$msiPath = Join-Path $maviMsiDir 'OpenSSH-Win64.msi'",
            "Write-Host '[1/9] OpenSSH-MSI über HTTPS herunterladen...' -ForegroundColor Cyan",
            "try {",
            "    # Invoke-WebRequest validiert Zertifikatskette und Zielnamen normal.",
            "    # Mavi setzt absichtlich keinen CertificateValidationCallback und kein Skip-Flag.",
            "    Invoke-WebRequest -UseBasicParsing -Uri $maviMsiUrl -OutFile $msiPath -TimeoutSec 120 -MaximumRedirection 0",
            "    if (-not (Test-Path -LiteralPath $msiPath)) { throw 'Downloaddatei wurde nicht angelegt.' }",
            "}",
            "catch {",
            "    Write-Warning \"HTTPS-MSI-Download fehlgeschlagen: $($_.Exception.Message)\"",
            "    Write-Warning 'Mavi verwendet den Windows-Capability/FoD-Fallback.'",
            "    $msiPath = ''",
            "}",
        ]
    elif bundled_msi:
        msi_assignment_lines = ["$msiPath = Join-Path $PSScriptRoot 'OpenSSH-Win64.msi'"]
    else:
        msi_assignment_lines = [f"$msiPath = '{ps_msi}'"]

    lines = [
        f"# Mavi OpenSSH Bootstrap v{VERSION} - automatisch erzeugt",
        "$ErrorActionPreference = 'Stop'",
        "$ProgressPreference = 'SilentlyContinue'",
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
        f"$expectedMsiSha256 = '{ps_msi_sha256}'",
        f"$expectedMsiSigner = '{ps_expected_signer}'",
        f"$ansibleServerIp = '{ps_ansible_ip}'",
        f"$maviInstanceId = '{ps_instance_id}'",
        f"$maviCaThumbprint = '{ps_ca_thumbprint}'",
        "if ([string]::IsNullOrWhiteSpace($ansibleServerIp)) {",
        "    throw 'SICHERHEITSABBRUCH: ansible_server_ip fehlt. Port 22 wird nicht breit geöffnet.'",
        "}",
        "$parsedAnsibleIp = $null",
        "if (-not [System.Net.IPAddress]::TryParse($ansibleServerIp, [ref]$parsedAnsibleIp)) {",
        "    throw \"SICHERHEITSABBRUCH: Ungültige ansible_server_ip: $ansibleServerIp\"",
        "}",
        "if ($parsedAnsibleIp.Equals([System.Net.IPAddress]::Any) -or $parsedAnsibleIp.Equals([System.Net.IPAddress]::IPv6Any)) {",
        "    throw 'SICHERHEITSABBRUCH: Wildcard-IP ist für ansible_server_ip unzulässig.'",
        "}",
        "",
        "function Assert-MaviMsiTrust {",
        "    param(",
        "        [Parameter(Mandatory=$true)][string]$Path,",
        "        [string]$ExpectedSha256 = '',",
        "        [string]$ExpectedSigner = ''",
        "    )",
        "    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {",
        "        throw \"SICHERHEITSABBRUCH: OpenSSH-MSI fehlt: $Path\"",
        "    }",
        "    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {",
        "        $actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()",
        "        if ($actualSha256 -cne $ExpectedSha256.ToLowerInvariant()) {",
        "            throw \"SICHERHEITSABBRUCH: OpenSSH-MSI SHA-256 stimmt nicht. Erwartet=$ExpectedSha256 Ist=$actualSha256\"",
        "        }",
        "        Write-Host \"    SHA-256: $actualSha256 (gültig)\" -ForegroundColor Green",
        "    }",
        "    $signature = Get-AuthenticodeSignature -LiteralPath $Path",
        "    if ([string]$signature.Status -cne 'Valid' -or $null -eq $signature.SignerCertificate) {",
        "        throw \"SICHERHEITSABBRUCH: Authenticode-Status der OpenSSH-MSI ist '$($signature.Status)', erwartet wird 'Valid'.\"",
        "    }",
        "    $subject = [string]$signature.SignerCertificate.Subject",
        "    $simpleName = [string]$signature.SignerCertificate.GetNameInfo(",
        "        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,",
        "        $false",
        "    )",
        "    if (-not [string]::IsNullOrWhiteSpace($ExpectedSigner) -and",
        "        $subject -ine $ExpectedSigner -and $simpleName -ine $ExpectedSigner) {",
        "        throw \"SICHERHEITSABBRUCH: MSI-Signer stimmt nicht. Erwartet='$ExpectedSigner' Subject='$subject' SimpleName='$simpleName'.\"",
        "    }",
        "    Write-Host \"    Authenticode: Valid | Signer: $subject\" -ForegroundColor Green",
        "}",
        "",
        *msi_assignment_lines,
        "Write-Host '[2/9] OpenSSH Server prüfen...' -ForegroundColor Cyan",
        "$sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue",
        "if (-not $sshd) {",
        "    if (-not [string]::IsNullOrWhiteSpace($msiPath) -and (Test-Path -LiteralPath $msiPath)) {",
        "        Write-Host '[3/9] OpenSSH-MSI prüfen und installieren...' -ForegroundColor Cyan",
        "        Assert-MaviMsiTrust -Path $msiPath -ExpectedSha256 $expectedMsiSha256 -ExpectedSigner $expectedMsiSigner",
        "        $quotedMsi = '\"' + $msiPath + '\"'",
        "        $msi = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\\msiexec.exe') -ArgumentList \"/i $quotedMsi /qn /norestart\" -Wait -PassThru",
        "        if ($msi.ExitCode -notin @(0, 1641, 3010)) {",
        "            Write-Warning \"MSI meldete Exit-Code $($msi.ExitCode). Mavi versucht den Windows-Capability/FoD-Fallback.\"",
        "        }",
        "        else { Write-Host \"    MSI erfolgreich, Exit-Code $($msi.ExitCode).\" -ForegroundColor Green }",
        "    }",
        "    elseif (-not [string]::IsNullOrWhiteSpace($msiPath)) {",
        "        Write-Warning \"MSI nicht erreichbar: $msiPath\"",
        "    }",
        "    $sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue",
        "    if (-not $sshd) {",
        "        Write-Host '[3/9] OpenSSH als Windows Capability installieren (Fallback)...' -ForegroundColor Yellow",
        "        Write-Host '    Dieser Schritt kann über Windows Update/WSUS mehrere Minuten dauern.' -ForegroundColor Yellow",
        "        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1",
        "        if (-not $cap) { throw 'OpenSSH.Server Windows-Capability wurde nicht gefunden.' }",
        "        if ($cap.State -ne 'Installed') { $cap | Add-WindowsCapability -Online | Out-Host }",
        "    }",
        "}",
        "$sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue",
        "if (-not $sshd) { throw 'sshd wurde nach der OpenSSH-Installation nicht gefunden.' }",
        "",
        "Write-Host '[4/9] Fremde TCP/22-Freigaben fail-closed prüfen...' -ForegroundColor Cyan",
        "$maviFirewallName = 'Mavi-OpenSSH-' + $maviInstanceId + '-Ansible-In-TCP'",
        "function Test-MaviPort22Coverage {",
        "    param([object]$LocalPort)",
        "    foreach ($token in @(([string]$LocalPort) -split ',')) {",
        "        $value = $token.Trim()",
        "        if ($value -in @('Any', '*', '22')) { return $true }",
        "        if ($value -match '^(\\d+)\\s*-\\s*(\\d+)$') {",
        "            if ([int]$Matches[1] -le 22 -and [int]$Matches[2] -ge 22) { return $true }",
        "        }",
        "    }",
        "    return $false",
        "}",
        "$unsafeRules = New-Object 'System.Collections.Generic.List[string]'",
        "$allowRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)",
        "foreach ($rule in $allowRules) {",
        "    if ([string]$rule.Name -ceq $maviFirewallName) { continue }",
        "    $isPort22 = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Where-Object {",
        "        $protocol = [string]$_.Protocol",
        "        $tcpOrAny = $protocol -in @('6', '256') -or $protocol -ieq 'TCP' -or $protocol -ieq 'Any'",
        "        $tcpOrAny -and (Test-MaviPort22Coverage $_.LocalPort)",
        "    }).Count -gt 0",
        "    if (-not $isPort22) { continue }",
        "",
        "    # Eine breite Port-/Adressregel ist nur dann ein SSH-Bypass, wenn sie",
        "    # auch auf sshd anwendbar ist. Programmspezifische Regeln fremder",
        "    # Anwendungen (z. B. FortiClient.exe) dürfen nicht als sshd-Freigabe",
        "    # fehlklassifiziert oder verändert werden.",
        "    $appFilters = @($rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)",
        "    $programs = @($appFilters | ForEach-Object { [string]$_.Program } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })",
        "    $packages = @($appFilters | ForEach-Object { [string]$_.Package } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })",
        "    $packageBound = @($packages | Where-Object { $_ -notin @('Any', '*') }).Count -gt 0",
        "    $programCanApplyToSshd = $programs.Count -eq 0 -or @($programs | Where-Object {",
        "        $_ -in @('Any', '*') -or [IO.Path]::GetFileName($_) -ieq 'sshd.exe'",
        "    }).Count -gt 0",
        "    if ($packageBound -or -not $programCanApplyToSshd) { continue }",
        "",
        "    $serviceFilters = @($rule | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue)",
        "    $services = @($serviceFilters | ForEach-Object { [string]$_.Service } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })",
        "    $serviceCanApplyToSshd = $services.Count -eq 0 -or @($services | Where-Object {",
        "        $_ -in @('Any', '*') -or $_ -ieq 'sshd'",
        "    }).Count -gt 0",
        "    if (-not $serviceCanApplyToSshd) { continue }",
        "",
        "    $addresses = @($rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue)",
        "    $onlyController = $addresses.Count -eq 1 -and @($addresses[0].RemoteAddress).Count -eq 1 -and [string]$addresses[0].RemoteAddress -ceq $ansibleServerIp",
        "    if (-not $onlyController) {",
        "        $programSummary = if ($programs.Count -gt 0) { $programs -join '|' } else { 'Any' }",
        "        $serviceSummary = if ($services.Count -gt 0) { $services -join '|' } else { 'Any' }",
        "        $unsafeRules.Add(([string]$rule.DisplayName + ' [' + [string]$rule.Name + '] Program=' + $programSummary + ' Service=' + $serviceSummary))",
        "    }",
        "}",
        "if ($unsafeRules.Count -gt 0) {",
        "    throw ('SICHERHEITSABBRUCH: Bereits aktive fremde TCP/22-Freigaben würden die Controller-Beschränkung umgehen. Mavi verändert sie niemals automatisch. Administrativ prüfen/deaktivieren und erneut starten: ' + ($unsafeRules -join ', '))",
        "}",
        "$existingOwnedRule = Get-NetFirewallRule -Name $maviFirewallName -ErrorAction SilentlyContinue",
        "if ($existingOwnedRule -and [string]$existingOwnedRule.Group -cne 'Mavi Provisioner') {",
        "    throw ('SICHERHEITSABBRUCH: Firewall-Regelname wird von einer fremden Regel belegt: ' + $maviFirewallName)",
        "}",
        "",
        "Write-Host '[5/9] sshd_config über entfernbaren Instanz-Include härten...' -ForegroundColor Cyan",
        "New-Item -ItemType Directory -Path $env:ProgramData\\ssh -Force | Out-Null",
        "$sshdConfig = Join-Path $env:ProgramData 'ssh\\sshd_config'",
        "$sshdConfigPreexisted = Test-Path -LiteralPath $sshdConfig -PathType Leaf",
        "if (-not $sshdConfigPreexisted) { New-Item -ItemType File -Path $sshdConfig -Force | Out-Null }",
        "$maviStateRoot = Join-Path $env:ProgramData ('MaviProvisioner\\bootstrap\\' + $maviInstanceId)",
        "New-Item -ItemType Directory -Path $maviStateRoot -Force | Out-Null",
        "$maviStatePath = Join-Path $maviStateRoot 'state.json'",
        "$maviPreviousState = $null",
        "if (Test-Path -LiteralPath $maviStatePath) { try { $maviPreviousState = Get-Content -LiteralPath $maviStatePath -Raw | ConvertFrom-Json -ErrorAction Stop } catch { throw 'SICHERHEITSABBRUCH: Vorhandener Mavi-Bootstrap-Status ist beschädigt.' } }",
        "$configBackup = Join-Path $maviStateRoot 'sshd_config.pre-mavi.bak'",
        "if (-not (Test-Path -LiteralPath $configBackup)) { Copy-Item -LiteralPath $sshdConfig -Destination $configBackup -Force }",
        "$runConfigBackup = Join-Path $maviStateRoot 'sshd_config.rollback.tmp'",
        "Copy-Item -LiteralPath $sshdConfig -Destination $runConfigBackup -Force",
        "$managedConfigDir = Join-Path $env:ProgramData 'ssh\\sshd_config.d'",
        "New-Item -ItemType Directory -Path $managedConfigDir -Force | Out-Null",
        "$managedConfig = Join-Path $managedConfigDir ('mavi-' + $maviInstanceId + '.conf')",
        "$managedConfigBackup = Join-Path $maviStateRoot 'managed_config.rollback.tmp'",
        "$managedConfigPreexisted = Test-Path -LiteralPath $managedConfig -PathType Leaf",
        "if ($managedConfigPreexisted) { Copy-Item -LiteralPath $managedConfig -Destination $managedConfigBackup -Force }",
        "$beginMarker = '# BEGIN MAVI PROVISIONER ' + $maviInstanceId",
        "$endMarker = '# END MAVI PROVISIONER ' + $maviInstanceId",
        "$configLines = @(Get-Content -LiteralPath $sshdConfig -ErrorAction SilentlyContinue)",
        "$keptConfigLines = New-Object 'System.Collections.Generic.List[string]'",
        "$insideManagedBlock = $false",
        "foreach ($lineObj in $configLines) {",
        "    $line = [string]$lineObj",
        "    if ($line -ceq $beginMarker) { if ($insideManagedBlock) { throw 'SICHERHEITSABBRUCH: Verschachtelter Mavi-sshd-Marker.' }; $insideManagedBlock = $true; continue }",
        "    if ($line -ceq $endMarker) { if (-not $insideManagedBlock) { throw 'SICHERHEITSABBRUCH: Verwaister Mavi-sshd-Endmarker.' }; $insideManagedBlock = $false; continue }",
        "    if (-not $insideManagedBlock) { $keptConfigLines.Add($line) }",
        "}",
        "if ($insideManagedBlock) { throw 'SICHERHEITSABBRUCH: Unvollständiger Mavi-sshd-Marker.' }",
        "$managedDirectives = @('# Mavi Provisioner instance ' + $maviInstanceId, 'PubkeyAuthentication yes', 'PasswordAuthentication no', 'KbdInteractiveAuthentication no')",
        "$configStage = $sshdConfig + '.mavi-stage'",
        "$managedStage = $managedConfig + '.mavi-stage'",
        "$includeLine = 'Include __PROGRAMDATA__/ssh/sshd_config.d/mavi-' + $maviInstanceId + '.conf'",
        "try {",
        "    Set-Content -LiteralPath $managedStage -Value $managedDirectives -Encoding ascii",
        "    Move-Item -LiteralPath $managedStage -Destination $managedConfig -Force",
        "    Set-Content -LiteralPath $configStage -Value (@($beginMarker, $includeLine, $endMarker) + @($keptConfigLines)) -Encoding ascii",
        "    Move-Item -LiteralPath $configStage -Destination $sshdConfig -Force",
        "$sshdExeCandidates = @(",
        "    (Join-Path $env:WINDIR 'System32\\OpenSSH\\sshd.exe'),",
        "    (Join-Path $env:ProgramFiles 'OpenSSH\\sshd.exe'),",
        "    (Join-Path $env:ProgramFiles 'OpenSSH-Win64\\sshd.exe')",
        ")",
        "$sshdExe = $sshdExeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1",
        "    if (-not $sshdExe) { throw 'SICHERHEITSABBRUCH: sshd.exe zur Konfigurationsprüfung nicht gefunden.' }",
        "    & $sshdExe -t -f $sshdConfig",
        "    if ($LASTEXITCODE -ne 0) { throw 'SICHERHEITSABBRUCH: sshd_config oder Include ist ungültig.' }",
        "}",
        "catch {",
        "    Copy-Item -LiteralPath $runConfigBackup -Destination $sshdConfig -Force",
        "    if ($managedConfigPreexisted) { Copy-Item -LiteralPath $managedConfigBackup -Destination $managedConfig -Force } else { Remove-Item -LiteralPath $managedConfig -Force -ErrorAction SilentlyContinue }",
        "    throw",
        "}",
        "finally { Remove-Item -LiteralPath $runConfigBackup,$managedConfigBackup,$configStage,$managedStage -Force -ErrorAction SilentlyContinue }",
        "",
        "Write-Host '[6/9] Mavi Public Key einrichten...' -ForegroundColor Cyan",
        "$keyFile = Join-Path $env:ProgramData 'ssh\\administrators_authorized_keys'",
        f"$maviKey = '{ps_key}'",
        "$existing = @()",
        "if (Test-Path -LiteralPath $keyFile) { $existing = @(Get-Content -LiteralPath $keyFile -ErrorAction SilentlyContinue) }",
        "$keyPreexisted = @($existing | Where-Object { $_.Trim() -eq $maviKey }).Count -gt 0",
        "if ($maviPreviousState -and $null -ne $maviPreviousState.KeyPreexisted) { $keyPreexisted = [bool]$maviPreviousState.KeyPreexisted }",
        "if (-not $keyPreexisted) { Add-Content -LiteralPath $keyFile -Value $maviKey -Encoding ascii }",
        "icacls.exe $keyFile /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null",
        "",
        "Write-Host '[7/9] PowerShell als SSH-Shell setzen...' -ForegroundColor Cyan",
        "$originalDefaultShellExists = $false",
        "$originalDefaultShell = ''",
        "if ($maviPreviousState -and $null -ne $maviPreviousState.OriginalDefaultShellExists) {",
        "    $originalDefaultShellExists = [bool]$maviPreviousState.OriginalDefaultShellExists",
        "    $originalDefaultShell = [string]$maviPreviousState.OriginalDefaultShell",
        "} else {",
        "    $existingShellProperty = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -ErrorAction SilentlyContinue",
        "    if ($null -ne $existingShellProperty) { $originalDefaultShellExists = $true; $originalDefaultShell = [string]$existingShellProperty.DefaultShell }",
        "}",
        "New-Item -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Force | Out-Null",
        "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -Value 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -PropertyType String -Force | Out-Null",
        "",
        "Write-Host '[8/9] Instanzeigene Windows-Firewallregel setzen...' -ForegroundColor Cyan",
        "Get-NetFirewallRule -Name $maviFirewallName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop",
        "New-NetFirewallRule -Name $maviFirewallName -DisplayName ('Mavi OpenSSH nur Ansible-Server (' + $maviInstanceId + ')') -Group 'Mavi Provisioner' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -RemoteAddress $ansibleServerIp -Profile Any | Out-Null",
        "$maviRule = Get-NetFirewallRule -Name $maviFirewallName -ErrorAction Stop",
        "$maviAddress = @($maviRule | Get-NetFirewallAddressFilter -ErrorAction Stop)",
        "if ($maviAddress.Count -ne 1 -or [string]$maviAddress[0].RemoteAddress -cne $ansibleServerIp) {",
        "    throw 'SICHERHEITSABBRUCH: Die Firewall-RemoteAddress konnte nicht exakt verifiziert werden.'",
        "}",
        "Write-Host \"    TCP/22 erlaubt ausschließlich von $ansibleServerIp.\" -ForegroundColor Green",
        "",
        "Write-Host '[9/9] sshd aktivieren beziehungsweise neu starten...' -ForegroundColor Cyan",
        "Set-Service -Name sshd -StartupType Automatic",
        "$sshd = Get-Service -Name sshd",
        "if ($sshd.Status -eq 'Running') { Restart-Service -Name sshd -Force } else { Start-Service -Name sshd }",
        "",
        "$trackedThumbprints = New-Object 'System.Collections.Generic.List[string]'",
        "if ($maviPreviousState -and $maviPreviousState.CaThumbprintsAdded) { foreach ($thumb in @($maviPreviousState.CaThumbprintsAdded)) { if ($thumb -match '^[0-9A-Fa-f]{40}$' -and -not $trackedThumbprints.Contains(([string]$thumb).ToUpperInvariant())) { $trackedThumbprints.Add(([string]$thumb).ToUpperInvariant()) } } }",
        "if ($env:MAVI_CA_ADDED_THIS_RUN -ceq '1' -and $maviCaThumbprint -match '^[0-9A-Fa-f]{40}$') { $addedThumbprint = $maviCaThumbprint.ToUpperInvariant(); if (-not $trackedThumbprints.Contains($addedThumbprint)) { $trackedThumbprints.Add($addedThumbprint) } }",
        "if ($maviPreviousState -and $null -ne $maviPreviousState.SshdConfigPreexisted) { $sshdConfigPreexisted = [bool]$maviPreviousState.SshdConfigPreexisted }",
        "$bootstrapState = [ordered]@{ InstanceId=$maviInstanceId; CaThumbprintsAdded=@($trackedThumbprints); FirewallRule=$maviFirewallName; ManagedConfig=$managedConfig; BeginMarker=$beginMarker; EndMarker=$endMarker; KeyFile=$keyFile; MaviKey=$maviKey; KeyPreexisted=$keyPreexisted; SshdConfig=$sshdConfig; SshdConfigPreexisted=$sshdConfigPreexisted; OriginalDefaultShellExists=$originalDefaultShellExists; OriginalDefaultShell=$originalDefaultShell; UpdatedUtc=[DateTime]::UtcNow.ToString('o') }",
        "$bootstrapState | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $maviStatePath -Encoding utf8",
        "& icacls.exe $maviStateRoot /inheritance:r /grant '*S-1-5-32-544:(OI)(CI)F' /grant '*S-1-5-18:(OI)(CI)F' | Out-Null",
        "if ($LASTEXITCODE -ne 0) { throw 'Mavi-Bootstrap-Status konnte nicht sicher per ACL geschützt werden.' }",
        "",
        "Write-Host 'SSH Host-Key Fingerprint...' -ForegroundColor Cyan",
        "Get-Service sshd | Format-Table Name,Status,StartType",
        "$hostKey = Join-Path $env:ProgramData 'ssh\\ssh_host_ed25519_key.pub'",
        "if (Test-Path -LiteralPath $hostKey) {",
        "    $sshKeygenCandidates = @(",
        "        (Join-Path $env:WINDIR 'System32\\OpenSSH\\ssh-keygen.exe'),",
        "        (Join-Path $env:ProgramFiles 'OpenSSH\\ssh-keygen.exe'),",
        "        (Join-Path $env:ProgramFiles 'OpenSSH-Win64\\ssh-keygen.exe')",
        "    )",
        "    $sshKeygen = $sshKeygenCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1",
        "    if (-not $sshKeygen) {",
        "        $cmd = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue",
        "        if ($cmd) { $sshKeygen = $cmd.Source }",
        "    }",
        "    if ($sshKeygen) { & $sshKeygen -lf $hostKey }",
        "    else { Write-Warning 'ssh-keygen.exe nicht gefunden; Host-Key wurde trotzdem erzeugt.' }",
        "}",
        "Write-Host ''",
        "Write-Host 'Mavi OpenSSH fertig: Public-Key aktiv, Passwortlogin aus, Firewall auf Ansible-IP begrenzt.' -ForegroundColor Green",
        "Write-Host 'sshd bleibt wie angefordert installiert und aktiv.' -ForegroundColor Green",
        "Write-Host 'Du kannst dieses Fenster jetzt schließen und in Mavi den PC auf OpenSSH umstellen.' -ForegroundColor Green",
        "Write-Host ''",
        "Read-Host 'ENTER zum Schließen' | Out-Null",
    ]
    return "\r\n".join(lines) + "\r\n"


def _software_local_and_windows_path(project: Path, raw: str) -> tuple[Path | None, str, str]:
    """Mavi-Softwarepfad in Planner-, Laufwerks- und UNC-Pfad übersetzen."""
    value = str(raw or "").strip().strip('"').strip("'")
    config = get_config(project)
    source = config.get("software_source", {}) or {}
    drive = str(source.get("drive", "") or "").strip().replace("/", "\\")
    unc_root = str(source.get("unc_root", "") or "").strip().rstrip("\\/")
    local_root_raw = str(source.get("local_root", "") or "").strip()
    local_root = Path(local_root_raw).expanduser() if local_root_raw else None
    rel_text = ""
    local: Path | None = None

    value_win = value.replace("/", "\\")
    if value and drive and value_win.lower().startswith(drive.lower()):
        rel_text = value_win[len(drive):].lstrip("\\/")
        if local_root is not None:
            local = local_root.joinpath(*[x for x in re.split(r"[\\/]+", rel_text) if x])
    elif value and unc_root and value_win.lower().startswith(unc_root.replace("/", "\\").lower()):
        rel_text = value_win[len(unc_root):].lstrip("\\/")
        if local_root is not None:
            local = local_root.joinpath(*[x for x in re.split(r"[\\/]+", rel_text) if x])
    elif value and value.startswith("/"):
        candidate = Path(value).expanduser()
        local = candidate
        if local_root is not None:
            try:
                rel_text = str(candidate.relative_to(local_root)).replace("/", "\\")
            except ValueError:
                rel_text = ""

    if rel_text:
        drive_path = (drive.rstrip("\\") + "\\" + rel_text) if drive else ""
        unc_path = (unc_root + "\\" + rel_text) if unc_root else ""
    else:
        drive_path = value if re.match(r"^[A-Za-z]:[\\/]", value) else ""
        unc_path = value if value.startswith("\\\\") else ""
    return local, drive_path, unc_path


def _bootstrap_instance_id(project: Path, config: dict[str, Any] | None = None) -> str:
    """Deterministische, controllerlokal eindeutige Kennung für Bootstrap-Ressourcen."""
    resolved_project = project.expanduser().resolve(strict=False)
    current_config = config if isinstance(config, dict) else get_config(project)
    profile = current_config.get("profile", {}) if isinstance(current_config, dict) else {}
    profile_name = str(profile.get("name", "") or "environment") if isinstance(profile, dict) else "environment"
    readable = re.sub(r"[^a-z0-9]+", "-", profile_name.casefold()).strip("-")[:32] or "environment"
    path_digest = hashlib.sha256(str(resolved_project).encode("utf-8")).hexdigest()[:12]
    return f"{readable}-{path_digest}"


def _bootstrap_settings(project: Path) -> dict[str, Any]:
    """Zentrale HTTPS-Bootstrap-Konfiguration validieren und normalisieren."""
    config = get_config(project)
    base_url = str(config.get("bootstrap_base_url", "") or "").strip()
    local_dir_raw = str(config.get("bootstrap_local_dir", "") or "").strip()
    ansible_server_ip = str(config.get("ansible_server_ip", "") or "").strip()
    expected_signer = str(config.get("openssh_msi_expected_signer", "") or "").strip()
    allowed_cidrs_raw = config.get("bootstrap_allowed_cidrs", [])
    ca_validity_raw = config.get("bootstrap_ca_validity_days", 825)
    server_validity_raw = config.get("bootstrap_server_cert_validity_days", 90)
    instance_id = _bootstrap_instance_id(project, config)

    if not base_url:
        raise ValueError("bootstrap_base_url fehlt.")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme.lower() != "https":
        raise ValueError("bootstrap_base_url muss mit https:// beginnen; HTTP ist unzulässig.")
    try:
        url_port = parsed.port
    except ValueError as exc:
        raise ValueError("bootstrap_base_url enthält einen ungültigen Port.") from exc
    if url_port is not None and not 1 <= url_port <= 65535:
        raise ValueError("bootstrap_base_url enthält einen ungültigen Port.")
    effective_port = url_port if url_port is not None else 443
    if not parsed.hostname:
        raise ValueError("bootstrap_base_url enthält keinen gültigen Hostnamen bzw. keine IP.")
    url_host = str(parsed.hostname)
    try:
        parsed_url_ip = ipaddress.ip_address(url_host)
    except ValueError:
        try:
            url_host_ascii = url_host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("bootstrap_base_url enthält einen ungültigen DNS-Namen.") from exc
        if (
            len(url_host_ascii) > 253
            or not re.fullmatch(
                r"(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?",
                url_host_ascii,
            )
        ):
            raise ValueError("bootstrap_base_url enthält einen ungültigen DNS-Namen.")
        url_host = url_host_ascii.rstrip(".").lower()
        netloc_host = url_host
    else:
        url_host = str(parsed_url_ip)
        netloc_host = f"[{url_host}]" if parsed_url_ip.version == 6 else url_host
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("bootstrap_base_url darf keine Zugangsdaten enthalten.")
    if parsed.query or parsed.fragment:
        raise ValueError("bootstrap_base_url darf weder Query noch Fragment enthalten.")
    if any(ord(char) < 32 or ord(char) == 127 for char in base_url):
        raise ValueError("bootstrap_base_url darf keine Steuerzeichen enthalten.")
    normalized_path = parsed.path or "/"
    if not normalized_path.endswith("/"):
        normalized_path += "/"
    if (
        normalized_path == "/"
        or not re.fullmatch(r"/[A-Za-z0-9._~/-]*/", normalized_path)
        or "//" in normalized_path
        or "\\" in normalized_path
        or any(part in {".", ".."} for part in normalized_path.split("/"))
    ):
        raise ValueError(
            "bootstrap_base_url benötigt einen eigenen einfachen URL-Pfad, z. B. /mavi-bootstrap/."
        )
    normalized_netloc = netloc_host + (f":{url_port}" if url_port is not None else "")
    base_url = urllib.parse.urlunsplit((
        "https",
        normalized_netloc,
        normalized_path,
        "",
        "",
    ))

    if not local_dir_raw:
        raise ValueError("bootstrap_local_dir fehlt.")
    local_dir_candidate = Path(local_dir_raw).expanduser()
    if not local_dir_candidate.is_absolute():
        raise ValueError("bootstrap_local_dir muss ein absoluter lokaler Pfad sein.")
    local_dir = local_dir_candidate.resolve(strict=False)
    safe_webroot_parents = (Path("/var/www"), Path("/srv"), Path("/opt"), Path("/mnt"))
    in_safe_parent = False
    for parent in safe_webroot_parents:
        try:
            local_dir.relative_to(parent)
        except ValueError:
            continue
        if local_dir != parent:
            in_safe_parent = True
            break
    if not in_safe_parent:
        raise ValueError(
            "bootstrap_local_dir muss ein eigener Unterordner unter /var/www, /srv, /opt oder /mnt sein. "
            "Empfohlen: /var/www/mavi-bootstrap"
        )
    try:
        parsed_ip = ipaddress.ip_address(ansible_server_ip)
    except ValueError as exc:
        raise ValueError("ansible_server_ip fehlt oder ist keine einzelne gültige IP-Adresse.") from exc
    if parsed_ip.is_unspecified or parsed_ip.is_multicast or parsed_ip.is_loopback or parsed_ip.is_link_local:
        raise ValueError(
            "ansible_server_ip darf weder Wildcard-, Multicast-, Loopback- noch Link-Local-Adresse sein."
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in expected_signer):
        raise ValueError("openssh_msi_expected_signer darf keine Steuerzeichen enthalten.")

    try:
        ca_validity_days = int(ca_validity_raw)
        server_cert_validity_days = int(server_validity_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "bootstrap_ca_validity_days und bootstrap_server_cert_validity_days müssen Ganzzahlen sein."
        ) from exc
    if not 90 <= ca_validity_days <= 1825:
        raise ValueError("bootstrap_ca_validity_days muss zwischen 90 und 1825 liegen.")
    if not 1 <= server_cert_validity_days <= 397:
        raise ValueError("bootstrap_server_cert_validity_days muss zwischen 1 und 397 liegen.")
    if server_cert_validity_days >= ca_validity_days:
        raise ValueError(
            "bootstrap_server_cert_validity_days muss kürzer als bootstrap_ca_validity_days sein."
        )
    if allowed_cidrs_raw in (None, "", []):
        allowed_values: list[str] = []
    elif isinstance(allowed_cidrs_raw, str):
        allowed_values = [x.strip() for x in allowed_cidrs_raw.split(",") if x.strip()]
    elif isinstance(allowed_cidrs_raw, list):
        allowed_values = [str(x or "").strip() for x in allowed_cidrs_raw if str(x or "").strip()]
    else:
        raise ValueError("bootstrap_allowed_cidrs muss eine YAML-Liste oder kommaseparierte Zeichenfolge sein.")

    if not allowed_values:
        private_candidates = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
        )
        matching_private = [network for network in private_candidates if parsed_ip in network]
        if matching_private:
            allowed_networks = matching_private
        elif parsed_ip.version == 4:
            allowed_networks = [ipaddress.ip_network("0.0.0.0/0")]
        else:
            allowed_networks = [ipaddress.ip_network("::/0")]
    else:
        try:
            allowed_networks = [ipaddress.ip_network(value, strict=False) for value in allowed_values]
        except ValueError as exc:
            raise ValueError(f"Ungültiges Netz in bootstrap_allowed_cidrs: {exc}") from exc

    # Normalisieren und doppelte Netze entfernen, damit Statusvergleiche stabil bleiben.
    allowed_networks = list(dict.fromkeys(allowed_networks))

    return {
        "base_url": base_url,
        "local_dir": local_dir,
        "ansible_server_ip": str(parsed_ip),
        "expected_signer": expected_signer,
        "url_host": url_host,
        "url_path": normalized_path,
        "port": int(effective_port),
        "allowed_cidrs": [str(network) for network in allowed_networks],
        "instance_id": instance_id,
        "ca_validity_days": ca_validity_days,
        "server_cert_validity_days": server_cert_validity_days,
    }


def _bootstrap_setup_instruction(project: Path, *, reason: str = "") -> str:
    """Einmalige Fehlerhilfe für die Vollautomatik, ohne unsicheren Fallback."""
    config = get_config(project)
    base_url = str(config.get("bootstrap_base_url", "") or "<HTTPS-BASIS-URL>").strip()
    local_dir = str(config.get("bootstrap_local_dir", "") or "/var/www/mavi-bootstrap").strip()
    safe_base_url = redact_sensitive_text(base_url)
    safe_local_dir = redact_sensitive_text(local_dir)
    safe_config_path = redact_sensitive_text(project_paths(project)["config"])
    lines = []
    if reason:
        lines.extend([f"Grund: {redact_sensitive_text(reason)}", ""])
    lines.extend([
        "Die Mavi-Vollautomatik konnte das Server-Setup nicht abschließen.",
        f"  Konfiguration: {safe_config_path}",
        f"  HTTPS-Ziel:    {safe_base_url}",
        f"  Webroot:       {safe_local_dir}",
        "Nach Korrektur des gemeldeten Grundes einfach erneut starten:",
        "  mavi-provisioner ssh server-setup",
        "Mavi installiert und konfiguriert nginx, CA, SAN-Zertifikat, Webroot und Firewall selbst.",
        "Es gibt ausdrücklich keinen HTTP-Fallback und keine deaktivierte Zertifikatsprüfung.",
    ])
    return "\n".join(lines)


def _atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _atomic_copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        shutil.copy2(source, tmp_path)
        if os.name != "nt":
            os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, destination)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bootstrap_pki_paths(project: Path) -> dict[str, Path]:
    """Alle privilegierten Bootstrap-Artefakte strikt pro Laufzeitprojekt isolieren."""
    instance_id = _bootstrap_instance_id(project)
    root = Path("/etc/mavi-bootstrap/instances") / instance_id
    pki = root / "pki"
    return {
        "root": root,
        "pki": pki,
        "ca_key": pki / "mavi-bootstrap-root-ca.key.pem",
        "ca_cert": pki / "mavi-bootstrap-root-ca.cert.pem",
        "server_key": pki / "mavi-bootstrap-server.key.pem",
        "server_cert": pki / "mavi-bootstrap-server.cert.pem",
        "server_csr": pki / "mavi-bootstrap-server.csr.pem",
        "openssl_config": pki / "mavi-bootstrap-server.cnf",
        "state": root / "server-state.json",
        "nginx_config": Path(f"/etc/nginx/conf.d/mavi-bootstrap-{instance_id}.conf"),
        "system_ca": Path(
            f"/usr/local/share/ca-certificates/mavi-bootstrap-{instance_id}-root-ca.crt"
        ),
        "system_ca_anchor": Path(
            f"/etc/pki/ca-trust/source/anchors/mavi-bootstrap-{instance_id}-root-ca.crt"
        ),
    }


def _bootstrap_launcher_roots(project: Path) -> tuple[Path | None, str]:
    """Lokalen Ablagepfad und den dazugehörigen Windows-Pfad ableiten."""
    config = get_config(project)
    source = config.get("software_source", {}) or {}
    local_override = str(config.get("bootstrap_launcher_local_dir", "") or "").strip()
    windows_override = str(config.get("bootstrap_launcher_windows_dir", "") or "").strip()

    if local_override:
        local_root = Path(local_override).expanduser()
        if not local_root.is_absolute():
            raise ValueError("bootstrap_launcher_local_dir muss absolut sein.")
    else:
        software_local = str(source.get("local_root", "") or "").strip()
        local_root = Path(software_local).expanduser() / "Mavi-Bootstrap" if software_local else None
    if local_root is not None:
        if not local_root.is_absolute():
            raise ValueError("Die lokale Mavi-Starterablage muss ein absoluter Pfad sein.")
        local_root = local_root.resolve(strict=False)
        if local_root == Path("/") or len(local_root.parts) < 3:
            raise ValueError("Die lokale Mavi-Starterablage darf kein System- oder Mount-Wurzelpfad sein.")

    if windows_override:
        windows_root = windows_override.rstrip("\\/")
    else:
        drive = str(source.get("drive", "") or "").strip().replace("/", "\\").rstrip("\\")
        unc_root = str(source.get("unc_root", "") or "").strip().replace("/", "\\").rstrip("\\")
        windows_base = drive or unc_root
        windows_root = windows_base + "\\Mavi-Bootstrap" if windows_base else ""
    if windows_root:
        if any(ord(char) < 32 or ord(char) == 127 for char in windows_root):
            raise ValueError("Die Windows-Starterablage enthält unzulässige Steuerzeichen.")
        if not (re.match(r"^[A-Za-z]:\\", windows_root) or windows_root.startswith("\\\\")):
            raise ValueError("Die Windows-Starterablage muss ein absoluter Laufwerks- oder UNC-Pfad sein.")

    return local_root, windows_root


def _root_command(command: list[str], *, description: str, quiet: bool = False) -> None:
    print(f"  → {description}")
    try:
        if quiet:
            result = subprocess.run(
                command,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        else:
            result = subprocess.run(command, check=False)
    except OSError as exc:
        die(f"{description} konnte nicht gestartet werden: {exc}")
    if result.returncode != 0:
        detail = ""
        if quiet and result.stderr:
            detail = "\n\n" + redact_sensitive_text(result.stderr.strip())
        die(f"{description} ist mit Exit-Code {result.returncode} fehlgeschlagen.{detail}")


def _install_bootstrap_server_packages() -> None:
    required = ("nginx", "openssl", "ssh-keygen")
    ca_updater_available = bool(
        shutil.which("update-ca-certificates") or shutil.which("update-ca-trust")
    )
    if all(shutil.which(binary) for binary in required) and ca_updater_available:
        return

    if shutil.which("apt-get"):
        _root_command(["apt-get", "update"], description="Paketlisten aktualisieren")
        _root_command(
            [
                "apt-get", "install", "-y", "--no-install-recommends",
                "nginx", "openssl", "ca-certificates", "openssh-client",
            ],
            description="nginx, OpenSSL, CA-Zertifikate und OpenSSH-Client installieren",
        )
        return

    package_manager = shutil.which("dnf") or shutil.which("yum")
    if package_manager:
        _root_command(
            [package_manager, "install", "-y", "nginx", "openssl", "ca-certificates", "openssh-clients"],
            description="nginx, OpenSSL, CA-Zertifikate und OpenSSH-Client installieren",
        )
        return

    die("Kein unterstützter Paketmanager gefunden. Unterstützt werden apt, dnf und yum.")


def _bootstrap_operator_ids(project: Path) -> tuple[int, int]:
    """Bei sudo den ursprünglichen Mavi-Benutzer statt root als Webroot-Eigentümer verwenden."""
    try:
        uid = int(os.environ.get("SUDO_UID", ""))
        gid = int(os.environ.get("SUDO_GID", ""))
        if uid >= 0 and gid >= 0:
            return uid, gid
    except (TypeError, ValueError):
        pass
    try:
        project_stat = project.stat()
        if project_stat.st_uid != 0:
            return int(project_stat.st_uid), int(project_stat.st_gid)
    except OSError:
        pass
    return int(os.getuid()), int(os.getgid())


def _nginx_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _openssl_server_config(host: str) -> str:
    try:
        parsed_host = ipaddress.ip_address(host)
    except ValueError:
        san_line = f"DNS.1 = {host}"
    else:
        san_line = f"IP.1 = {parsed_host}"
    return (
        "[req]\n"
        "prompt = no\n"
        "distinguished_name = dn\n"
        "req_extensions = req_ext\n"
        "\n"
        "[dn]\n"
        f"CN = {host}\n"
        "O = Mavi\n"
        "OU = Automated Bootstrap\n"
        "\n"
        "[req_ext]\n"
        "subjectAltName = @alt_names\n"
        "\n"
        "[server_ext]\n"
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid,issuer\n"
        "subjectAltName = @alt_names\n"
        "\n"
        "[alt_names]\n"
        f"{san_line}\n"
    )


def _certificate_valid_for(path: Path, seconds: int) -> bool:
    """Zertifikatslaufzeit konservativ mit OpenSSL prüfen, ohne Zertifikate zu verändern."""
    openssl = shutil.which("openssl")
    if not openssl or not path.is_file() or seconds < 0:
        return False
    try:
        result = subprocess.run(
            [openssl, "x509", "-checkend", str(int(seconds)), "-noout", "-in", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _certificate_sha1_thumbprint(path: Path) -> str:
    """Windows-Zertifikatthumbprint als exakten Bezeichner (nicht als Vertrauenshash) liefern."""
    pem = path.read_text(encoding="ascii")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha1(der, usedforsecurity=False).hexdigest().upper()


def _archive_bootstrap_pki_for_rotation(paths: dict[str, Path]) -> Path:
    """Alte, instanzeigene PKI recoverable archivieren, statt sie zu überschreiben."""
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    ca_digest = _sha256_file(paths["ca_cert"])[:12] if paths["ca_cert"].is_file() else "no-ca"
    archive = paths["root"] / "rotations" / f"{timestamp}-{ca_digest}"
    archive.mkdir(parents=True, exist_ok=False)
    os.chmod(archive, 0o700)
    archived: list[str] = []
    for key in (
        "ca_key", "ca_cert", "server_key", "server_cert", "server_csr", "openssl_config", "state",
    ):
        source = paths[key]
        if source.exists():
            destination = archive / source.name
            shutil.move(str(source), str(destination))
            archived.append(destination.name)
    serial = paths["pki"] / "mavi-bootstrap-root-ca.cert.srl"
    if serial.exists():
        destination = archive / serial.name
        shutil.move(str(serial), str(destination))
        archived.append(destination.name)
    _atomic_write_bytes(
        archive / "rotation.json",
        (json.dumps({
            "archived_epoch": time.time(),
            "archived_files": archived,
            "old_ca_sha256": _sha256_file(archive / paths["ca_cert"].name)
            if (archive / paths["ca_cert"].name).is_file() else "",
            "old_ca_windows_thumbprint": _certificate_sha1_thumbprint(archive / paths["ca_cert"].name)
            if (archive / paths["ca_cert"].name).is_file() else "",
        }, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        mode=0o600,
    )
    return archive


def _create_or_reuse_bootstrap_ca(
    settings: dict[str, Any],
    paths: dict[str, Path],
    *,
    rotate: bool = False,
) -> tuple[bool, Path | None]:
    """Instanz-CA erzeugen; Rotation nur explizit und mit recoverable Archiv."""
    ca_key = paths["ca_key"]
    ca_cert = paths["ca_cert"]
    if ca_cert.exists() and not ca_key.exists():
        die(
            "Das Mavi-CA-Zertifikat existiert, aber sein privater Schlüssel fehlt. "
            "Mavi rotiert die Vertrauenswurzel absichtlich nicht still. Backup wiederherstellen."
        )
    rotation_archive: Path | None = None
    if rotate and (ca_cert.exists() or ca_key.exists()):
        rotation_archive = _archive_bootstrap_pki_for_rotation(paths)
    elif ca_cert.exists():
        required_seconds = (int(settings["server_cert_validity_days"]) + 30) * 86400
        if not _certificate_valid_for(ca_cert, required_seconds):
            die(
                "Die instanzeigene Mavi-CA läuft zu früh ab oder ist nicht gültig genug für ein neues "
                "Serverzertifikat. Bewusst rotieren mit: "
                "mavi-provisioner ssh server-setup --rotate-ca --yes. "
                "Danach muss die alte CA mit ihrer archivierten Thumbprint-Liste von Ziel-PCs entfernt werden."
            )
    created = not ca_cert.exists()
    if not ca_key.exists():
        _root_command(
            [
                "openssl", "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(ca_key),
            ],
            description="private Mavi-CA erzeugen",
            quiet=True,
        )
        os.chmod(ca_key, 0o600)
    if not ca_cert.exists():
        _root_command(
            [
                "openssl", "req", "-x509", "-new", "-sha256",
                "-key", str(ca_key), "-out", str(ca_cert),
                "-days", str(settings["ca_validity_days"]),
                "-subj",
                f"/CN=Mavi Bootstrap Root CA {settings['instance_id']}/O=Mavi/OU=Automated Bootstrap",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
            ],
            description="Mavi-CA-Zertifikat erzeugen",
            quiet=True,
        )
        os.chmod(ca_cert, 0o644)
    return created, rotation_archive


def _issue_bootstrap_server_certificate(settings: dict[str, Any], paths: dict[str, Path]) -> None:
    config_text = _openssl_server_config(settings["url_host"])
    _atomic_write_bytes(paths["openssl_config"], config_text.encode("utf-8"), mode=0o600)

    temporary_key = paths["pki"] / ".mavi-server.key.new"
    temporary_csr = paths["pki"] / ".mavi-server.csr.new"
    temporary_cert = paths["pki"] / ".mavi-server.cert.new"
    for candidate in (temporary_key, temporary_csr, temporary_cert):
        candidate.unlink(missing_ok=True)
    try:
        _root_command(
            [
                "openssl", "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(temporary_key),
            ],
            description="HTTPS-Serverschlüssel erzeugen",
            quiet=True,
        )
        _root_command(
            [
                "openssl", "req", "-new", "-sha256",
                "-key", str(temporary_key), "-out", str(temporary_csr),
                "-config", str(paths["openssl_config"]),
            ],
            description="HTTPS-Zertifikatsanfrage mit SAN erzeugen",
            quiet=True,
        )
        _root_command(
            [
                "openssl", "x509", "-req", "-sha256",
                "-in", str(temporary_csr),
                "-CA", str(paths["ca_cert"]),
                "-CAkey", str(paths["ca_key"]),
                "-CAcreateserial", "-out", str(temporary_cert),
                "-days", str(settings["server_cert_validity_days"]),
                # -extensions alleine reicht bei `openssl x509 -req` nicht aus.
                # Ohne -extfile ignoriert OpenSSL die SAN-Erweiterung und das
                # Zertifikat ist anschließend nicht für die Bootstrap-IP bzw.
                # den Bootstrap-DNS-Namen gültig.
                "-extfile", str(paths["openssl_config"]),
                "-extensions", "server_ext",
            ],
            description="HTTPS-Serverzertifikat mit Mavi-CA signieren",
            quiet=True,
        )
        os.chmod(temporary_key, 0o600)
        os.chmod(temporary_cert, 0o644)
        os.replace(temporary_key, paths["server_key"])
        os.replace(temporary_csr, paths["server_csr"])
        os.replace(temporary_cert, paths["server_cert"])
        os.chmod(paths["server_key"], 0o600)
        os.chmod(paths["server_csr"], 0o600)
        os.chmod(paths["server_cert"], 0o644)
    finally:
        for candidate in (temporary_key, temporary_csr, temporary_cert):
            candidate.unlink(missing_ok=True)


def _nginx_bootstrap_config(settings: dict[str, Any], paths: dict[str, Path]) -> str:
    allow_lines = ["        allow 127.0.0.1;", "        allow ::1;"]
    allow_lines.append(f"        allow {settings['ansible_server_ip']};")
    allow_lines.extend(f"        allow {cidr};" for cidr in settings["allowed_cidrs"])
    allow_lines.append("        deny all;")
    webroot = str(settings["local_dir"]).rstrip("/\\") + "/"
    listen_lines = [f"    listen {settings['port']} ssl;"]
    if ipaddress.ip_address(settings["ansible_server_ip"]).version == 6:
        listen_lines.append(f"    listen [::]:{settings['port']} ssl;")
    return "\n".join([
        f"# Automatisch verwaltet durch Mavi Provisioner; Instanz {settings['instance_id']}",
        "server {",
        *listen_lines,
        f"    server_name {_nginx_quote(settings['url_host'])};",
        f"    ssl_certificate {_nginx_quote(str(paths['server_cert']))};",
        f"    ssl_certificate_key {_nginx_quote(str(paths['server_key']))};",
        "    ssl_protocols TLSv1.2 TLSv1.3;",
        "    ssl_session_tickets off;",
        "    server_tokens off;",
        "    client_max_body_size 1m;",
        "    add_header X-Content-Type-Options nosniff always;",
        "    add_header Cache-Control \"no-store\" always;",
        "",
        f"    location ^~ {_nginx_quote(settings['url_path'])} {{",
        f"        alias {_nginx_quote(webroot)};",
        "        autoindex off;",
        "        default_type application/octet-stream;",
        "        limit_except GET HEAD { deny all; }",
        *allow_lines,
        "    }",
        "",
        "    location / { return 404; }",
        "}",
        "",
    ])


def _ufw_delete_tagged_rules(ufw: str, tag: str) -> None:
    """Nur eindeutig mit der aktuellen Instanz markierte UFW-Regeln entfernen."""
    try:
        status = subprocess.run(
            [ufw, "status", "numbered"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        die(f"UFW-Regeln konnten für die sichere Instanzbereinigung nicht gelesen werden: {exc}")
    if status.returncode != 0:
        die("UFW-Regeln konnten für die sichere Instanzbereinigung nicht gelesen werden.")
    numbers: list[int] = []
    for line in (status.stdout or "").splitlines():
        if tag not in line:
            continue
        match = re.match(r"^\[\s*(\d+)\]", line.strip())
        if match:
            numbers.append(int(match.group(1)))
    for number in sorted(set(numbers), reverse=True):
        _root_command(
            [ufw, "--force", "delete", str(number)],
            description=f"instanzeigene UFW-Regel {number} entfernen",
        )


def _configure_bootstrap_firewall(settings: dict[str, Any]) -> dict[str, Any]:
    """Server-Firewall ausschließlich über instanzeigene, entfernbaren Ressourcen verwalten."""
    port = str(settings["port"])
    firewall_sources = list(settings["allowed_cidrs"])
    server_source = str(settings["ansible_server_ip"])
    firewall_tag = f"mavi-bootstrap-{settings['instance_id']}"
    if not any(
        ipaddress.ip_address(server_source) in ipaddress.ip_network(cidr)
        for cidr in firewall_sources
        if ipaddress.ip_network(cidr).version == ipaddress.ip_address(server_source).version
    ):
        firewall_sources.append(server_source)
    ufw = shutil.which("ufw")
    if ufw:
        status = subprocess.run([ufw, "status"], check=False, capture_output=True, text=True)
        if status.returncode == 0 and re.search(r"(?im)^Status:\s+active\s*$", status.stdout or ""):
            _ufw_delete_tagged_rules(ufw, firewall_tag)
            for cidr in firewall_sources:
                _root_command(
                    [
                        ufw, "allow", "from", cidr, "to", "any", "port", port,
                        "proto", "tcp", "comment", firewall_tag,
                    ],
                    description=f"UFW HTTPS/{port} für {cidr} freigeben",
                )
            return {"backend": "ufw", "tag": firewall_tag, "sources": firewall_sources, "port": int(port)}

    firewall_cmd = shutil.which("firewall-cmd")
    if firewall_cmd:
        state = subprocess.run([firewall_cmd, "--state"], check=False, capture_output=True, text=True)
        if state.returncode == 0:
            zones = subprocess.run(
                [firewall_cmd, "--permanent", "--get-zones"],
                check=False,
                capture_output=True,
                text=True,
            )
            if zones.returncode != 0:
                die("firewalld-Zonen konnten nicht gelesen werden.")
            if firewall_tag in (zones.stdout or "").split():
                _root_command(
                    [firewall_cmd, "--permanent", f"--delete-zone={firewall_tag}"],
                    description=f"alte instanzeigene firewalld-Zone {firewall_tag} entfernen",
                )
            _root_command(
                [firewall_cmd, "--permanent", f"--new-zone={firewall_tag}"],
                description=f"instanzeigene firewalld-Zone {firewall_tag} anlegen",
            )
            for cidr in firewall_sources:
                _root_command(
                    [firewall_cmd, "--permanent", f"--zone={firewall_tag}", f"--add-source={cidr}"],
                    description=f"firewalld HTTPS/{port} für {cidr} freigeben",
                )
            _root_command(
                [firewall_cmd, "--permanent", f"--zone={firewall_tag}", f"--add-port={port}/tcp"],
                description=f"firewalld HTTPS/{port} in Instanzzone freigeben",
            )
            _root_command([firewall_cmd, "--reload"], description="firewalld neu laden")
            return {
                "backend": "firewalld",
                "tag": firewall_tag,
                "sources": firewall_sources,
                "port": int(port),
            }
    return {"backend": "none", "tag": firewall_tag, "sources": firewall_sources, "port": int(port)}


def _remove_bootstrap_firewall(state: dict[str, Any]) -> None:
    """Nur im Serverstatus ausgewiesene Firewall-Ressourcen dieser Instanz entfernen."""
    firewall = state.get("firewall", {}) if isinstance(state, dict) else {}
    if not isinstance(firewall, dict):
        return
    backend = str(firewall.get("backend", "") or "")
    tag = str(firewall.get("tag", "") or "")
    instance_id = str(state.get("instance_id", "") or "") if isinstance(state, dict) else ""
    if not tag or tag != f"mavi-bootstrap-{instance_id}":
        if backend not in {"", "none"}:
            die("Firewall-Status besitzt keine eindeutig zur Instanz passende Eigentumsmarke.")
        return
    if backend == "ufw":
        ufw = shutil.which("ufw")
        if not ufw:
            die("UFW fehlt; instanzeigene Regeln konnten nicht entfernt werden.")
        _ufw_delete_tagged_rules(ufw, tag)
    elif backend == "firewalld":
        firewall_cmd = shutil.which("firewall-cmd")
        if not firewall_cmd:
            die("firewall-cmd fehlt; instanzeigene Zone konnte nicht entfernt werden.")
        zones = subprocess.run(
            [firewall_cmd, "--permanent", "--get-zones"],
            check=False,
            capture_output=True,
            text=True,
        )
        if zones.returncode != 0:
            die("firewalld-Zonen konnten nicht gelesen werden.")
        if tag in (zones.stdout or "").split():
            _root_command(
                [firewall_cmd, "--permanent", f"--delete-zone={tag}"],
                description=f"instanzeigene firewalld-Zone {tag} entfernen",
            )
            _root_command([firewall_cmd, "--reload"], description="firewalld neu laden")


def _trust_bootstrap_ca_locally(paths: dict[str, Path]) -> None:
    paths["system_ca"].parent.mkdir(parents=True, exist_ok=True)
    _atomic_copy_file(paths["ca_cert"], paths["system_ca"])
    os.chmod(paths["system_ca"], 0o644)
    update_ca = shutil.which("update-ca-certificates")
    if update_ca:
        _root_command([update_ca], description="Mavi-CA im Linux-Systemvertrauen aktivieren")
        return
    update_trust = shutil.which("update-ca-trust")
    if update_trust:
        anchors = paths["system_ca_anchor"]
        anchors.parent.mkdir(parents=True, exist_ok=True)
        _atomic_copy_file(paths["ca_cert"], anchors)
        _root_command([update_trust, "extract"], description="Mavi-CA im Linux-Systemvertrauen aktivieren")
        return
    die("Weder update-ca-certificates noch update-ca-trust ist verfügbar.")


def _untrust_bootstrap_ca_locally(paths: dict[str, Path]) -> None:
    """Nur die Vertrauensanker der aktuellen Bootstrap-Instanz entfernen."""
    removed_debian_anchor = paths["system_ca"].exists()
    removed_rhel_anchor = paths["system_ca_anchor"].exists()
    paths["system_ca"].unlink(missing_ok=True)
    paths["system_ca_anchor"].unlink(missing_ok=True)
    if removed_debian_anchor:
        update_ca = shutil.which("update-ca-certificates")
        if not update_ca:
            die("update-ca-certificates fehlt; lokaler CA-Trust konnte nicht sauber aktualisiert werden.")
        _root_command([update_ca, "--fresh"], description="instanzeigene Mavi-CA aus Linux-Vertrauen entfernen")
    if removed_rhel_anchor:
        update_trust = shutil.which("update-ca-trust")
        if not update_trust:
            die("update-ca-trust fehlt; lokaler CA-Trust konnte nicht sauber aktualisiert werden.")
        _root_command([update_trust, "extract"], description="instanzeigene Mavi-CA aus Linux-Vertrauen entfernen")


def _enable_and_reload_nginx(paths: dict[str, Path]) -> None:
    nginx = shutil.which("nginx")
    if not nginx:
        die("nginx wurde trotz Paketinstallation nicht gefunden.")
    _root_command([nginx, "-t"], description="nginx-Konfiguration sicher validieren")
    if shutil.which("systemctl"):
        _root_command(["systemctl", "enable", "--now", "nginx"], description="nginx aktivieren und starten")
        _root_command(["systemctl", "reload", "nginx"], description="nginx-Konfiguration laden")
    elif shutil.which("service"):
        _root_command(["service", "nginx", "restart"], description="nginx neu starten")
    else:
        die("Weder systemctl noch service ist verfügbar, um nginx zu starten.")


def _tcp_port_is_bindable(port: int, *, include_ipv6: bool) -> bool:
    """Konservativer Vorabcheck: Kann nginx den Port auf allen benötigten Familien binden?"""
    targets: list[tuple[int, tuple[Any, ...]]] = [
        (socket.AF_INET, ("0.0.0.0", port)),
    ]
    if include_ipv6 and socket.has_ipv6:
        targets.append((socket.AF_INET6, ("::", port, 0, 0)))
    for family, address in targets:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                if family == socket.AF_INET6:
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                probe.bind(address)
        except OSError:
            return False
    return True


def _tcp_listener_process_names(port: int) -> set[str]:
    """Best effort: Namen der Prozesse ermitteln, die den TCP-Port bereits halten."""
    names: set[str] = set()
    ss = shutil.which("ss")
    if ss:
        try:
            result = subprocess.run(
                [ss, "-H", "-ltnp"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None:
            for line in (result.stdout or "").splitlines():
                fields = line.split()
                if len(fields) < 4 or not re.search(rf":{port}$", fields[3]):
                    continue
                for process_name in re.findall(r'\(\("([^"]+)"', line):
                    names.add(process_name.casefold())
    if names:
        return names

    fuser = shutil.which("fuser")
    if not fuser:
        return names
    try:
        result = subprocess.run(
            [fuser, "-n", "tcp", str(port)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return names
    for pid_text in re.findall(r"\b\d+\b", (result.stdout or "") + " " + (result.stderr or "")):
        try:
            process_name = Path(f"/proc/{int(pid_text)}/comm").read_text(encoding="utf-8").strip()
        except (OSError, ValueError, UnicodeError):
            continue
        if process_name:
            names.add(process_name.casefold())
    return names


def _managed_nginx_is_active() -> bool:
    systemctl = shutil.which("systemctl")
    if systemctl:
        try:
            result = subprocess.run(
                [systemctl, "is-active", "--quiet", "nginx"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0
    service = shutil.which("service")
    if service:
        try:
            result = subprocess.run(
                [service, "nginx", "status"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0
    return False


def _bootstrap_url_with_port(settings: dict[str, Any], port: int) -> str:
    parsed = urllib.parse.urlsplit(settings["base_url"])
    host = str(parsed.hostname or settings["url_host"])
    try:
        host_is_ipv6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        host_is_ipv6 = False
    netloc_host = f"[{host}]" if host_is_ipv6 else host
    netloc = netloc_host if port == 443 else f"{netloc_host}:{port}"
    return urllib.parse.urlunsplit(("https", netloc, parsed.path, "", ""))


def _persist_bootstrap_base_url(
    project: Path,
    base_url: str,
    *,
    fallback_uid: int,
    fallback_gid: int,
) -> None:
    """Automatisch gewählten Port zentral speichern und bestehende Dateirechte erhalten."""
    config_path = project_paths(project)["config"]
    existing_uid = fallback_uid
    existing_gid = fallback_gid
    existing_mode = 0o644
    try:
        current_stat = config_path.stat()
        existing_uid = int(current_stat.st_uid)
        existing_gid = int(current_stat.st_gid)
        existing_mode = int(current_stat.st_mode & 0o7777)
    except OSError:
        pass
    config = load_yaml(config_path, {}) or {}
    if not isinstance(config, dict):
        die(f"Zentrale Konfiguration ist kein YAML-Objekt: {config_path}")
    config["bootstrap_base_url"] = base_url
    try:
        atomic_write_yaml(config_path, config)
    except OSError as exc:
        die(f"Automatisch gewählter HTTPS-Port konnte nicht zentral gespeichert werden: {exc}")
    try:
        os.chown(config_path, existing_uid, existing_gid, follow_symlinks=False)
    except (AttributeError, NotImplementedError):
        pass
    except OSError as exc:
        die(f"Besitzrechte der zentralen Konfiguration konnten nicht erhalten werden: {exc}")
    os.chmod(config_path, existing_mode)


def _select_usable_bootstrap_port(
    project: Path,
    settings: dict[str, Any],
    *,
    uid: int,
    gid: int,
) -> dict[str, Any]:
    """Konfigurierten Port behalten oder einen freien, dauerhaft gespeicherten Ersatz wählen."""
    configured_port = int(settings["port"])
    include_ipv6 = ipaddress.ip_address(settings["ansible_server_ip"]).version == 6
    if _tcp_port_is_bindable(configured_port, include_ipv6=include_ipv6):
        return settings

    listeners = _tcp_listener_process_names(configured_port)
    managed_nginx_listener = (
        any(name == "nginx" or name.startswith("nginx-") for name in listeners)
        and _managed_nginx_is_active()
    )
    if managed_nginx_listener:
        health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
        endpoint_ok, endpoint_detail = _strict_https_probe(
            health_url,
            trusted_ca=_bootstrap_pki_paths(project)["system_ca"],
        )
        if endpoint_ok:
            print(
                f"  ✓ HTTPS-Port {configured_port} liefert bereits das gültige "
                "Mavi-Zertifikat und bleibt erhalten."
            )
            return settings
        print(
            f"  ! nginx nutzt HTTPS-Port {configured_port}, liefert dort aber nicht "
            "nachweislich das Mavi-Zertifikat. Mavi trennt den TLS-Endpunkt automatisch."
        )
        print(f"    Prüfung: {redact_sensitive_text(endpoint_detail)}")

    preferred_ports = [8443, 9443, 10443, 11443, 12443, 13443, 14443, 15443]
    fallback_candidates = preferred_ports + list(range(8444, 8501))
    selected_port = next(
        (
            candidate
            for candidate in fallback_candidates
            if candidate != configured_port
            and _tcp_port_is_bindable(candidate, include_ipv6=include_ipv6)
        ),
        None,
    )
    occupied_by = ", ".join(sorted(listeners)) if listeners else "einen anderen Dienst"
    if selected_port is None:
        die(
            f"HTTPS-Port {configured_port} ist durch {occupied_by} belegt, "
            "und Mavi konnte keinen freien Ersatzport finden."
        )
    fallback_url = _bootstrap_url_with_port(settings, selected_port)
    _persist_bootstrap_base_url(
        project,
        fallback_url,
        fallback_uid=uid,
        fallback_gid=gid,
    )
    print(
        f"  ! HTTPS-Port {configured_port} ist durch {occupied_by} belegt. "
        f"Mavi verwendet automatisch Port {selected_port}."
    )
    print(f"  ✓ bootstrap_base_url dauerhaft gespeichert: {fallback_url}")
    return _bootstrap_settings(project)


def _relaunch_bootstrap_server_setup_as_root(project: Path, *, rotate_ca: bool = False) -> None:
    sudo = shutil.which("sudo")
    if not sudo:
        die("Für das automatische nginx-/Zertifikats-Setup fehlt sudo.")
    executable = shutil.which(sys.argv[0]) or sys.argv[0]
    script_path = Path(executable).expanduser().resolve()
    command = [
        sudo,
        sys.executable,
        str(script_path),
        "--project",
        str(project.resolve()),
        "ssh",
        "server-setup",
        "--yes",
    ]
    if rotate_ca:
        command.append("--rotate-ca")
    print("\nMavi benötigt einmalig sudo für nginx, Zertifikat und Server-Firewall.")
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        die(f"Automatisches HTTPS-Server-Setup ist mit Code {result.returncode} fehlgeschlagen.")


def cmd_ssh_server_setup(args: argparse.Namespace) -> None:
    """Kompletten HTTPS-Server inklusive privater CA automatisch einrichten."""
    project = args.project.resolve()
    if os.name == "nt" or not hasattr(os, "geteuid"):
        die("Das automatische HTTPS-Server-Setup ist für Linux-Ansible-Server vorgesehen.")
    if os.geteuid() != 0:
        ensure_initialized(project, quiet=True)
        _relaunch_bootstrap_server_setup_as_root(
            project,
            rotate_ca=bool(getattr(args, "rotate_ca", False)),
        )
        return

    settings = _bootstrap_settings(project)
    paths = _bootstrap_pki_paths(project)
    uid, gid = _bootstrap_operator_ids(project)
    rotate_ca = bool(getattr(args, "rotate_ca", False))
    if rotate_ca and not bool(getattr(args, "yes", False)):
        die("CA-Rotation benötigt die explizite Bestätigung --yes.")

    print("\nMavi VOLLAUTOMATISCHES HTTPS-SERVER-SETUP")
    print("=========================================")
    _install_bootstrap_server_packages()
    settings = _select_usable_bootstrap_port(project, settings, uid=uid, gid=gid)
    print(f"HTTPS:      {settings['base_url']}")
    print(f"Webroot:    {settings['local_dir']}")
    print(f"Instanz:    {settings['instance_id']}")
    print(f"Client-Netze: {', '.join(settings['allowed_cidrs'])}")

    paths["pki"].mkdir(parents=True, exist_ok=True)
    os.chmod(paths["root"], 0o755)
    os.chmod(paths["pki"], 0o700)
    ca_created, rotation_archive = _create_or_reuse_bootstrap_ca(
        settings,
        paths,
        rotate=rotate_ca,
    )
    _issue_bootstrap_server_certificate(settings, paths)
    _trust_bootstrap_ca_locally(paths)

    webroot: Path = settings["local_dir"]
    webroot.mkdir(parents=True, exist_ok=True)
    os.chmod(webroot, 0o755)
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    _atomic_write_bytes(webroot / "Mavi-SETUP-CHECK.txt", health_body)
    _atomic_copy_file(paths["ca_cert"], webroot / "Mavi-ROOT-CA.pem")
    _atomic_write_bytes(
        webroot / ".mavi-bootstrap-owner.json",
        (json.dumps({
            "instance_id": settings["instance_id"],
            "project": str(project),
            "webroot": str(webroot),
        }, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        mode=0o644,
    )

    paths["nginx_config"].parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_bytes(
        paths["nginx_config"],
        _nginx_bootstrap_config(settings, paths).encode("utf-8"),
        mode=0o644,
    )
    _enable_and_reload_nginx(paths)
    firewall_state = _configure_bootstrap_firewall(settings)

    launcher_root, _windows_root = _bootstrap_launcher_roots(project)
    if launcher_root is not None:
        try:
            launcher_root.mkdir(parents=True, exist_ok=True)
            os.chmod(launcher_root, 0o755)
            os.chown(launcher_root, uid, gid, follow_symlinks=False)
        except (OSError, NotImplementedError) as exc:
            print(f"! Softwareablage wird später mit Benutzerrechten angelegt: {redact_sensitive_text(exc)}")

    for managed_path in (
        webroot,
        webroot / "Mavi-SETUP-CHECK.txt",
        webroot / "Mavi-ROOT-CA.pem",
        webroot / ".mavi-bootstrap-owner.json",
    ):
        try:
            os.chown(managed_path, uid, gid, follow_symlinks=False)
        except NotImplementedError:
            pass
        except OSError as exc:
            die(f"Webroot-Besitzrechte konnten nicht gesetzt werden: {exc}")
    state = {
        "version": VERSION,
        "instance_id": settings["instance_id"],
        "project": str(project),
        "base_url": settings["base_url"],
        "webroot": str(webroot),
        "host": settings["url_host"],
        "ansible_server_ip": settings["ansible_server_ip"],
        "port": settings["port"],
        "allowed_cidrs": settings["allowed_cidrs"],
        "firewall": firewall_state,
        "ca_sha256": _sha256_file(paths["ca_cert"]),
        "ca_windows_thumbprint": _certificate_sha1_thumbprint(paths["ca_cert"]),
        "ca_validity_days": settings["ca_validity_days"],
        "server_cert_validity_days": settings["server_cert_validity_days"],
        "ca_created": ca_created,
        "rotation_archive": str(rotation_archive) if rotation_archive is not None else "",
        "configured_epoch": time.time(),
    }
    _atomic_write_bytes(
        paths["state"],
        (json.dumps(state, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        mode=0o644,
    )
    print("\n✓ nginx, Mavi-CA, SAN-Zertifikat, Webroot und Server-Firewall sind eingerichtet.")
    print("✓ Die CA bleibt stabil und wird bei späteren Läufen nicht still ersetzt.")
    if rotation_archive is not None:
        print(f"! Alte PKI recoverable archiviert: {rotation_archive}")
        print("! Die archivierte alte CA muss anschließend auf allen Ziel-PCs anhand der Thumbprint entfernt werden.")


def _ensure_automatic_https_server(project: Path) -> dict[str, Any]:
    """Server-Setup nur bei Bedarf automatisch mit sudo ausführen."""
    settings = _bootstrap_settings(project)
    paths = _bootstrap_pki_paths(project)
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
    files_ready = all(
        path.exists()
        for path in (
            paths["system_ca"], paths["nginx_config"], paths["state"],
        )
    )
    if files_ready and hasattr(os, "geteuid") and os.geteuid() == 0:
        files_ready = all(
            path.exists()
            for path in (
                paths["ca_key"], paths["ca_cert"], paths["server_key"], paths["server_cert"],
            )
        )
    state_ready = False
    nginx_ready = False
    if files_ready:
        try:
            state = json.loads(paths["state"].read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                raise ValueError("Ungültiger Mavi-Serverstatus")
            state_ready = (
                state.get("instance_id") == settings["instance_id"]
                and state.get("project") == str(project.resolve())
                and state.get("base_url") == settings["base_url"]
                and state.get("webroot") == str(settings["local_dir"])
                and state.get("host") == settings["url_host"]
                and state.get("ansible_server_ip") == settings["ansible_server_ip"]
                and state.get("port") == settings["port"]
                and state.get("allowed_cidrs") == settings["allowed_cidrs"]
                and state.get("ca_validity_days") == settings["ca_validity_days"]
                and state.get("server_cert_validity_days") == settings["server_cert_validity_days"]
            )
            nginx_ready = paths["nginx_config"].read_text(encoding="utf-8") == _nginx_bootstrap_config(
                settings,
                paths,
            )
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            state_ready = False
            nginx_ready = False
    https_ready = False
    certificates_ready = (
        _certificate_valid_for(paths["ca_cert"], 30 * 86400)
        and _certificate_valid_for(paths["server_cert"], 7 * 86400)
    )
    if files_ready and state_ready and nginx_ready and certificates_ready:
        https_ready, _detail = _strict_https_probe(
            health_url,
            expected_body=health_body,
            trusted_ca=paths["system_ca"],
        )
    if files_ready and state_ready and nginx_ready and certificates_ready and https_ready:
        return settings

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        cmd_ssh_server_setup(argparse.Namespace(project=project, yes=True))
    else:
        _relaunch_bootstrap_server_setup_as_root(project)

    if not paths["system_ca"].is_file():
        die("Automatisches Setup meldete Erfolg, aber das Mavi-CA-Zertifikat fehlt.")
    # Das Root-Setup kann bei einem Portkonflikt die zentrale Basis-URL
    # automatisch angepasst haben. Daher alle abgeleiteten Werte neu laden.
    settings = _bootstrap_settings(project)
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
    https_ready, detail = _strict_https_probe(
        health_url,
        expected_body=health_body,
        trusted_ca=paths["system_ca"],
    )
    if not https_ready:
        die(f"Automatisches HTTPS-Setup wurde abgeschlossen, ist aber nicht erreichbar: {detail}")
    return settings


class _RejectBootstrapRedirects(urllib.request.HTTPRedirectHandler):
    """Feste Bootstrap-URL: auch kein HTTPS-zu-HTTP-Redirect wird verfolgt."""

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"Bootstrap-Weiterleitungen sind deaktiviert: {newurl}",
            headers,
            fp,
        )


def _strict_https_probe(
    url: str,
    *,
    expected_body: bytes | None = None,
    trusted_ca: Path | None = None,
) -> tuple[bool, str]:
    """HTTPS-Aufruf mit strikter Ketten- und Hostnamenprüfung, ohne Bypass."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "https":
            return False, "Sicherheitsabbruch: URL ist nicht HTTPS."
        context = ssl.create_default_context()
        if trusted_ca is not None:
            if not trusted_ca.is_file():
                return False, f"Vertrauenswürdige Mavi-CA fehlt: {trusted_ca}"
            # Ergänzt die private Mavi-CA ausdrücklich zum normalen Trust Store.
            # CERT_REQUIRED und check_hostname bleiben zwingend aktiv.
            context.load_verify_locations(cafile=str(trusted_ca))
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        request = urllib.request.Request(url, headers={"User-Agent": f"mavi-provisioner/{VERSION}"})
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _RejectBootstrapRedirects(),
            urllib.request.HTTPSHandler(context=context),
        )
        with opener.open(request, timeout=10) as response:
            status = int(getattr(response, "status", 200))
            final_url = str(response.geturl() or url)
            body = response.read(1024 * 1024)
        final = urllib.parse.urlsplit(final_url)
        if (
            final.scheme.lower() != "https"
            or final.hostname != parsed.hostname
            or final.port != parsed.port
        ):
            return False, f"Unzulässige HTTPS-Weiterleitung: {final_url}"
        if status < 200 or status >= 300:
            return False, f"HTTPS antwortete mit Status {status}."
        if expected_body is not None and body != expected_body:
            return False, "HTTPS-Inhalt stimmt nicht mit dem lokal veröffentlichten Artefakt überein."
        return True, f"HTTPS erreichbar, Zertifikat und Hostname gültig (Status {status})."
    except ssl.SSLCertVerificationError as exc:
        return False, f"Zertifikatsprüfung fehlgeschlagen: {exc}"
    except ssl.SSLError as exc:
        return False, f"TLS-/CA-Prüfung fehlgeschlagen: {exc}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTPS antwortete mit Status {exc.code}."
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            return False, f"Zertifikatsprüfung fehlgeschlagen: {exc.reason}"
        return False, f"HTTPS-Aufruf fehlgeschlagen: {exc}"
    except (TimeoutError, OSError, ValueError) as exc:
        return False, f"HTTPS-Aufruf fehlgeschlagen: {exc}"


def _https_ssh_bootstrap_cmd(
    ps1_download_url: str,
    ps1_sha256: str,
    *,
    ca_der: bytes,
    launcher_id: str,
) -> str:
    """Erzeugt den doppelklickbaren CMD-Starter für den OpenSSH-Bootstrap."""
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", ps1_sha256):
        raise ValueError("Der PS1-Hash für den Windows-Starter ist ungültig.")
    if not ca_der or len(ca_der) > 65536:
        raise ValueError("Das Mavi-CA-Zertifikat ist leer oder unerwartet groß.")
    safe_url = _powershell_single_quote(ps1_download_url)
    safe_sha = _powershell_single_quote(ps1_sha256.lower())
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", launcher_id).strip("._-") or "WINDOWS"
    ca_sha256 = hashlib.sha256(ca_der).hexdigest()
    ca_base64 = base64.b64encode(ca_der).decode("ascii")
    ca_chunks = [ca_base64[index:index + 64] for index in range(0, len(ca_base64), 64)]

    ca_import_script = (
        "$ErrorActionPreference='Stop';"
        "$d=Join-Path $env:TEMP 'Mavi-OpenSSH-Bootstrap';"
        "$p=Join-Path $d 'Mavi-Bootstrap-Root-CA.cer';"
        f"$expected='{ca_sha256}';"
        "$bytes=[IO.File]::ReadAllBytes($p);"
        "$sha=[Security.Cryptography.SHA256]::Create();"
        "try{$actual=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};"
        "if($actual -cne $expected){throw ('SICHERHEITSABBRUCH: CA SHA-256 stimmt nicht. Erwartet='+$expected+' Ist='+$actual)};"
        "$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$bytes);"
        "$now=[DateTime]::UtcNow;if($now -lt $cert.NotBefore.ToUniversalTime() -or $now -gt $cert.NotAfter.ToUniversalTime()){throw 'SICHERHEITSABBRUCH: Eingebettete Mavi-CA ist noch nicht oder nicht mehr gültig.'};"
        "$rawBc=$cert.Extensions|Where-Object{$_.Oid.Value -eq '2.5.29.19'}|Select-Object -First 1;"
        "if($null -eq $rawBc){throw 'SICHERHEITSABBRUCH: Zertifikat besitzt keine CA-BasicConstraints.'};"
        "$bc=New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension;"
        "$bc.CopyFrom($rawBc);if(-not $bc.CertificateAuthority){throw 'SICHERHEITSABBRUCH: Eingebettetes Zertifikat ist keine CA.'};"
        "$added=$false;"
        "$store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine');"
        "try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);"
        "$found=$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false);"
        "if($found.Count -eq 0){$store.Add($cert);$added=$true;Write-Host ('Mavi-CA installiert: '+$cert.Thumbprint) -ForegroundColor Green}"
        "else{Write-Host ('Mavi-CA bereits vertraut: '+$cert.Thumbprint) -ForegroundColor Green}}finally{$store.Close()};"
        "if($added){exit 17}else{exit 0}"
    )
    ca_import_b64 = base64.b64encode(ca_import_script.encode("utf-16-le")).decode("ascii")

    download_script = (
        "$ErrorActionPreference='Stop';"
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        f"$u='{safe_url}';$expected='{safe_sha}';"
        "$d=Join-Path $env:TEMP 'Mavi-OpenSSH-Bootstrap';"
        "New-Item -ItemType Directory -Path $d -Force|Out-Null;"
        "$p=Join-Path $d 'Mavi-OpenSSH-Setup.ps1';"
        "try{"
        "Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $p -TimeoutSec 60 -MaximumRedirection 0;"
        "if(-not(Test-Path -LiteralPath $p)){throw 'Bootstrap-Download fehlgeschlagen.'};"
        "$actual=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();"
        "if($actual -cne $expected){throw ('SICHERHEITSABBRUCH: PS1 SHA-256 stimmt nicht. Erwartet='+$expected+' Ist='+$actual)};"
        "& $p"
        "}catch{Write-Host '';Write-Host ('Mavi OpenSSH Bootstrap FEHLER: '+$_.Exception.Message) -ForegroundColor Red;"
        "Read-Host 'ENTER zum Schliessen'|Out-Null;exit 10}"
    )
    download_b64 = base64.b64encode(download_script.encode("utf-16-le")).decode("ascii")
    copied_launcher = f"Mavi-OpenSSH-Launcher-{safe_id}.cmd"
    lines = [
        "@echo off",
        "setlocal EnableExtensions DisableDelayedExpansion",
        f"title Mavi OpenSSH Vollautomatik - {safe_id}",
        "if /I \"%~1\"==\"--mavi-elevated\" goto mavi_elevated",
        f"set \"MaviCOPY=%TEMP%\\{copied_launcher}\"",
        "copy /Y \"%~f0\" \"%MaviCOPY%\" >nul",
        "if errorlevel 1 goto mavi_copy_failed",
        "echo.",
        "echo Mavi macht jetzt automatisch: UAC, CA-Vertrauen, HTTPS und OpenSSH.",
        "echo Bitte die Windows-UAC-Abfrage bestaetigen.",
        "echo.",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"try{$r=Start-Process -FilePath $env:MaviCOPY -Verb RunAs -ArgumentList @('--mavi-elevated') -Wait -PassThru;exit $r.ExitCode}catch{Write-Host $_.Exception.Message -ForegroundColor Red;exit 5}\"",
        "set \"MaviRC=%ERRORLEVEL%\"",
        "if not \"%MaviRC%\"==\"0\" (",
        "  echo.",
        "  echo Mavi Bootstrap meldete Fehlercode %MaviRC%.",
        "  pause",
        ")",
        "exit /b %MaviRC%",
        "",
        ":mavi_copy_failed",
        "echo FEHLER: Der Starter konnte nicht nach TEMP kopiert werden.",
        "pause",
        "exit /b 4",
        "",
        ":mavi_elevated",
        "powershell.exe -NoProfile -Command \"if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }\"",
        "if errorlevel 1 (",
        "  echo FEHLER: Administratorrechte wurden nicht erteilt.",
        "  pause",
        "  exit /b 5",
        ")",
        "set \"MaviDIR=%TEMP%\\Mavi-OpenSSH-Bootstrap\"",
        "if not exist \"%MaviDIR%\" mkdir \"%MaviDIR%\"",
        "set \"MaviCA64=%MaviDIR%\\Mavi-Bootstrap-Root-CA.b64\"",
        "set \"MaviCACERT=%MaviDIR%\\Mavi-Bootstrap-Root-CA.cer\"",
        f"> \"%MaviCA64%\" echo {ca_chunks[0]}",
        *[f">> \"%MaviCA64%\" echo {chunk}" for chunk in ca_chunks[1:]],
        "certutil.exe -f -decode \"%MaviCA64%\" \"%MaviCACERT%\" >nul",
        "if errorlevel 1 goto mavi_ca_failed",
        "set \"MAVI_CA_ADDED_THIS_RUN=0\"",
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {ca_import_b64}",
        "set \"MaviCARC=%ERRORLEVEL%\"",
        "if \"%MaviCARC%\"==\"17\" set \"MAVI_CA_ADDED_THIS_RUN=1\"",
        "if not \"%MaviCARC%\"==\"0\" if not \"%MaviCARC%\"==\"17\" goto mavi_ca_failed",
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {download_b64}",
        "set \"MaviRC=%ERRORLEVEL%\"",
        "if not \"%MaviRC%\"==\"0\" goto mavi_bootstrap_failed",
        "echo.",
        "echo Mavi OpenSSH wurde vollautomatisch eingerichtet.",
        "exit /b 0",
        "",
        ":mavi_ca_failed",
        "echo.",
        "echo SICHERHEITSABBRUCH: Die feste Mavi-CA konnte nicht verifiziert oder importiert werden.",
        "pause",
        "exit /b 8",
        "",
        ":mavi_bootstrap_failed",
        "echo.",
        "echo Mavi OpenSSH Bootstrap meldete Fehlercode %MaviRC%.",
        "pause",
        "exit /b %MaviRC%",
        "",
    ]
    if max((len(line) for line in lines), default=0) > 7000:
        raise RuntimeError("Interner Fehler: HTTPS-Launcher-Zeile überschreitet das sichere CMD-Limit.")
    return "\r\n".join(lines)


def _deliver_ssh_launcher_to_public_desktop(
    project: Path,
    *,
    host: str,
    launcher_path: Path,
    expected_sha256: str,
) -> str:
    """Liefert den öffentlichen, hashgebundenen Starter über das bestehende PSRP/WinRM aus.

    Das ist ausschließlich ein Ersatz für eine nicht beschreibbare zentrale
    Softwareablage. Der bisherige, bereits funktionierende Verwaltungsweg wird
    verwendet; weder HTTP noch ein freigegebener Schreibzugriff werden erzeugt.
    Die Datei landet zunächst unter einem temporären Namen auf Windows, wird
    dort gegen den lokalen SHA-256 geprüft und erst dann am endgültigen Namen veröffentlicht.
    """
    if not launcher_path.is_file():
        raise FileNotFoundError(
            "Der lokale Mavi-OpenSSH-Starter fehlt vor der Direktbereitstellung: "
            f"{launcher_path}"
        )

    expected_sha256 = str(expected_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("Der lokale SHA-256 des Mavi-OpenSSH-Starters ist ungültig.")

    local_sha256 = _sha256_file(launcher_path).lower()
    if local_sha256 != expected_sha256:
        raise RuntimeError(
            "SICHERHEITSABBRUCH: Der Mavi-OpenSSH-Starter wurde vor der Direktbereitstellung verändert; "
            f"erwartet={expected_sha256} lokal={local_sha256}"
        )

    _inv, windows, host_data = _host_inventory_entry(project, host)
    connection = _connection_label(windows, host_data)
    if connection not in {"PSRP", "WinRM"}:
        raise PermissionError(
            "Die sichere Direktbereitstellung ist nur über die noch bestehende PSRP/WinRM-Verbindung möglich. "
            f"{host} verwendet derzeit {connection}."
        )

    launcher_name = launcher_path.name
    if re.fullmatch(r"[A-Za-z0-9._-]+", launcher_name) is None:
        raise ValueError("Der Name des Mavi-OpenSSH-Starters enthält unzulässige Zeichen.")

    remote_dir = r"C:\Users\Public\Desktop\Mavi-Bootstrap"
    remote_final_path = remote_dir + "\\" + launcher_name
    remote_stage_path = remote_dir + "\\." + launcher_name + ".new"
    acl_powershell = r'''[CmdletBinding()]
param([string]$Path)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Mavi-Bootstrap-Ordner fehlt: $Path"
}

$acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) {
    [void]$acl.RemoveAccessRuleAll($rule)
}

$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$usersSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$rules = @(
    [System.Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $propagation,
        $allow
    ),
    [System.Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $propagation,
        $allow
    ),
    [System.Security.AccessControl.FileSystemAccessRule]::new(
        $usersSid,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inherit,
        $propagation,
        $allow
    )
)
foreach ($rule in $rules) {
    [void]$acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
$Ansible.Changed = $true
'''
    powershell = r'''[CmdletBinding()]
param(
    [string]$StagingPath,
    [string]$FinalPath,
    [string]$ExpectedSha256
)

$ErrorActionPreference = 'Stop'
try {
    if (-not (Test-Path -LiteralPath $StagingPath -PathType Leaf)) {
        throw "Temporärer Mavi-Starter fehlt: $StagingPath"
    }

    $stagingHash = [string](Get-FileHash -LiteralPath $StagingPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not $stagingHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA-256 des temporären Mavi-Starters stimmt nicht überein. Erwartet=$ExpectedSha256 Erhalten=$stagingHash"
    }

    if (Test-Path -LiteralPath $FinalPath -PathType Leaf) {
        Remove-Item -LiteralPath $FinalPath -Force -ErrorAction Stop
    }
    Move-Item -LiteralPath $StagingPath -Destination $FinalPath -Force -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $FinalPath -PathType Leaf)) {
        throw "Mavi-Starter konnte nicht auf dem öffentlichen Desktop veröffentlicht werden: $FinalPath"
    }

    $finalHash = [string](Get-FileHash -LiteralPath $FinalPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not $finalHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA-256 des veröffentlichten Mavi-Starters stimmt nicht überein. Erwartet=$ExpectedSha256 Erhalten=$finalHash"
    }

    $payload = [ordered]@{
        Path = $FinalPath
        Sha256 = $finalHash.ToLowerInvariant()
    }
    $json = $payload | ConvertTo-Json -Compress
    $marker = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $Ansible.Result = @{ Marker = $marker }
    $Ansible.Changed = $true
}
catch {
    Remove-Item -LiteralPath $StagingPath -Force -ErrorAction SilentlyContinue
    throw
}
'''
    play = [{
        "name": "Mavi OpenSSH-Starter direkt bereitstellen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Öffentlichen Mavi-Bootstrap-Desktop anlegen",
                "ansible.windows.win_file": {
                    "path": remote_dir,
                    "state": "directory",
                },
            },
            {
                "name": "Mavi-Bootstrap-Desktop gegen unbefugtes Ändern sperren",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": acl_powershell,
                    "parameters": {
                        "Path": remote_dir,
                    },
                },
            },
            {
                "name": "Mavi-OpenSSH-Starter temporär kopieren",
                "ansible.windows.win_copy": {
                    "src": str(launcher_path.resolve()),
                    "dest": remote_stage_path,
                    "force": True,
                },
            },
            {
                "name": "Mavi-OpenSSH-Starter prüfen und veröffentlichen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "StagingPath": remote_stage_path,
                        "FinalPath": remote_final_path,
                        "ExpectedSha256": expected_sha256,
                    },
                },
                "register": "mavi_launcher_delivery_verify",
            },
            {
                "name": "Mavi-Starter-Bereitstellung auslesen",
                "ansible.builtin.debug": {
                    "msg": "Mavi_LAUNCHER_DELIVERY_B64={{ mavi_launcher_delivery_verify.result.Marker }}"
                },
            },
        ],
    }]

    playbook_path: Path | None = None
    vault_password_file: Path | None = None
    try:
        fd, raw_playbook = tempfile.mkstemp(prefix=".mavi-ssh-launcher-delivery-", suffix=".yml")
        os.close(fd)
        playbook_path = Path(raw_playbook)
        atomic_write_yaml(playbook_path, play)

        print("  → Mavi-Starter wird über die bestehende PSRP/WinRM-Verbindung auf den öffentlichen Desktop kopiert.")
        vault_password = getpass.getpass("Vault password: ")
        vault_password_file = create_temporary_vault_password_file(vault_password)
        cmd = [
            "ansible-playbook",
            "-i",
            str(project_paths(project)["inventory"]),
            str(playbook_path),
            "--limit",
            host,
            "--vault-password-file",
            str(vault_password_file),
        ]
        try:
            completed = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Die direkte PSRP/WinRM-Bereitstellung des Mavi-Starters hat nach 120 Sekunden nicht geantwortet."
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                "Die direkte PSRP/WinRM-Bereitstellung konnte nicht gestartet werden: "
                f"{redact_sensitive_text(exc)}"
            ) from exc

        combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
        match = re.search(r"Mavi_LAUNCHER_DELIVERY_B64=([A-Za-z0-9+/=]+)", combined)
        if completed.returncode != 0 or not match:
            lines = [
                redact_sensitive_text(line.strip())
                for line in strip_ansi(combined).splitlines()
                if line.strip()
            ]
            detail = " | ".join(lines[-10:])
            raise RuntimeError(
                "Die direkte PSRP/WinRM-Bereitstellung auf den öffentlichen Desktop ist fehlgeschlagen"
                + (f": {detail}" if detail else f" (Ansible-Code {completed.returncode})")
            )

        try:
            payload = json.loads(base64.b64decode(match.group(1)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Die PSRP/WinRM-Bereitstellung lieferte keinen lesbaren SHA-256-Nachweis zurück."
            ) from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Die PSRP/WinRM-Bereitstellung lieferte ein unerwartetes Ergebnis.")

        remote_sha256 = str(payload.get("Sha256", "") or "").strip().lower()
        remote_path = str(payload.get("Path", "") or "").strip()
        if remote_sha256 != expected_sha256:
            raise RuntimeError(
                "SICHERHEITSABBRUCH: SHA-256 des direkt bereitgestellten Mavi-Starters stimmt nicht überein; "
                f"erwartet={expected_sha256} Windows={remote_sha256 or '(leer)'}"
            )
        if remote_path.casefold() != remote_final_path.casefold():
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Mavi-Starter wurde nicht am erwarteten öffentlichen Desktop-Pfad veröffentlicht."
            )
        return remote_path
    finally:
        if playbook_path is not None:
            playbook_path.unlink(missing_ok=True)
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)


def _publish_https_ssh_bootstrap(
    project: Path,
    *,
    host: str,
    public_key: str,
    msi_raw: str = "",
) -> dict[str, str]:
    settings = _bootstrap_settings(project)
    webroot: Path = settings["local_dir"]
    safe_host = re.sub(r"[^A-Za-z0-9._-]+", "_", str(host or "WINDOWS")).strip("._-") or "WINDOWS"
    host_dir = webroot / safe_host
    local_msi: Path | None = None
    if msi_raw:
        local_msi, _, _ = _software_local_and_windows_path(project, msi_raw)
        if local_msi is None or not local_msi.is_file():
            raise FileNotFoundError(
                "Die angegebene OpenSSH-MSI ist auf dem Ansible-Server nicht als Datei erreichbar: "
                f"{msi_raw}"
            )

    try:
        webroot.mkdir(parents=True, exist_ok=True)
        resolved_webroot = webroot.resolve(strict=True)
        host_dir.mkdir(parents=True, exist_ok=True)
        resolved_host_dir = host_dir.resolve(strict=True)
        resolved_host_dir.relative_to(resolved_webroot)
        if resolved_host_dir.parent != resolved_webroot:
            raise PermissionError("Host-Webroot muss ein direkter Unterordner des Bootstrap-Webroots sein.")
        probe_path = host_dir / ".mavi-write-probe"
        _atomic_write_bytes(probe_path, b"write-ok\n", mode=0o600)
        probe_path.unlink()
    except (OSError, ValueError) as exc:
        raise PermissionError(_bootstrap_setup_instruction(project, reason=str(exc))) from exc

    quoted_host = urllib.parse.quote(safe_host, safe="") + "/"
    host_base_url = urllib.parse.urljoin(settings["base_url"], quoted_host)
    ps1_name = f"Mavi-OpenSSH-Setup-{safe_host}.ps1"
    launcher_name = f"START-Mavi-OPENSSH-{safe_host}.cmd"
    msi_name = "OpenSSH-Win64.msi"
    msi_sha256 = ""
    msi_url = ""
    if local_msi is not None:
        msi_destination = host_dir / msi_name
        source_msi_sha256 = _sha256_file(local_msi)
        _atomic_copy_file(local_msi, msi_destination)
        copied_msi_sha256 = _sha256_file(msi_destination)
        if copied_msi_sha256 != source_msi_sha256:
            msi_destination.unlink(missing_ok=True)
            raise RuntimeError(
                "SICHERHEITSABBRUCH: OpenSSH-MSI wurde beim Kopieren verändert; "
                f"Quelle={source_msi_sha256} Ziel={copied_msi_sha256}"
            )
        msi_sha256 = source_msi_sha256
        msi_url = urllib.parse.urljoin(host_base_url, msi_name)

    pki_paths = _bootstrap_pki_paths(project)
    if not pki_paths["system_ca"].is_file():
        raise FileNotFoundError(
            "Die automatisch verwaltete Mavi-CA fehlt. 'mavi-provisioner ssh server-setup' ausführen."
        )
    try:
        ca_pem = pki_paths["system_ca"].read_text(encoding="ascii")
        ca_der = ssl.PEM_cert_to_DER_cert(ca_pem)
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError(f"Das Mavi-CA-Zertifikat ist nicht lesbar: {exc}") from exc
    ca_windows_thumbprint = hashlib.sha1(ca_der, usedforsecurity=False).hexdigest().upper()
    ps1_url = urllib.parse.urljoin(host_base_url, ps1_name)
    ps1_bytes = _ssh_bootstrap_ps1(
        public_key,
        bundled_msi=False,
        msi_download_url=msi_url,
        msi_sha256=msi_sha256,
        expected_signer=settings["expected_signer"],
        ansible_server_ip=settings["ansible_server_ip"],
        bootstrap_instance_id=settings["instance_id"],
        bootstrap_ca_thumbprint=ca_windows_thumbprint,
    ).encode("utf-8-sig")
    ps1_sha256 = hashlib.sha256(ps1_bytes).hexdigest()
    launcher_bytes = _https_ssh_bootstrap_cmd(
        ps1_url,
        ps1_sha256,
        ca_der=ca_der,
        launcher_id=safe_host,
    ).encode("ascii", errors="strict")

    _atomic_write_bytes(host_dir / ps1_name, ps1_bytes)
    _atomic_write_bytes(host_dir / launcher_name, launcher_bytes)

    launcher_sha256 = hashlib.sha256(launcher_bytes).hexdigest()
    # Der Starter ist absichtlich immer als echte lokale Datei vorhanden. Damit
    # kann er mit `cat <Datei>` angezeigt und manuell in den Mavi-Release-Ordner
    # kopiert werden. Ein schreibgeschützter Install-Mount blockiert die
    # OpenSSH-Vorbereitung nicht und es gibt keinen PSRP-/NTLM-Kopier-Fallback.
    offline_launcher = host_dir / launcher_name
    windows_launcher = ""
    delivery_method = "manual_release_file"
    delivery_note = "Starter lokal erzeugt; manuelle Ablage im Mavi-Release-Ordner vorgesehen."
    software_share_error = ""
    metadata = {
        "version": VERSION,
        "host": host,
        "mode": "fixed_https",
        "created_epoch": time.time(),
        "launcher_url": urllib.parse.urljoin(host_base_url, launcher_name),
        "ps1_url": ps1_url,
        "ps1_sha256": ps1_sha256,
        "msi_url": msi_url,
        "msi_sha256": msi_sha256,
        "ansible_server_ip": settings["ansible_server_ip"],
        "expected_signer": settings["expected_signer"],
        "ca_der_sha256": hashlib.sha256(ca_der).hexdigest(),
        "ca_windows_thumbprint": ca_windows_thumbprint,
        "instance_id": settings["instance_id"],
        "offline_launcher": str(offline_launcher),
        "windows_launcher": windows_launcher,
        "delivery_method": delivery_method,
        "delivery_note": delivery_note,
        "software_share_error": software_share_error,
    }
    _atomic_write_bytes(
        host_dir / ".mavi-bootstrap.json",
        (json.dumps(metadata, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    _atomic_write_bytes(webroot / "Mavi-SETUP-CHECK.txt", health_body)
    return {
        "local_dir": str(host_dir),
        "launcher": launcher_name,
        "launcher_url": metadata["launcher_url"],
        "launcher_sha256": launcher_sha256,
        "offline_launcher": str(offline_launcher),
        "windows_launcher": windows_launcher,
        "delivery_method": delivery_method,
        "delivery_note": delivery_note,
        "ca_der_sha256": hashlib.sha256(ca_der).hexdigest(),
        "ca_windows_thumbprint": ca_windows_thumbprint,
        "instance_id": settings["instance_id"],
        "ps1_url": ps1_url,
        "ps1_sha256": ps1_sha256,
        "msi_url": msi_url,
        "msi_sha256": msi_sha256,
        "health_url": urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt"),
        "health_body": health_body.decode("ascii"),
        "ansible_server_ip": settings["ansible_server_ip"],
        "expected_signer": settings["expected_signer"],
    }


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
        inv, windows, host_data = _host_inventory_entry(args.project, host)
        del inv
        host_ip = str(host_data.get("ansible_host", "") or host)
        ansible_user = str(_effective_host_var(windows, host_data, "ansible_user", ansible_user) or ansible_user)

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


def cmd_ssh_winrm_https(args: argparse.Namespace) -> None:
    """WinRM ausschließlich aus einer bestehenden Mavi-SSH-Key-Sitzung heraus härten."""
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
        _run_winrm_temporary_play(
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
    except (OSError, RuntimeError, ValueError) as exc:
        print("\nSICHERHEITSABBRUCH: WinRM wurde nicht als Mavi-Transport übernommen.")
        print(redact_sensitive_text(exc))
        print("Der Inventory-Host bleibt auf SSH. HTTP/5985 wird von Mavi nicht erneut aktiviert.")
        raise SystemExit(2)
    finally:
        vault_file.unlink(missing_ok=True)

    _remember_winrm_https_state(
        host_data,
        settings=settings,
        fqdn=identity["fqdn"],
        ca_cert=Path(issued["ca_cert"]),
        kerberos_principal=kerberos_principal,
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


def cmd_ssh_winrm_reset(args: argparse.Namespace) -> None:
    """WinRM auf Stand 0 setzen und OpenSSH auf Wunsch als letzten Kanal abschalten."""
    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    disable_openssh = bool(getattr(args, "disable_openssh", False))
    connection = str(
        _effective_host_var(windows, host_data, "ansible_connection", "") or ""
    ).lower()

    if not bool(getattr(args, "yes", False)):
        print("\nMavi REMOTE-VERWALTUNG ZURÜCKSETZEN")
        print("====================================")
        print(f"PC:       {args.host}")
        print("WinRM:    alle Listener, Mavi-Regeln, Mavi-Zertifikate und Richtlinienwerte entfernen")
        print("           Dienst anschließend stoppen und deaktivieren")
        if disable_openssh:
            print("OpenSSH:  Mavi-Key entfernen, Mavi-Firewallregel entfernen, sshd stoppen/deaktivieren")
            print("! Danach gibt es keinen Mavi-Fernzugang mehr. Neueinrichtung nur lokal per Starter.")
        else:
            print("OpenSSH:  bleibt als sofortiger Weg für eine neue WinRM-Einrichtung aktiv")
        if not yes_no("Diesen Stand-0-Rückbau wirklich ausführen?", default=False):
            print("Abgebrochen.")
            return

    requested_key = getattr(args, "key", None)
    requested_port = getattr(args, "port", None)
    if connection != "ssh" or requested_key is not None or requested_port is not None:
        if connection != "ssh":
            print(f"\n{args.host} wird zuerst über den vorhandenen Mavi-Key auf OpenSSH umgestellt.")
        cmd_ssh_use(
            argparse.Namespace(
                project=args.project,
                host=args.host,
                key=requested_key,
                port=requested_port,
                yes=bool(getattr(args, "yes", False)),
            )
        )
        inv, windows, host_data = _host_inventory_entry(args.project, args.host)

    reset_public_key_prefix = ""
    reset_key_marker = ""
    openssh_firewall_rule = ""
    if disable_openssh:
        active_key_raw = str(
            _effective_host_var(windows, host_data, "ansible_ssh_private_key_file", "") or ""
        ).strip()
        if active_key_raw:
            active_key_path = Path(active_key_raw).expanduser().resolve()
            active_public_key, _ = _public_key_summary(
                Path(str(active_key_path) + ".pub")
            )
            active_key_parts = active_public_key.split()
            if len(active_key_parts) >= 2:
                reset_public_key_prefix = f"{active_key_parts[0]} {active_key_parts[1]}"
        if not reset_public_key_prefix:
            reset_public_key_prefix = _mavi_public_key_prefix(args.project)
        reset_key_marker = _ssh_environment_marker(args.project)
        openssh_firewall_rule = (
            f"Mavi-OpenSSH-{_bootstrap_instance_id(args.project)}-Ansible-In-TCP"
        )

    root_thumbprint = ""
    ca_der = _winrm_pki_paths(args.project)["ca_der"]
    if ca_der.is_file():
        try:
            root_thumbprint = hashlib.sha1(
                ca_der.read_bytes(),
                usedforsecurity=False,
            ).hexdigest().upper()
        except (OSError, ValueError) as exc:
            die(
                "Der Fingerabdruck der lokalen Mavi-WinRM-CA konnte nicht gelesen werden: "
                f"{redact_sensitive_text(exc)}"
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
        _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_winrm_reset_play(
                root_thumbprint=root_thumbprint,
                disable_openssh=disable_openssh,
                public_key_prefix=reset_public_key_prefix,
                key_marker=reset_key_marker,
                openssh_firewall_rule=openssh_firewall_rule,
            ),
            vault_password_file=vault_file,
            description=(
                "WinRM/Kerberos- und OpenSSH-Rückbau über SSH"
                if disable_openssh
                else "WinRM/Kerberos-Stand-0-Rückbau über SSH"
            ),
            timeout=180.0,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print("\nFEHLER: Der Remote-Rückbau wurde nicht vollständig bestätigt.")
        print(redact_sensitive_text(exc))
        print(f"Der Inventory-Host {args.host} bleibt für die Reparatur auf OpenSSH eingestellt.")
        raise SystemExit(2)
    finally:
        if vault_file is not None:
            vault_file.unlink(missing_ok=True)

    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    current_key_raw = str(
        _effective_host_var(windows, host_data, "ansible_ssh_private_key_file", "") or ""
    ).strip()
    current_port_raw = _effective_host_var(windows, host_data, "ansible_port", None)
    try:
        current_port = int(current_port_raw) if current_port_raw is not None else None
    except (TypeError, ValueError):
        current_port = None
    _apply_ssh_transport(
        args.project,
        host_data,
        key_path=Path(current_key_raw).expanduser() if current_key_raw else None,
        port=current_port,
    )
    host_data.pop("mavi_winrm_https", None)
    host_data.pop("mavi_winrm_fqdn", None)
    if disable_openssh:
        host_data["mavi_remote_management_disabled"] = {
            "version": 1,
            "winrm": True,
            "openssh": True,
        }
    atomic_write_yaml(project_paths(args.project)["inventory"], inv)

    removed_artifacts, artifact_warnings = _remove_host_winrm_certificate_artifacts(
        args.project,
        args.host,
    )

    print("\n✓ Remote-Verwaltungszustand wurde zurückgesetzt.")
    print("  WinRM:            Listener entfernt, Dienst gestoppt und deaktiviert")
    print("  Kerberos/PSRP:    gespeicherter Hoststatus entfernt; kein persistenter Mavi-Ticketcache")
    print(f"  Host-PKI-Dateien: {removed_artifacts} Datei(en) auf dem Controller entfernt")
    print("  Gemeinsame CA:    bleibt bestehen, damit andere Windows-PCs weiter funktionieren")
    if disable_openssh:
        print("  OpenSSH:          Mavi-Key entfernt; sshd wird verzögert gestoppt und ist deaktiviert")
        print("  Fernzugang:       vollständig aus; OpenSSH bleibt lediglich installiert")
        print("\nFür eine spätere Neueinrichtung zuerst den Mavi-OpenSSH-Starter lokal am PC ausführen.")
        print(f"Danach: mavi-provisioner ssh use {args.host}")
    else:
        print("  OpenSSH:          bleibt installiert und aktiv")
        print(f"\nWinRM neu einrichten mit: mavi-provisioner ssh winrm-https {args.host}")
    for warning in artifact_warnings:
        print(f"! {warning}")


def cmd_ssh_use_psrp(args: argparse.Namespace) -> None:
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


def _mavi_public_key_prefix(project: Path) -> str:
    """Nur Key-Typ + Base64-Payload, ohne Kommentar, für exakten Remote-Abgleich."""
    settings = get_ssh_settings(project)
    pub_path = Path(settings["public_key"]).expanduser().resolve()
    if not pub_path.exists():
        return ""
    try:
        text = pub_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    parts = text.split()
    if len(parts) < 2:
        return ""
    return f"{parts[0]} {parts[1]}"


def _remove_mavi_ssh_keys_from_host(
    project: Path,
    host: str,
) -> int:
    """Entfernt nur Mavi-autorisierte Public Keys auf genau einem Windows-Host."""
    key_prefix = _mavi_public_key_prefix(project)
    marker = _ssh_environment_marker(project)

    powershell = r'''[CmdletBinding()]
param(
    [string]$CurrentKeyPrefix = "",
    [string]$Marker = ""
)

$keyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'

$result = [ordered]@{
    KeyFile = $keyFile
    Existed = $false
    RemovedCount = 0
    Removed = @()
    RemainingCount = 0
}

if (-not (Test-Path -LiteralPath $keyFile)) {
    $Ansible.Result = $result
    $Ansible.Changed = $false
    return
}

$result.Existed = $true
$lines = @(Get-Content -LiteralPath $keyFile -ErrorAction Stop)
$kept = New-Object 'System.Collections.Generic.List[string]'
$removed = New-Object 'System.Collections.Generic.List[string]'

foreach ($lineObj in $lines) {
    $line = [string]$lineObj
    $trim = $line.Trim()
    $remove = $false

    if (-not [string]::IsNullOrWhiteSpace($trim) -and -not $trim.StartsWith('#')) {
        if (-not [string]::IsNullOrWhiteSpace($Marker)) {
            $markerPattern = '(^|\s)' + [regex]::Escape($Marker) + '(\s|$)'
            if ($trim -match $markerPattern) {
                $remove = $true
            }
        }

        if (
            -not $remove -and
            -not [string]::IsNullOrWhiteSpace($CurrentKeyPrefix) -and
            ($trim -eq $CurrentKeyPrefix -or $trim.StartsWith($CurrentKeyPrefix + ' '))
        ) {
            $remove = $true
        }
    }

    if ($remove) {
        $removed.Add($trim)
    }
    else {
        $kept.Add($line)
    }
}

if ($removed.Count -gt 0) {
    if ($kept.Count -gt 0) {
        Set-Content -LiteralPath $keyFile -Value @($kept) -Encoding ascii
    }
    else {
        [System.IO.File]::WriteAllText($keyFile, '', [System.Text.Encoding]::ASCII)
    }

    & icacls.exe $keyFile /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "ACLs für '$keyFile' konnten nach der Key-Entfernung nicht gesetzt werden. icacls Exit-Code: $LASTEXITCODE"
    }
}

$result.RemovedCount = $removed.Count
$result.Removed = @($removed)
$result.RemainingCount = $kept.Count
$Ansible.Result = $result
$Ansible.Changed = ($removed.Count -gt 0)
'''

    play = [{
        "name": "Mavi SSH-Public-Keys entfernen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Mavi SSH-Key(s) aus administrators_authorized_keys entfernen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "CurrentKeyPrefix": key_prefix,
                        "Marker": marker,
                    },
                },
                "register": "mavi_ssh_key_remove",
            },
            {
                "name": "Mavi SSH-Key-Entfernung anzeigen",
                "ansible.builtin.debug": {
                    "msg": (
                        "Mavi_SSH_KEY_REMOVE removed={{ mavi_ssh_key_remove.result.RemovedCount | default(0) }} "
                        "remaining={{ mavi_ssh_key_remove.result.RemainingCount | default(0) }} "
                        "file={{ mavi_ssh_key_remove.result.KeyFile | default('') }}"
                    )
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
            prefix="mavi-ssh-key-remove-",
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

        cmd = [
            "ansible-playbook",
            "-i",
            str(project_paths(project)["inventory"]),
            str(tmp_path),
            "--limit",
            host,
            "--ask-vault-pass",
        ]
        return run_subprocess(cmd, project)
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass


def cmd_ssh_remove_keys(args: argparse.Namespace) -> None:
    """Mavi-Keys nach ausdrücklicher Bestätigung vom Windows-PC entfernen."""
    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    del inv
    connection_before = _connection_label(windows, host_data)
    saved_winrm_available = False
    if connection_before == "SSH":
        try:
            _saved_winrm_https_transport(args.project, host_data)
        except ValueError:
            pass
        else:
            saved_winrm_available = True

    if not bool(getattr(args, "yes", False)):
        print("\nMavi SSH-KEYS ENTFERNEN")
        print("=======================")
        print(f"PC:          {args.host}")
        print(f"Verbindung:  {connection_before}")
        print(f"Entfernt werden NUR Mavi-Keys dieses Projekts mit Marker '{_ssh_environment_marker(args.project)}'")
        print("und der aktuell auf dem Ansible-Server konfigurierte Mavi-Public-Key.")
        print("Andere Einträge in administrators_authorized_keys bleiben erhalten.")
        if connection_before == "SSH":
            if saved_winrm_available:
                print("Danach wird dieser Host auf das gespeicherte PSRP/WinRM HTTPS + Kerberos umgestellt.")
            else:
                print("! Für diesen PC ist kein geprüfter PSRP/WinRM-Ersatzweg gespeichert.")
                print("! Der Mavi-Key wird bei Bestätigung trotzdem entfernt; das Inventory bleibt auf SSH.")
        question = (
            "Mavi SSH-Key(s) trotz fehlendem Ersatzweg wirklich entfernen?"
            if connection_before == "SSH" and not saved_winrm_available
            else "Mavi SSH-Key(s) auf diesem PC wirklich entfernen?"
        )
        if not yes_no(question, default=False):
            print("Abgebrochen.")
            return

    rc = _remove_mavi_ssh_keys_from_host(args.project, args.host)
    if rc != 0:
        print(f"\n! Key-Entfernung auf {args.host} fehlgeschlagen, Code {rc}.")
        return

    if connection_before == "SSH" and saved_winrm_available:
        inv, windows, host_data = _host_inventory_entry(args.project, args.host)
        del windows
        _apply_saved_winrm_https_transport(args.project, host_data)
        atomic_write_yaml(project_paths(args.project)["inventory"], inv)
        print(f"✓ {args.host}: Mavi SSH-Key(s) entfernt und Inventory auf PSRP HTTPS/Kerberos umgestellt.")
    else:
        print(f"✓ {args.host}: Mavi SSH-Key(s) entfernt. Verbindung bleibt {connection_before}.")
        if connection_before == "SSH":
            print("  Für neue Mavi-SSH-Verbindungen muss wieder ein Key eingerichtet oder die Verbindung umgestellt werden.")

    print("  OpenSSH/sshd bleibt auf Windows installiert und aktiv.")
    print("  Fremde SSH-Keys und Mavi-known_hosts auf dem Ansible-Server bleiben unangetastet.")


def ssh_remove_keys_menu(project: Path) -> None:
    while True:
        print()
        print("Mavi SSH-KEYS ENTFERNEN")
        print("=======================")
        print("  1) Von EINEM Windows-PC entfernen")
        print("  2) Von ALLEN Windows-PCs entfernen")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        if choice == "1":
            host = choose_host_interactive(project)
            cmd_ssh_remove_keys(
                argparse.Namespace(project=project, host=host, yes=False)
            )
            return

        if choice == "2":
            inv = load_inventory(project)
            windows = ensure_windows_tree(inv)
            hosts = list((windows.get("hosts", {}) or {}).keys())
            if not hosts:
                print("Keine Windows-PCs im Inventory vorhanden.")
                return

            print()
            print(f"! Mavi SSH-Key(s) werden auf {len(hosts)} PC(s) entfernt.")
            switch_to_winrm: set[str] = set()
            ssh_without_replacement: list[str] = []
            for host in hosts:
                _, host_windows, host_data = _host_inventory_entry(project, host)
                if _connection_label(host_windows, host_data) != "SSH":
                    continue
                try:
                    _saved_winrm_https_transport(project, host_data)
                except ValueError:
                    ssh_without_replacement.append(host)
                else:
                    switch_to_winrm.add(host)

            if ssh_without_replacement:
                print(
                    f"! Für {len(ssh_without_replacement)} SSH-PC(s) ist kein geprüfter "
                    "PSRP/WinRM-Ersatzweg gespeichert: " + ", ".join(ssh_without_replacement)
                )
                print("! Bei Bestätigung werden die Mavi-Keys dort trotzdem entfernt; das Inventory bleibt auf SSH.")
                question = "Mavi SSH-Key(s) trotzdem auf ALLEN Inventory-PCs entfernen?"
            else:
                question = "Mavi SSH-Key(s) wirklich auf ALLEN Inventory-PCs entfernen?"
            if not yes_no(question, default=False):
                print("Abgebrochen.")
                return

            succeeded: list[str] = []
            failed: list[str] = []
            for index, host in enumerate(hosts, start=1):
                print()
                print(f"[{index}/{len(hosts)}] {host}")
                before_inv, before_windows, before_data = _host_inventory_entry(project, host)
                del before_inv
                connection_before = _connection_label(before_windows, before_data)
                rc = _remove_mavi_ssh_keys_from_host(project, host)
                if rc != 0:
                    failed.append(host)
                    print(f"! {host}: fehlgeschlagen, Verbindung bleibt {connection_before}.")
                    continue

                if host in switch_to_winrm:
                    after_inv, after_windows, after_data = _host_inventory_entry(project, host)
                    del after_windows
                    _apply_saved_winrm_https_transport(project, after_data)
                    atomic_write_yaml(project_paths(project)["inventory"], after_inv)
                succeeded.append(host)
                if host in switch_to_winrm:
                    print(f"✓ {host}: Key(s) entfernt → PSRP HTTPS/Kerberos")
                else:
                    print(f"✓ {host}: Key(s) entfernt, Verbindung bleibt {connection_before}")

            print()
            print("Mavi SSH-KEY-ENTFERNUNG FERTIG")
            print("==============================")
            print(f"Erfolgreich: {len(succeeded)}/{len(hosts)}")
            if failed:
                print("Fehlgeschlagen: " + ", ".join(failed))
            return

        if choice == "0":
            return

        print("Ungültige Auswahl.")


def _parse_ansible_core_version() -> tuple[int, ...] | None:
    if not shutil.which("ansible"):
        return None
    try:
        result = subprocess.run(
            ["ansible", "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    first = (result.stdout or result.stderr or "").splitlines()
    if not first:
        return None
    m = re.search(r"(?:core\s+)?(\d+)\.(\d+)(?:\.(\d+))?", first[0])
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def cmd_ssh_status(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    settings = get_ssh_settings(args.project)
    key_path = Path(getattr(args, "key", None) or settings["private_key"]).expanduser().resolve()
    pub_path = Path(str(key_path) + ".pub")
    public_key, fingerprint = _public_key_summary(pub_path)
    version = _parse_ansible_core_version()

    print("\nMavi OPENSSH-STATUS")
    print("==================")
    print(f"ssh executable:     {'✓ ' + shutil.which('ssh') if shutil.which('ssh') else 'FEHLT'}")
    print(f"ssh-keygen:         {'✓ ' + shutil.which('ssh-keygen') if shutil.which('ssh-keygen') else 'FEHLT'}")
    if version:
        supported = version >= (2, 18, 0)
        print(f"Ansible Core:       {'.'.join(map(str, version))} {'✓' if supported else '! offiziell Windows-SSH erst ab 2.18'}")
    else:
        print("Ansible Core:       nicht erkannt")
    print(f"Private Key:        {'✓' if key_path.exists() else 'FEHLT'} {key_path}")
    known_hosts = Path(settings["known_hosts"]).expanduser().resolve()
    print(f"Public Key:         {'✓' if public_key else 'FEHLT'} {pub_path}")
    print(f"known_hosts:        {'✓' if known_hosts.exists() else 'FEHLT'} {known_hosts}")
    if fingerprint:
        print(f"Fingerprint:        {fingerprint}")
    try:
        bootstrap = _bootstrap_settings(args.project)
        print(f"HTTPS-Basis-URL:     ✓ {bootstrap['base_url']}")
        print(f"HTTPS-Webroot:       {bootstrap['local_dir']}")
        print(f"Ansible-Server-IP:   ✓ {bootstrap['ansible_server_ip']}")
        print(f"MSI-Signer-Vorgabe:  {bootstrap['expected_signer'] or '(nur Authenticode Valid)'}")
    except ValueError as exc:
        print(f"HTTPS-Bootstrap:     FEHLER — {redact_sensitive_text(exc)}")
    try:
        winrm = _winrm_https_settings(args.project)
        print(f"WinRM-Endziel:       ✓ HTTPS:{winrm['port']} / Kerberos-only")
    except ValueError as exc:
        print(f"WinRM-Endziel:       FEHLER — {redact_sensitive_text(exc)}")

    host = getattr(args, "host", None)
    if host:
        inv, windows, host_data = _host_inventory_entry(args.project, host)
        del inv
        print("\nHOST")
        print("----")
        print(f"Name:               {host}")
        print(f"IP:                 {host_data.get('ansible_host', '')}")
        disabled_state = host_data.get("mavi_remote_management_disabled")
        remote_management_disabled = (
            isinstance(disabled_state, dict) and disabled_state.get("openssh") is True
        )
        if remote_management_disabled:
            print("Remote-Verwaltung:  AUS — WinRM und OpenSSH wurden vollständig deaktiviert")
        print(f"Inventory-Eintrag:  {_connection_label(windows, host_data)}")
        print(f"Port:               {_effective_host_var(windows, host_data, 'ansible_port', '')}")
        print(f"Shell:              {_effective_host_var(windows, host_data, 'ansible_shell_type', '(PSRP intern PowerShell)')}")
        print(f"Ansible-User:       {_effective_host_var(windows, host_data, 'ansible_user', '(geerbt)')}")
        print(f"Private-Key-Datei:  {host_data.get('ansible_ssh_private_key_file', '(nicht host-spezifisch)')}")
        target_host = str(host_data.get("ansible_host", "") or host)
        target_port = int(_effective_host_var(windows, host_data, "ansible_port", 22) or 22)
        print(f"Host-Key bekannt:   {'✓' if _known_host_present(known_hosts, target_host, target_port) else 'NEIN'}")
        if str(_effective_host_var(windows, host_data, "ansible_connection", "psrp")).lower() == "ssh":
            if remote_management_disabled:
                print("SSH-Dienst:         laut gespeichertem Stand-0-Status deaktiviert")
            else:
                key_only = not bool(_effective_host_var(windows, host_data, "ansible_ssh_password", ""))
                print(f"SSH Key-only:       {'✓' if key_only else '! Passwort ist noch aktiv'}")
        else:
            protocol = str(_effective_host_var(windows, host_data, "ansible_psrp_protocol", "") or "").lower()
            auth = str(_effective_host_var(windows, host_data, "ansible_psrp_auth", "") or "").lower()
            if protocol != "https" or auth != "kerberos":
                print("Transport-Schutz:  ! LEGACY/UNSICHER — nicht HTTPS + Kerberos-only")
            else:
                try:
                    _saved_winrm_https_transport(args.project, host_data)
                    print("Transport-Schutz:  ✓ HTTPS-Zertifikat + Kerberos-Endzustand gespeichert")
                except ValueError as exc:
                    print(f"Transport-Schutz:  ! {redact_sensitive_text(exc)}")


def ssh_menu(project: Path) -> None:
    while True:
        print()
        print("OPENSSH / WINDOWS")
        print("=================")
        print("  1) Mavi SSH-Key anlegen / anzeigen")
        print("  2) OpenSSH für neuen PC vollautomatisch vorbereiten")
        print("  3) PC auf OpenSSH umstellen")
        print("  4) PC auf geprüftes PSRP/WinRM HTTPS + Kerberos umstellen")
        print("  5) OpenSSH-Status / Doctor")
        print("  6) Verbindung testen (win_ping)")
        print("  7) Mavi SSH-Key(s) von Windows-PC(s) entfernen")
        print("  8) nginx/HTTPS/Zertifikat automatisch einrichten oder prüfen")
        print("  9) WinRM über OpenSSH auf HTTPS + Kerberos-only härten")
        print(" 10) WinRM/Kerberos auf Stand 0 setzen (OpenSSH bleibt aktiv)")
        print(" 11) WinRM und OpenSSH vollständig deaktivieren")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_ssh_keygen(argparse.Namespace(project=project, key=None, yes=False))
            elif choice == "2":
                host = choose_host_interactive(project)
                cmd_ssh_guide(argparse.Namespace(project=project, host=host, key=None, msi=None, prompt_msi=False))
            elif choice == "3":
                host = choose_host_interactive(project)
                cmd_ssh_use(argparse.Namespace(project=project, host=host, key=None, port=None, yes=False))
            elif choice == "4":
                host = choose_host_interactive(project)
                cmd_ssh_use_psrp(argparse.Namespace(project=project, host=host))
            elif choice == "5":
                host = choose_host_interactive(project)
                cmd_ssh_status(argparse.Namespace(project=project, host=host, key=None))
            elif choice == "6":
                host = choose_host_interactive(project)
                try:
                    cmd_ping(argparse.Namespace(project=project, host=host))
                except SystemExit as exc:
                    if exc.code not in (0, None):
                        print(f"\nPing beendet mit Code {exc.code}.")
            elif choice == "7":
                ssh_remove_keys_menu(project)
            elif choice == "8":
                cmd_ssh_setup_check(argparse.Namespace(project=project, msi=None))
            elif choice == "9":
                host = choose_host_interactive(project)
                cmd_ssh_winrm_https(argparse.Namespace(project=project, host=host))
            elif choice == "10":
                host = choose_host_interactive(project)
                cmd_ssh_winrm_reset(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        key=None,
                        port=None,
                        yes=False,
                        disable_openssh=False,
                    )
                )
            elif choice == "11":
                host = choose_host_interactive(project)
                cmd_ssh_winrm_reset(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        key=None,
                        port=None,
                        yes=False,
                        disable_openssh=True,
                    )
                )
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")

def load_inventory(project: Path) -> dict[str, Any]:
    path = project_paths(project)["inventory"]
    if not path.exists():
        return {
            "all": {
                "children": {
                    "windows": {
                        "vars": {
                            "ansible_connection": "ssh",
                            "ansible_port": 22,
                            "ansible_shell_type": "powershell",
                        },
                        "hosts": {},
                    }
                }
            }
        }
    data = load_yaml(path, {})
    if not isinstance(data, dict):
        die(f"Inventory ist kein gültiges YAML-Dictionary: {path}")
    # Alte Projekte dürfen bei keinem neuen Mavi-Aufruf versehentlich erneut
    # HTTP/5985 + NTLM verwenden. Sichere, explizit gesetzte PSRP-HTTPS/
    # Kerberos-Hosts bleiben erhalten; sonst wird nur in-memory auf SSH
    # zurückgestellt und beim nächsten Inventory-Schreiben persistiert.
    windows = (
        data.get("all", {}) if isinstance(data.get("all"), dict) else {}
    )
    children = windows.get("children", {}) if isinstance(windows.get("children"), dict) else {}
    group = children.get("windows", {}) if isinstance(children.get("windows"), dict) else {}
    group_vars = group.get("vars", {}) if isinstance(group.get("vars"), dict) else {}
    group_connection = str(group_vars.get("ansible_connection", "") or "").lower()
    group_protocol = str(group_vars.get("ansible_psrp_protocol", "") or "").lower()
    group_auth = str(group_vars.get("ansible_psrp_auth", "") or "").lower()
    group_legacy = group_connection == "psrp" and (
        group_protocol != "https" or group_auth != "kerberos"
    )
    if group_legacy:
        group_vars["ansible_connection"] = "ssh"
        group_vars["ansible_port"] = 22
        group_vars["ansible_shell_type"] = "powershell"
        for key in ("ansible_psrp_protocol", "ansible_psrp_auth", "ansible_psrp_cert_validation", "ansible_psrp_ca_cert", "ansible_psrp_message_encryption"):
            group_vars.pop(key, None)
    hosts = group.get("hosts", {}) if isinstance(group.get("hosts"), dict) else {}
    for host_vars in hosts.values():
        if not isinstance(host_vars, dict):
            continue
        connection = str(host_vars.get("ansible_connection", "") or "").lower()
        protocol = str(host_vars.get("ansible_psrp_protocol", "") or "").lower()
        auth = str(host_vars.get("ansible_psrp_auth", "") or "").lower()
        legacy = connection == "psrp" and (
            protocol != "https" or auth != "kerberos"
        )
        if legacy:
            host_vars["ansible_connection"] = "ssh"
            host_vars["ansible_port"] = 22
            host_vars["ansible_shell_type"] = "powershell"
            for key in ("ansible_psrp_protocol", "ansible_psrp_auth", "ansible_psrp_cert_validation", "ansible_psrp_ca_cert", "ansible_psrp_message_encryption"):
                host_vars.pop(key, None)
    return data


def ensure_windows_tree(inv: dict[str, Any]) -> dict[str, Any]:
    all_ = inv.setdefault("all", {})
    children = all_.setdefault("children", {})
    windows = children.setdefault("windows", {})
    vars_ = windows.setdefault("vars", {})
    vars_.setdefault("ansible_connection", "ssh")
    vars_.setdefault("ansible_port", 22)
    vars_.setdefault("ansible_shell_type", "powershell")
    windows.setdefault("hosts", {})
    return windows


def cmd_host_add(args: argparse.Namespace) -> None:
    ensure_initialized(args.project, quiet=True)
    p = project_paths(args.project)

    name = args.name or prompt("PC-Name (muss dem Windows-Computernamen entsprechen)")
    ip = validate_host_address(
        args.ip or prompt("IPv4-Adresse oder FQDN")
    )

    # Standard: KEIN host-spezifischer Benutzer. Dadurch erbt der neue PC
    # den zentralen Ansible-/Domänen-Benutzer aus windows.vars bzw. group_vars.
    # Ein Override ist nur noch bewusst per --ansible-user möglich.
    ansible_user = getattr(args, "ansible_user", None)
    legacy_local_admin = getattr(args, "local_admin", None)
    requested_connection = getattr(args, "connection", None)
    ssh_key_arg = getattr(args, "ssh_key", None)
    ssh_port_arg = getattr(args, "ssh_port", None)

    if ansible_user and legacy_local_admin:
        die("--ansible-user und --local-admin nicht gleichzeitig verwenden.")

    interactive_add = args.name is None or args.ip is None
    if requested_connection is None and interactive_add:
        print()
        selected_transport = prompt_choice(
            "Verbindung für diesen PC:",
            [
                ("1", "OpenSSH / SSH-Key (Mavi-Standard)"),
            ],
            "1",
        )
        requested_connection = "ssh"

    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        die("PC-Name enthält ungültige Zeichen.")

    inv = load_inventory(args.project)
    windows = ensure_windows_tree(inv)
    hosts = windows["hosts"]

    host_data = hosts.setdefault(name, {})
    if not isinstance(host_data, dict):
        host_data = {}
        hosts[name] = host_data

    host_data["ansible_host"] = ip

    if ansible_user:
        host_data["ansible_user"] = ansible_user
    elif legacy_local_admin:
        # Rückwärtskompatibilität für alte CLI-Aufrufe.
        host_data["ansible_user"] = f"{name}\\{legacy_local_admin}"
    else:
        # Wichtig: einen eventuell alten lokalen Override entfernen, damit
        # der zentrale Domänen-Admin wieder geerbt wird.
        host_data.pop("ansible_user", None)

    if requested_connection == "ssh":
        key_path = Path(ssh_key_arg).expanduser() if ssh_key_arg else None
        resolved_key, resolved_port = _apply_ssh_transport(
            args.project,
            host_data,
            key_path=key_path,
            port=ssh_port_arg,
        )
    elif requested_connection == "psrp":
        die(
            "Neue Hosts werden nicht mehr mit PSRP HTTP/NTLM angelegt. "
            "Zuerst den OpenSSH-Starter ausführen, dann 'ssh winrm-https' verwenden."
        )
    elif requested_connection not in (None, "inherit"):
        die("Unbekannte Verbindung. Erlaubt: inherit, psrp, ssh.")

    atomic_write_yaml(p["inventory"], inv)
    print(f"✓ {name} ({ip}) eingetragen.")

    if "ansible_user" in host_data:
        print(f"  Ansible-User: {host_data['ansible_user']} (Host-Override)")
    else:
        group_user = (windows.get("vars", {}) or {}).get("ansible_user")
        if group_user:
            print(f"  Ansible-User: {group_user} (zentral geerbt)")
        else:
            print("  Ansible-User: zentral geerbt (windows.vars / group_vars)")

    print(f"  Verbindung: {_connection_label(windows, host_data)}")
    if requested_connection == "ssh":
        print(f"  SSH-Port:    {resolved_port}")
        print(f"  SSH-Key:     {resolved_key}")
        if not resolved_key.exists():
            print("  ! SSH-Key fehlt noch. Nächster Schritt: mavi-provisioner ssh keygen")
        print(f"  Anleitung:   mavi-provisioner ssh guide {name}")


def cmd_host_list(args: argparse.Namespace) -> None:
    inv = load_inventory(args.project)
    windows = ensure_windows_tree(inv)
    hosts = windows.get("hosts", {})
    if not hosts:
        print("Keine Windows-Hosts eingetragen.")
        return

    group_user = (windows.get("vars", {}) or {}).get("ansible_user")

    print(f"{'HOST':<25} {'IP':<18} {'VERB.':<8} {'ANSIBLE-USER'}")
    print("-" * 105)
    for name, data in hosts.items():
        data = data or {}
        host_user = data.get("ansible_user")
        if host_user:
            shown_user = f"{host_user} (Host-Override)"
        elif group_user:
            shown_user = f"{group_user} (geerbt)"
        else:
            shown_user = "(geerbt aus group_vars/windows.vars)"

        connection = _connection_label(windows, data)
        print(
            f"{name:<25} "
            f"{str(data.get('ansible_host', '')):<18} "
            f"{connection:<8} "
            f"{shown_user}"
        )


def shlex_quote(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:=,@+-]+", value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run_subprocess(cmd: list[str], cwd: Path) -> int:
    shown_command = " ".join(shlex_quote(x) for x in cmd)
    print("\n→ " + redact_sensitive_text(shown_command))
    print()
    try:
        return subprocess.call(cmd, cwd=str(cwd))
    except FileNotFoundError:
        die(f"Befehl nicht gefunden: {cmd[0]}")
    return 1



ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(value: str) -> str:
    return ANSI_ESCAPE_RE.sub("", value)


def format_elapsed(seconds: float) -> str:
    seconds_i = max(0, int(seconds))
    minutes, seconds_i = divmod(seconds_i, 60)
    hours, minutes = divmod(minutes, 60)

    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds_i:02d}"

    return f"{minutes:02d}:{seconds_i:02d}"


def is_live_install_task(task_name: str) -> bool:
    """
    Nur Aufgaben markieren, bei denen der eigentliche Installer läuft.
    Kopieren, Prüfen, Diagnose usw. erzeugen keinen Heartbeat.
    """
    markers = (
        " | Systemweit installieren",
        " | Als SYSTEM installieren",
        " | Detached systemweit installieren",
        " | Interaktiv über Task Scheduler installieren",
        " | Microsoft Office / Project / Visio per ODT installieren",
        " | ODT-Task auf Abschluss warten",
        " | WinGet MACHINE installieren",
        " | WinGet USER über angemeldeten Benutzer installieren",
    )
    return any(marker in task_name for marker in markers)


def task_software_key(task_name: str) -> str:
    if " | " not in task_name:
        return ""
    return task_name.split(" | ", 1)[0].strip()


def print_live_install_status(
    *,
    host: str,
    task_name: str,
    task_started: float,
    last_output: float,
    apps: dict[str, dict[str, Any]],
) -> None:
    key = task_software_key(task_name)
    app = apps.get(key, {}) if key else {}

    now = time.monotonic()
    elapsed = format_elapsed(now - task_started)
    silent_for = max(0, int(now - last_output))

    name = str(app.get("name") or key or "unbekannt")
    context = str(app.get("context") or "machine")
    installer = (
        f"WinGet:{app.get('winget_id')}"
        if str(app.get("type") or "").lower() == "winget"
        else (Path(str(app.get("installer") or "")).name or "(unbekannt)")
    )

    arguments = app.get("arguments")
    if arguments in (None, ""):
        arguments_text = "(KEINE)"
    else:
        arguments_text = redact_sensitive_text(arguments)

    print()
    print(
        f"[Mavi LIVE {elapsed}] Installer läuft noch, "
        "Ansible wartet auf Rückmeldung."
    )
    print(f"  Host:       {host}")
    print(f"  Programm:   {name}")
    print(f"  Task:       {task_name}")
    print(f"  Kontext:    {context}")
    print(f"  Installer:  {installer}")
    print(f"  Parameter:  {arguments_text}")
    print(
        f"  Letzte Ansible-Ausgabe: vor {silent_for}s"
    )
    print(
        "  Hinweis: Der Prozess wurde NICHT abgebrochen. "
        "Das ist nur die Live-Statusanzeige."
    )
    print(flush=True)



def print_general_wait_status(
    *,
    host: str,
    current_task: str,
    task_started: float,
    last_output: float,
    apps: dict[str, dict[str, Any]],
) -> None:
    """
    Heartbeat auch dann, wenn Ansible noch keine neue TASK-Zeile geliefert
    hat. Das ist wichtig, wenn die Ausgabe selbst puffert oder ein Modul
    zwischen zwei sichtbaren Tasks hängt.
    """
    now = time.monotonic()
    elapsed = format_elapsed(now - task_started)
    silent_for = max(0, int(now - last_output))

    key = task_software_key(current_task)
    app = apps.get(key, {}) if key else {}

    name = str(app.get("name") or key or "unbekannt")
    context = str(app.get("context") or "machine")
    installer = (
        f"WinGet:{app.get('winget_id')}"
        if str(app.get("type") or "").lower() == "winget"
        else (Path(str(app.get("installer") or "")).name or "(unbekannt)")
    )
    arguments = app.get("arguments")

    if arguments in (None, ""):
        arguments_text = "(KEINE)"
    else:
        arguments_text = redact_sensitive_text(arguments)

    print()
    print(
        f"[Mavi LIVE {elapsed}] Ansible läuft noch, "
        "aber liefert gerade keine neue Ausgabe."
    )
    print(f"  Host:       {host}")
    print(f"  Programm:   {name}")
    print(f"  Letzter sichtbarer Task: {current_task or '(noch keiner)'}")
    print(f"  Kontext:    {context}")
    print(f"  Installer:  {installer}")
    print(f"  Parameter:  {arguments_text}")
    print(f"  Keine neue Ansible-Ausgabe seit: {silent_for}s")
    print(
        "  Der Provisioner läuft weiter. Das ist KEIN Fehler und "
        "es wurde nichts abgebrochen."
    )
    print(flush=True)


def _stdout_reader(
    stream: Any,
    output_queue: "queue.Queue[str | None]",
) -> None:
    """
    Eigener Reader-Thread statt selectors + TextIOWrapper.

    Grund: TextIOWrapper kann mehrere Zeilen intern puffern. selectors sieht
    dann am OS-Handle keine neuen Bytes mehr, obwohl Python noch komplette
    Zeilen im eigenen Buffer hat. Genau dadurch konnte v0.8.4 nach einem
    'skipping:' scheinbar einfrieren.
    """
    try:
        for line in iter(stream.readline, ""):
            output_queue.put(line)
    finally:
        output_queue.put(None)



def create_temporary_vault_password_file(password: str) -> Path:
    """
    Einmal eingegebenes Vault-Passwort für Hauptlauf und parallele
    Live-Probes verwenden. Datei ist 0600 und wird nach dem Lauf gelöscht.
    """
    fd, raw_path = tempfile.mkstemp(
        prefix=".mavi-vault-",
        suffix=".txt",
    )

    path = Path(raw_path)

    try:
        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(password)
            handle.write("\n")

    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass

        path.unlink(missing_ok=True)
        raise

    return path


VAULT_SECRET_VARIABLE_RE = re.compile(
    r"^(?:vault|mavi_vault)_[A-Za-z][A-Za-z0-9_]{0,127}$"
)


def _credentials_vault_path(project: Path, config: dict[str, Any]) -> tuple[Path, str]:
    project_root = project.expanduser().resolve()
    identity = config.get("identity", {})
    if not isinstance(identity, dict):
        die("identity in mavi_config.yml muss ein YAML-Objekt sein.")
    raw_path = str(
        identity.get("vault_path", "inventory/group_vars/windows/vault.yml")
        or "inventory/group_vars/windows/vault.yml"
    ).strip()
    relative = Path(raw_path)
    if relative.is_absolute():
        die("identity.vault_path muss relativ zum Laufzeitprojekt sein.")
    resolved = (project_root / relative).resolve()
    try:
        resolved.relative_to(project_root)
    except ValueError:
        die("identity.vault_path darf das Laufzeitprojekt nicht über '..' verlassen.")
    if resolved.suffix.lower() not in {".yml", ".yaml"}:
        die("identity.vault_path muss auf eine .yml- oder .yaml-Datei zeigen.")
    normalized = resolved.relative_to(project_root).as_posix()
    return resolved, normalized


def _atomic_write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    tmp_path = Path(raw_tmp)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content.rstrip() + "\n")
        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        tmp_path.unlink(missing_ok=True)


def _encrypted_vault_variable_block(
    *,
    variable_name: str,
    secret_value: str,
    vault_password_file: Path,
) -> str:
    executable = shutil.which("ansible-vault")
    if not executable:
        die(
            "ansible-vault wurde nicht gefunden. Credentials werden nicht "
            "ersatzweise im Klartext gespeichert."
        )
    result = subprocess.run(
        [
            executable,
            "encrypt_string",
            "--stdin-name",
            variable_name,
            "--vault-password-file",
            str(vault_password_file),
        ],
        input=secret_value + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = redact_sensitive_text(result.stderr or result.stdout or "")
        die(f"ansible-vault konnte den Geheimwert nicht verschlüsseln: {detail.strip()}")

    block_pattern = re.compile(
        rf"(?m)^{re.escape(variable_name)}:\s*!vault\s*\|\s*$"
        rf"(?:\r?\n[ \t]+[^\r\n]*)+"
    )
    match = block_pattern.search(result.stdout or "")
    if not match:
        die("ansible-vault lieferte keinen erwarteten verschlüsselten YAML-Block.")
    block = match.group(0).rstrip()
    if secret_value and secret_value in block:
        die("SICHERHEITSABBRUCH: ansible-vault-Ausgabe enthielt den Klartextwert.")
    return block


def _upsert_encrypted_vault_variable(
    path: Path,
    *,
    variable_name: str,
    encrypted_block: str,
    force: bool,
) -> None:
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    for line in existing.splitlines():
        if not line or line.isspace() or line.lstrip().startswith("#") or line.strip() == "---":
            continue
        if line[:1].isspace():
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*:\s*!vault\s*\|\s*", line):
            die(
                f"Vault-Datei {path} enthält nicht verschlüsselte oder unbekannte "
                "Top-Level-Daten. Mavi verändert sie nicht automatisch."
            )

    current_pattern = re.compile(
        rf"(?m)^{re.escape(variable_name)}:\s*!vault\s*\|\s*$"
        rf"(?:\r?\n[ \t]+[^\r\n]*)+"
    )
    current = current_pattern.search(existing)
    if current and not force:
        if not sys.stdin.isatty() or not yes_no(
            f"Verschlüsselten Wert '{variable_name}' ersetzen?",
            False,
        ):
            die(f"Vault-Wert '{variable_name}' wurde nicht überschrieben.")

    if current:
        updated = existing[:current.start()] + encrypted_block + existing[current.end():]
    else:
        separator = "\n\n" if existing.strip() else "---\n"
        updated = existing.rstrip() + separator + encrypted_block
    _atomic_write_private_text(path, updated)


def _prompt_secret_twice(label: str) -> str:
    value = getpass.getpass(label + ": ")
    if not value:
        die("Leere Geheimwerte werden nicht gespeichert.")
    confirmation = getpass.getpass(label + " wiederholen: ")
    if not secrets.compare_digest(value, confirmation):
        die("Die beiden Eingaben stimmen nicht überein.")
    return value


def _store_vault_secret(
    project: Path,
    *,
    variable_name: str,
    secret_label: str,
    force: bool,
) -> tuple[Path, str]:
    config = get_config(project)
    vault_path, normalized_path = _credentials_vault_path(project, config)
    secret_value = _prompt_secret_twice(secret_label)
    vault_password = getpass.getpass("Ansible-Vault-Passwort: ")
    if not vault_password:
        die("Leeres Ansible-Vault-Passwort ist nicht erlaubt.")
    vault_password_file: Path | None = None
    try:
        vault_password_file = create_temporary_vault_password_file(vault_password)
        encrypted_block = _encrypted_vault_variable_block(
            variable_name=variable_name,
            secret_value=secret_value,
            vault_password_file=vault_password_file,
        )
        _upsert_encrypted_vault_variable(
            vault_path,
            variable_name=variable_name,
            encrypted_block=encrypted_block,
            force=force,
        )
    finally:
        secret_value = ""
        vault_password = ""
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)
    return vault_path, normalized_path


def cmd_credentials_setup(args: argparse.Namespace) -> None:
    """Create the Windows credential as an encrypted group variable only."""
    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)
    identity = dict(config.get("identity", {}) or {})
    ansible_user = str(
        getattr(args, "ansible_user", None)
        or identity.get("ansible_user", "")
        or ""
    ).strip()
    if not ansible_user and sys.stdin.isatty():
        ansible_user = prompt(r"Ansible-Benutzer, z. B. EXAMPLE\Provisioning-Admin")
    try:
        ansible_user = _mavi_normalize_ansible_user(ansible_user)
    except ValueError as exc:
        die(str(exc))
    if not ansible_user:
        die("Ansible-Benutzer fehlt.")

    vault_path, normalized_path = _store_vault_secret(
        args.project,
        variable_name="ansible_password",
        secret_label=f"Kennwort für {ansible_user}",
        force=bool(getattr(args, "force", False)),
    )

    identity["ansible_user"] = ansible_user
    identity["vault_path"] = normalized_path
    config["identity"] = identity
    atomic_write_yaml(project_paths(args.project)["config"], config)

    inventory = load_inventory(args.project)
    windows = ensure_windows_tree(inventory)
    windows.setdefault("vars", {})["ansible_user"] = ansible_user
    atomic_write_yaml(project_paths(args.project)["inventory"], inventory)

    print("✓ Windows-Credential ausschließlich verschlüsselt gespeichert.")
    print(f"  Benutzer: {ansible_user}")
    print(f"  Vault:    {vault_path}")
    print("  Kennwort: nicht angezeigt und nie als CLI-Argument/Klartextdatei gespeichert")


def cmd_credentials_set(args: argparse.Namespace) -> None:
    """Add a Vault variable usable by strict installer argument references."""
    ensure_initialized(args.project, quiet=True)
    variable_name = str(args.name or "").strip()
    if not VAULT_SECRET_VARIABLE_RE.fullmatch(variable_name):
        die(
            "Installer-Geheimnis muss vault_ oder mavi_vault_ als Präfix haben "
            "und danach nur Buchstaben, Zahlen oder Unterstriche enthalten."
        )
    vault_path, _normalized_path = _store_vault_secret(
        args.project,
        variable_name=variable_name,
        secret_label=f"Geheimwert für {variable_name}",
        force=bool(getattr(args, "force", False)),
    )
    print(f"✓ '{variable_name}' verschlüsselt gespeichert: {vault_path}")
    print(f'  Katalogreferenz: "{{{{ {variable_name} }}}}"')


def redact_live_text(value: Any) -> str:
    """Kompatibilitätsname für die zentrale Secret-Schwärzung."""
    return redact_sensitive_text(value)


def _probe_process_map(
    probe: dict[str, Any] | None,
) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}

    for item in (probe or {}).get("Processes", []) or []:
        try:
            pid = int(item.get("Pid"))
        except (TypeError, ValueError):
            continue

        result[pid] = item

    return result


def print_remote_live_probe(
    probe: dict[str, Any],
    previous_probe: dict[str, Any] | None = None,
) -> None:
    """
    Kompakte Remote-Sicht auf den tatsächlich laufenden Installer.
    """
    processes = probe.get("Processes", []) or []
    current_map = _probe_process_map(probe)
    previous_map = _probe_process_map(previous_probe)

    current_pids = set(current_map)
    previous_pids = set(previous_map)

    new_pids = sorted(current_pids - previous_pids)
    gone_pids = sorted(previous_pids - current_pids)

    current_cpu = sum(
        float(item.get("CpuSeconds") or 0)
        for item in current_map.values()
    )
    previous_cpu = sum(
        float(item.get("CpuSeconds") or 0)
        for item in previous_map.values()
    )

    cpu_delta = (
        current_cpu - previous_cpu
        if previous_probe is not None
        else None
    )

    print()
    print("[Mavi REMOTE LIVE] Zustand auf dem Windows-PC")
    print(
        "  Ziel-Installer läuft: "
        + ("JA" if probe.get("TargetRunning") else "NEIN")
    )
    print(
        "  Pending Reboot:       "
        + ("JA" if probe.get("PendingReboot") else "NEIN")
    )
    print(f"  Relevante Prozesse:    {len(processes)}")

    if previous_probe is not None:
        activity: list[str] = []

        if cpu_delta is not None and cpu_delta > 0.05:
            activity.append(f"CPU +{cpu_delta:.2f}s")

        if new_pids:
            activity.append(
                "neue PID(s) " + ",".join(map(str, new_pids))
            )

        if gone_pids:
            activity.append(
                "beendete PID(s) " + ",".join(map(str, gone_pids))
            )

        if activity:
            print("  Aktivität seit Probe:  " + " | ".join(activity))
        else:
            print(
                "  Aktivität seit Probe:  "
                "keine sichtbare CPU-/Prozessänderung "
                "(nicht automatisch ein Fehler)"
            )

    if processes:
        print()
        print("  PROZESSE:")

        for item in processes[:12]:
            role = str(item.get("Role") or "RELATED")
            pid = item.get("Pid", "?")
            ppid = item.get("ParentPid", "?")
            name = str(item.get("Name") or "?")
            cpu = item.get("CpuSeconds")
            ram = item.get("WorkingSetMB")
            uptime = item.get("UptimeSeconds")

            cpu_text = "?" if cpu is None else f"{float(cpu):.2f}s"
            ram_text = "?" if ram is None else f"{float(ram):.1f} MB"

            if uptime is None:
                uptime_text = "?"
            else:
                uptime_text = format_elapsed(float(uptime))

            print(
                f"    [{role:<7}] PID={pid} PPID={ppid} "
                f"{name} | Laufzeit={uptime_text} "
                f"| CPU={cpu_text} | RAM={ram_text}"
            )

            command_line = redact_live_text(
                item.get("CommandLine")
            ).strip()

            if command_line:
                if len(command_line) > 220:
                    command_line = command_line[:220] + "..."

                print(f"              CMD: {command_line}")

    logs = probe.get("Logs", []) or []

    if logs:
        print()
        print("  AKTUELLE INSTALLER-LOGS:")

        for item in logs[:8]:
            print(
                f"    {item.get('LastWriteTime', '?')} | "
                f"{item.get('SizeKB', '?')} KB | "
                f"{item.get('Path', '?')}"
            )

    events = probe.get("MsiEvents", []) or []

    if events:
        print()
        print("  LETZTE MSI-EVENTS:")

        for item in events[:5]:
            message = redact_sensitive_text(item.get("Message"))
            if len(message) > 260:
                message = message[:260] + "..."

            print(
                f"    {item.get('Time', '?')} | "
                f"ID={item.get('Id', '?')} | {message}"
            )

    print()


def run_remote_live_probe(
    *,
    project: Path,
    host: str,
    app: dict[str, Any],
    vault_password_file: Path,
    timeout: float = 12.0,
    runtime_environment: dict[str, str] | None = None,
    kerberos_cache_only: bool = False,
) -> tuple[dict[str, Any] | None, str | None]:
    """
    Zweite kurze Ansible-Verbindung während der Hauptinstallation.
    Keine Änderung auf dem Ziel-PC, nur Prozess-/Log-/Reboot-Abfrage.
    """
    probe_playbook = project_paths(project)["live_probe_playbook"]

    if not probe_playbook.exists():
        return None, f"Probe-Playbook fehlt: {probe_playbook}"

    if str(app.get("type") or "").lower() == "winget":
        installer_name = "winget.exe"
        remote_installer = ""
    else:
        installer_name = Path(
            str(app.get("installer") or "")
        ).name
        remote_installer = (
            "C:\\Mavi-Provisioner\\Installers\\"
            + installer_name
        )

    fd, raw_output = tempfile.mkstemp(
        prefix=".mavi-live-probe-",
        suffix=".json",
    )
    os.close(fd)

    output_path = Path(raw_output)

    try:
        output_path.unlink(missing_ok=True)

        extra = {
            "mavi_probe_installer_path": remote_installer,
            "mavi_probe_installer_name": installer_name,
            "mavi_probe_software_name": str(
                app.get("name") or ""
            ),
            "mavi_probe_output_file": str(output_path),
        }

        cmd = [
            "ansible-playbook",
            "-i",
            str(project_paths(project)["inventory"]),
            str(probe_playbook),
            "--limit",
            host,
            "--vault-password-file",
            str(vault_password_file),
            "-e",
            json.dumps(extra, ensure_ascii=False),
        ]
        cmd = _ansible_command_with_kerberos_cache(
            cmd,
            enabled=kerberos_cache_only,
        )

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=runtime_environment,
            )
        except subprocess.TimeoutExpired:
            return (
                None,
                f"Remote-Probe nach {timeout:g}s ohne Antwort "
                "abgebrochen. Hauptinstallation läuft weiter.",
            )

        if result.returncode != 0:
            combined = (
                (result.stdout or "")
                + "\n"
                + (result.stderr or "")
            ).strip()

            lines = [
                line.strip()
                for line in combined.splitlines()
                if line.strip()
            ]

            detail = redact_sensitive_text(" | ".join(lines[-4:]))

            if len(detail) > 700:
                detail = detail[-700:]

            return (
                None,
                "Remote-Probe fehlgeschlagen"
                + (f": {detail}" if detail else "."),
            )

        if not output_path.exists():
            return None, "Remote-Probe lieferte keine Ergebnisdatei."

        payload = output_path.read_text(
            encoding="utf-8"
        ).strip()

        if not payload:
            return None, "Remote-Probe lieferte ein leeres Ergebnis."

        parsed = json.loads(payload)

        if not isinstance(parsed, dict):
            return None, "Remote-Probe lieferte unerwartete Daten."

        return parsed, None

    except (OSError, json.JSONDecodeError) as exc:
        return None, f"Remote-Probe konnte nicht ausgewertet werden: {exc}"

    finally:
        output_path.unlink(missing_ok=True)


def run_install_subprocess(
    cmd: list[str],
    cwd: Path,
    *,
    host: str,
    apps: dict[str, dict[str, Any]],
    status_interval: float = 10.0,
    vault_password_file: Path | None = None,
    live_probe: bool = True,
    runtime_environment: dict[str, str] | None = None,
    kerberos_cache_only: bool = False,
) -> int:
    """
    Ansible-Ausgabe live durchreichen.

    v0.8.5 benutzt einen Reader-Thread + Queue, damit keine bereits von
    Python gepufferten Ansible-Zeilen verloren/unsichtbar bleiben.

    Zusätzlich:
    - bei echtem Installer-Task: detaillierter Installer-Heartbeat
    - bei sonstiger Ansible-Stille: allgemeiner Heartbeat
    - KEIN automatischer Abbruch
    - KEINE manuellen Befehle auf dem Ziel-PC
    """
    cmd = _ansible_command_with_kerberos_cache(
        cmd,
        enabled=kerberos_cache_only,
    )
    shown_command = " ".join(shlex_quote(x) for x in cmd)
    print("\n→ " + redact_sensitive_text(shown_command))
    print()

    env = (runtime_environment or os.environ).copy()
    # Hilft Python-basierten Child-Prozessen, Ausgaben zeitnah zu flushen.
    env["PYTHONUNBUFFERED"] = "1"

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdin=None,  # Terminal geerbt, --ask-vault-pass bleibt nutzbar.
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
    except FileNotFoundError:
        die(f"Befehl nicht gefunden: {cmd[0]}")
        return 1

    assert proc.stdout is not None

    output_queue: "queue.Queue[str | None]" = queue.Queue()

    reader = threading.Thread(
        target=_stdout_reader,
        args=(proc.stdout, output_queue),
        name="mavi-ansible-output-reader",
        daemon=True,
    )
    reader.start()

    current_task = ""
    task_started = time.monotonic()
    last_output = time.monotonic()
    last_status = time.monotonic()
    stream_closed = False
    previous_probe: dict[str, Any] | None = None
    previous_probe_task = ""

    try:
        while True:
            try:
                item = output_queue.get(timeout=0.25)
            except queue.Empty:
                item = "__Mavi_NO_LINE__"

            if item is None:
                stream_closed = True

            elif item != "__Mavi_NO_LINE__":
                line = item
                print(redact_sensitive_text(line), end="", flush=True)

                now = time.monotonic()
                last_output = now

                clean = strip_ansi(line).strip()
                match = re.match(r"^TASK \[(.+)\]", clean)

                if match:
                    new_task = match.group(1).strip()

                    if new_task != current_task:
                        previous_probe = None
                        previous_probe_task = ""

                    current_task = new_task
                    task_started = now
                    last_status = now

            return_code = proc.poll()

            if return_code is not None and stream_closed and output_queue.empty():
                return return_code

            now = time.monotonic()

            if (
                status_interval > 0
                and now - last_status >= status_interval
                and proc.poll() is None
            ):
                if is_live_install_task(current_task):
                    print_live_install_status(
                        host=host,
                        task_name=current_task,
                        task_started=task_started,
                        last_output=last_output,
                        apps=apps,
                    )

                    key = task_software_key(current_task)
                    app = apps.get(key, {}) if key else {}

                    if (
                        live_probe
                        and vault_password_file is not None
                        and app
                    ):
                        probe, probe_error = run_remote_live_probe(
                            project=cwd,
                            host=host,
                            app=app,
                            vault_password_file=vault_password_file,
                            runtime_environment=runtime_environment,
                            kerberos_cache_only=kerberos_cache_only,
                        )

                        if probe is not None:
                            print_remote_live_probe(
                                probe,
                                previous_probe=(
                                    previous_probe
                                    if previous_probe_task == current_task
                                    else None
                                ),
                            )
                            previous_probe = probe
                            previous_probe_task = current_task

                        elif probe_error:
                            print()
                            print("[Mavi REMOTE LIVE] Detailprobe nicht verfügbar:")
                            print(f"  {probe_error}")
                            print(
                                "  Hauptinstallation läuft unverändert weiter."
                            )
                            print()
                else:
                    print_general_wait_status(
                        host=host,
                        current_task=current_task,
                        task_started=task_started,
                        last_output=last_output,
                        apps=apps,
                    )

                last_status = time.monotonic()

    except KeyboardInterrupt:
        print()
        print(
            "Abbruch angefordert. Ansible-Prozess wird beendet. "
            "Ein bereits gestarteter Windows-Installer kann auf dem "
            "Ziel-PC noch weiterlaufen."
        )
        proc.terminate()

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        return 130

    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass



def cmd_ping(args: argparse.Namespace) -> None:
    inventory = project_paths(args.project)["inventory"]
    cmd = [
        "ansible",
        "-i",
        str(inventory),
        args.host,
        "-m",
        "ansible.windows.win_ping",
        "--ask-vault-pass",
    ]
    raise SystemExit(run_subprocess(cmd, args.project))


def selected_apps_need_user(
    project: Path,
    names: list[str],
    all_: bool,
    catalog_name: str | None = None,
) -> bool:
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
    baseline_pids: set[int],
    max_wait_seconds: float = 90.0,
    poll_seconds: float = 5.0,
    runtime_environment: dict[str, str] | None = None,
    kerberos_cache_only: bool = False,
) -> tuple[bool, str]:
    """
    Verhindert, dass bei einer Katalogserie das nächste Paket startet,
    während ein vom Bootstrapper abgekoppelter Kindprozess noch arbeitet.
    """
    deadline = time.monotonic() + max(0.0, max_wait_seconds)
    announced = False
    last_busy: list[dict[str, Any]] = []

    while True:
        probe, error = run_remote_live_probe(
            project=project,
            host=host,
            app=app,
            vault_password_file=vault_password_file,
            timeout=12.0,
            runtime_environment=runtime_environment,
            kerberos_cache_only=kerberos_cache_only,
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
    max_wait_seconds: float = 180.0,
    runtime_environment: dict[str, str] | None = None,
    kerberos_cache_only: bool = False,
) -> bool:
    """
    Vor dem nächsten Paket kurz win_ping prüfen. Wenn ein vorheriger Installer
    Windows neu gestartet hat, wartet die Serie auf die Rückkehr des PCs.
    """
    deadline = time.monotonic() + max(1.0, max_wait_seconds)
    first_failure = True

    while True:
        cmd = [
            "ansible",
            "-i",
            str(project_paths(project)["inventory"]),
            host,
            "-m",
            "ansible.windows.win_ping",
            "--vault-password-file",
            str(vault_password_file),
        ]
        cmd = _ansible_command_with_kerberos_cache(
            cmd,
            enabled=kerberos_cache_only,
        )

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
    timeout: float = 45.0,
    runtime_environment: dict[str, str] | None = None,
    kerberos_cache_only: bool = False,
) -> tuple[dict[str, dict[str, Any]], str | None]:
    # Sicherer Precheck vor "Alle Programme".
    #
    # 1) creates_path gesetzt: exakt Test-Path. Falls der Pfad fehlt, wird
    #    NICHT auf einen moeglicherweise alten Registry-Rest ausgewichen.
    # 2) kein creates_path: konservativer Match gegen Windows Uninstall Registry.
    # 3) bei technischem Fehler wird nichts uebersprungen.

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

        cmd = [
            "ansible-playbook",
            "-i",
            str(project_paths(project)["inventory"]),
            str(tmp_path),
            "--limit",
            host,
            "--vault-password-file",
            str(vault_password_file),
        ]
        cmd = _ansible_command_with_kerberos_cache(
            cmd,
            enabled=kerberos_cache_only,
        )

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
    check: bool,
) -> list[str]:
    extra = {
        "catalog_file": str(catalog_file),
        "install_all": False,
        "software_names": software_names,
        "target_user": target_user,
    }

    cmd = [
        "ansible-playbook",
        "-i",
        str(project_paths(project)["inventory"]),
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
    ensure_initialized(args.project, quiet=True)
    p = project_paths(args.project)

    # --limit darf hier niemals ein Ansible-Muster wie "all", "windows"
    # oder "TP-*" erhalten. Nur ein exakt vorhandener Windows-Host ist gültig.
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

    results: list[dict[str, Any]] = []

    installed_precheck: dict[str, dict[str, Any]] = {}
    client_runtime_environment: dict[str, str] | None = None
    kerberos_ticket_directory: Path | None = None
    kerberos_ticket_path: Path | None = None
    kerberos_cache_only = False

    try:
        (
            client_runtime_environment,
            kerberos_ticket_directory,
            kerberos_ticket_path,
        ) = _prepare_client_runner_runtime(
            args.project,
            host=args.host,
            vault_password_file=vault_password_file,
        )
        kerberos_cache_only = kerberos_ticket_path is not None

        if args.all and not args.check:
            print()
            print("[Mavi SMART] Prüfe zuerst, welche Programme bereits installiert sind ...")

            installed_precheck, precheck_error = precheck_installed_apps(
                project=args.project,
                host=args.host,
                catalog=catalog,
                selected_keys=selected_keys,
                vault_password_file=vault_password_file,
                timeout=45.0,
                runtime_environment=client_runtime_environment,
                kerberos_cache_only=kerberos_cache_only,
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
                    max_wait_seconds=180.0,
                    runtime_environment=client_runtime_environment,
                    kerberos_cache_only=kerberos_cache_only,
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
                    timeout=12.0,
                    runtime_environment=client_runtime_environment,
                    kerberos_cache_only=kerberos_cache_only,
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
                check=bool(args.check),
            )

            return_code = run_install_subprocess(
                cmd,
                args.project,
                host=args.host,
                apps={key: app},
                status_interval=status_interval,
                vault_password_file=vault_password_file,
                live_probe=live_probe_enabled,
                runtime_environment=client_runtime_environment,
                kerberos_cache_only=kerberos_cache_only,
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
                    baseline_pids=baseline_pids,
                    max_wait_seconds=90.0,
                    poll_seconds=5.0,
                    runtime_environment=client_runtime_environment,
                    kerberos_cache_only=kerberos_cache_only,
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
        if kerberos_ticket_directory is not None and kerberos_ticket_path is not None:
            _discard_kerberos_ticket_cache(
                kerberos_ticket_directory,
                kerberos_ticket_path,
            )
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



def legacy_menu(project: Path) -> None:
    ensure_initialized(project, quiet=True)

    while True:
        default_catalog = get_default_catalog_name(project)

        print(
            "\n"
            "╔══════════════════════════════════════╗\n"
            "║   MAVI PROVISIONER — VOLLVERSION      ║\n"
            "╚══════════════════════════════════════╝\n"
            f" Standardkatalog: {default_catalog}\n"
            "\n"
            "  1) Normale Software hinzufügen\n"
            "  2) Microsoft-Produkt hinzufügen\n"
            "  3) Software-Katalog anzeigen\n"
            "  4) Software installieren\n"
            "  5) Kataloge verwalten\n"
            "  6) Neuen PC hinzufügen\n"
            "  7) PCs anzeigen\n"
            "  8) Verbindung testen (win_ping)\n"
            "  9) Dateien initialisieren / prüfen\n"
            " 10) Drucker verwalten / installieren\n"
            " 11) OpenSSH / Windows-Verbindung verwalten\n"
            " 12) Optionen / TUI anpassen\n"
            " 13) WinGet-Software suchen / hinzufügen\n"
            " 14) Microsoft Store-App suchen / hinzufügen\n"
            "  0) Beenden\n"
        )

        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_software_add(
                    argparse.Namespace(
                        project=project,
                        path=None,
                        name=None,
                        key=None,
                        catalog=None,
                        odt=None,
                    )
                )

            elif choice == "2":
                cmd_microsoft_add(
                    argparse.Namespace(
                        project=project,
                        catalog=None,
                        name=None,
                        key=None,
                        odt=None,
                    )
                )

            elif choice == "3":
                catalog_name = choose_catalog_interactive(
                    project,
                    None,
                    purpose="anzeigen",
                    ask_other=True,
                )
                cmd_software_list(
                    argparse.Namespace(
                        project=project,
                        catalog=catalog_name,
                    )
                )

            elif choice == "4":
                host = choose_host_interactive(project)

                catalog_name = choose_catalog_interactive(
                    project,
                    None,
                    purpose="für die Installation verwenden",
                    ask_other=True,
                )

                print()
                print("Was soll installiert werden?")
                print("  1) ALLE Programme aus diesem Katalog (Standard)")
                print("  2) Ein einzelnes Programm")
                print("  3) Mehrere Programme markieren")
                print("     Tipp: In 'Ein einzelnes Programm' wechselt Strg+2 sofort in den Markiermodus.")
                print()

                install_mode = input("> [1] ").strip() or "1"

                if install_mode == "1":
                    names = []
                    install_all = True

                elif install_mode == "2":
                    install_all = False
                    software_key, multi_mode = choose_software_single_with_multi_shortcut(
                        project,
                        catalog_name,
                        title=f"Einzelnes Programm aus '{catalog_name}' auswählen",
                    )
                    if multi_mode:
                        names = choose_software_multi_interactive(
                            project,
                            catalog_name,
                            title="PROGRAMME FÜR INSTALLATION MARKIEREN",
                        )
                        if not names:
                            print("Installation abgebrochen. Keine Programme markiert.")
                            continue
                    else:
                        if software_key is None:
                            continue
                        names = [software_key]

                elif install_mode == "3":
                    install_all = False
                    names = choose_software_multi_interactive(
                        project,
                        catalog_name,
                        title="PROGRAMME FÜR INSTALLATION MARKIEREN",
                    )
                    if not names:
                        print("Installation abgebrochen. Keine Programme markiert.")
                        continue

                else:
                    print("Ungültige Auswahl.")
                    continue

                target = ""
                if selected_apps_need_user(
                    project,
                    names,
                    install_all,
                    catalog_name,
                ):
                    target = prompt(
                        "Zielbenutzer für INTERAKTIVE Pakete "
                        "(Enter = aktuell angemeldet)",
                        "",
                    )

                ns = argparse.Namespace(
                    project=project,
                    host=host,
                    software=names,
                    all=install_all,
                    target_user=target,
                    check=False,
                    catalog=catalog_name,
                    status_interval=10.0,
                    live_probe=True,
                )

                try:
                    cmd_install(ns)
                except SystemExit as exc:
                    if exc.code not in (0, None):
                        print(
                            f"\nInstallation beendet mit Code {exc.code}."
                        )

            elif choice == "5":
                catalog_menu(project)

            elif choice == "6":
                cmd_host_add(
                    argparse.Namespace(
                        project=project,
                        name=None,
                        ip=None,
                        ansible_user=None,
                        local_admin=None,
                        connection=None,
                        ssh_key=None,
                        ssh_port=None,
                    )
                )

            elif choice == "7":
                cmd_host_list(argparse.Namespace(project=project))

            elif choice == "8":
                host = choose_host_interactive(project)
                try:
                    cmd_ping(
                        argparse.Namespace(
                            project=project,
                            host=host,
                        )
                    )
                except SystemExit as exc:
                    if exc.code not in (0, None):
                        print(f"\nPing beendet mit Code {exc.code}.")

            elif choice == "9":
                cmd_init(argparse.Namespace(project=project))

            elif choice == "10":
                printer_menu(project)

            elif choice == "11":
                ssh_menu(project)

            elif choice == "12":
                options_menu(project)

            elif choice == "13":
                cmd_winget_add(
                    argparse.Namespace(
                        project=project,
                        host=None,
                        query=None,
                        package_id=None,
                        source="winget",
                        catalog=None,
                        name=None,
                        key=None,
                        scope=None,
                        version=None,
                    )
                )

            elif choice == "14":
                cmd_store_add(
                    argparse.Namespace(
                        project=project,
                        host=None,
                        query=None,
                        package_id=None,
                        source="msstore",
                        catalog=None,
                        name=None,
                        key=None,
                        scope="user",
                        version=None,
                    )
                )

            elif choice == "0":
                print("Tschüss.")
                return

            else:
                print("Ungültige Auswahl.")

        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return

def mavi_software_source_setup(project: Path) -> None:
    """Softwarequelle und Windows-Pfadabbildungen vollständig in der TUI pflegen."""
    ensure_initialized(project, quiet=True)
    config = get_config(project)
    source = dict(config.get("software_source", {}) or {})
    old_source = dict(source)

    print()
    print("SOFTWAREQUELLE EINRICHTEN")
    print("=========================")

    source["label"] = prompt(
        "Bezeichnung",
        str(source.get("label", "") or "").strip() or "Softwarequelle",
    ).strip() or "Softwarequelle"

    source_kind = prompt_choice(
        "Wo liegt die Software?",
        [
            ("1", "Lokaler Ordner auf dem Controller"),
            ("2", "Windows-Freigabe / UNC"),
        ],
        "2" if str(source.get("kind", "") or "").lower() == "smb" else "1",
    )
    source["kind"] = "smb" if source_kind == "2" else "local"

    if source["kind"] == "smb":
        while True:
            unc_root = prompt(
                "UNC-Wurzel (z. B. \\\\server\\freigabe)",
                str(source.get("unc_root", "") or "").strip(),
            ).strip().rstrip("\\/")
            try:
                share, _prefix_path = _mavi_unc_mount_parts(unc_root)
            except ValueError as exc:
                print(f"! {exc}")
                continue
            break

        share_parts = [part for part in share[2:].split("/") if part]
        mount_path = (
            project
            / "software-sources"
            / slugify(share_parts[0])
            / slugify(share_parts[1])
        )
        source_root = str(mount_path)
        source["local_root"] = source_root
        source["unc_root"] = unc_root

        identity = config.get("identity", {}) or {}
        default_mount_user = (
            str(source.get("mount_user", "") or "").strip()
            or str(identity.get("ansible_user", "") or "").strip()
        )
        mount_user_label = (
            "SMB-Benutzer (DOMAIN\\Benutzer; 'gast' = Gast)"
            if default_mount_user
            else "SMB-Benutzer (DOMAIN\\Benutzer; Enter = Gast)"
        )
        mount_user = prompt(
            mount_user_label,
            default_mount_user,
        ).strip()
        source["mount_user"] = "" if mount_user.lower() == "gast" else mount_user

        mount_host = str(source.get("mount_host", "") or "").strip()
        domain_suffix = str(
            (config.get("winrm_https", {}) or {}).get("domain_suffix", "") or ""
        ).strip()
        if not mount_host and "." not in share_parts[0] and domain_suffix:
            mount_host = f"{share_parts[0]}.{domain_suffix}"

        while True:
            mounted, mount_host = _mavi_mount_smb_source(
                unc_root,
                mount_path,
                str(source.get("mount_user", "") or ""),
                mount_host,
            )
            source["mount_host"] = (
                "" if mount_host.lower() == share_parts[0].lower() else mount_host
            )
            if mounted:
                break
            if not yes_no("SMB-Verbindung erneut versuchen?", True):
                print("Softwarequelle wurde nicht geändert.")
                return
    else:
        source_root = _mavi_prompt_source_root(
            str(source.get("local_root", "") or "").strip()
            or str(project / "software-source")
        )
        source["local_root"] = source_root
        source["unc_root"] = ""
        source["mount_user"] = ""
        source["mount_host"] = ""
        if source_root:
            try:
                Path(source_root).expanduser().mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                print(f"! Software-Ordner konnte nicht automatisch angelegt werden: {exc}")

    if yes_no(
        "Windows-Laufwerksbuchstabe für diese Quelle hinterlegen?",
        bool(_mavi_drive_label(source.get("drive"))),
    ):
        while True:
            drive = _mavi_drive_label(prompt(
                "Laufwerk (z. B. S:)",
                _mavi_drive_label(source.get("drive")) or "S:\\",
            ))
            if re.fullmatch(r"[A-Z]:\\", drive):
                source["drive"] = drive
                break
            print("! Bitte nur einen Laufwerksbuchstaben wie S: eingeben.")
    else:
        source["drive"] = ""

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

    config["software_source"] = source
    config["path_mappings"] = mappings
    config["profile"]["setup_completed"] = not _mavi_profile_validation_issues(config)
    _mavi_write_config(project, config)

    print()
    print("✓ Softwarequelle gespeichert.")
    print(f"  UNC:            {unc_root or '(keine)'}")
    if source["kind"] == "local":
        print(f"  Lokaler Ordner: {source_root}")


def mavi_setup_menu(project: Path) -> None:
    """TUI-Einstieg für Grundprofil und erweiterte Softwarequellen."""
    while True:
        config = get_config(project)
        source = config.get("software_source", {}) or {}
        local_root = str(source.get("local_root", "") or "").strip()
        unc_root = str(source.get("unc_root", "") or "").strip()
        drive = _mavi_drive_label(source.get("drive"))
        source_kind = str(source.get("kind", "local") or "local").lower()

        print()
        print("GRUNDPROFIL & SOFTWAREQUELLE")
        print("============================")
        if source_kind == "smb":
            print(f"  Windows-Freigabe: {unc_root or '(noch nicht gesetzt)'}")
        else:
            print(f"  Lokaler Ordner:   {local_root or '(noch nicht gesetzt)'}")
        print(f"  Windows-Laufwerk: {drive or '(keins)'}")
        print()
        print("  1) Grundprofil bearbeiten")
        print("  2) Softwarequelle, UNC und Laufwerk einrichten")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_setup(argparse.Namespace(project=project, advanced=False))
            elif choice == "2":
                mavi_software_source_setup(project)
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")


def mavi_doctor_menu(project: Path) -> None:
    """TUI-Frontend für den read-only Doctor."""
    while True:
        print()
        print("DOCTOR & BEREITSCHAFT")
        print("=====================")
        print("  1) Controller, Profil und alle Voraussetzungen prüfen")
        print("  2) Einen bereits erreichbaren Windows-PC remote prüfen")
        print("  3) Offline-Collector für einen Windows-PC erzeugen")
        print("  4) Windows-Faktenbericht (JSON) importieren und auswerten")
        print("  5) Nur OpenSSH-Bereitschaft prüfen")
        print("  6) Nur WinRM/Kerberos-Bereitschaft prüfen")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=None,
                    feature="all",
                    remote=False,
                    ask_vault=True,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "2":
                host = choose_host_interactive(project)
                inv, windows, host_data = _host_inventory_entry(project, host)
                del inv
                connection = str(
                    _effective_host_var(
                        windows,
                        host_data,
                        "ansible_connection",
                        "ssh",
                    ) or "ssh"
                ).lower()
                ask_vault = yes_no(
                    "Benötigt dieses Inventory ein Ansible-Vault-Passwort?",
                    connection in {"psrp", "winrm"},
                )
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=host,
                    feature="all",
                    remote=True,
                    ask_vault=ask_vault,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "3":
                host = ""
                try:
                    host = choose_host_interactive(project)
                except SystemExit:
                    print("Kein Inventory-PC gewählt; Collector wird allgemein erzeugt.")
                path = _mavi_write_windows_collector(project, host or None)
                print()
                print("✓ Read-only Windows-Collector erstellt:")
                print(f"  {path}")
                print("  Datei auf das Ziel kopieren, als Administrator ausführen und die ausgegebene JSON-Datei zurück auf den Controller holen.")
            elif choice == "4":
                raw = prompt("Pfad zur Mavi-Doctor-Facts.json")
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=None,
                    feature="all",
                    remote=False,
                    ask_vault=True,
                    facts=Path(raw).expanduser(),
                    collector_out=None,
                ))
            elif choice == "5":
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=None,
                    feature="ssh",
                    remote=False,
                    ask_vault=True,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "6":
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=None,
                    feature="winrm",
                    remote=False,
                    ask_vault=True,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")


def mavi_credentials_menu(project: Path) -> None:
    """Geführter Vault-Einstieg ohne Geheimnisse an der Kommandozeile."""
    while True:
        config = get_config(project)
        identity = config.get("identity", {}) or {}
        configured_user = str(identity.get("ansible_user", "") or "").strip()
        configured_vault = str(identity.get("vault_path", "") or "").strip()

        print()
        print("ZUGANGSDATEN & VAULT")
        print("====================")
        print(f"  Windows-Benutzer: {configured_user or '(noch nicht gesetzt)'}")
        print(f"  Vault-Datei:      {configured_vault or '(noch nicht gesetzt)'}")
        print()
        print("  1) Windows-/Domänen-Benutzer und Kennwort verschlüsselt einrichten")
        print("  2) Installer-Geheimnis verschlüsselt anlegen")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_credentials_setup(argparse.Namespace(
                    project=project,
                    ansible_user=None,
                    force=False,
                ))
            elif choice == "2":
                name = prompt(
                    "Name (muss mit vault_ oder mavi_vault_ beginnen, z. B. vault_installer_token)"
                ).strip()
                cmd_credentials_set(argparse.Namespace(
                    project=project,
                    name=name,
                    force=False,
                ))
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")


def mavi_pc_menu(project: Path) -> None:
    """TUI-Flow für neue PCs: Inventory → SSH → Doctor."""
    while True:
        print()
        print("PCS & VERBINDUNG")
        print("================")
        print("  1) Neuen PC ins Inventory aufnehmen")
        print("  2) PCs anzeigen")
        print("  3) OpenSSH / Windows-Verbindung einrichten")
        print("  4) Verbindung testen (win_ping)")
        print("  5) Doctor für einen PC ausführen")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_host_add(argparse.Namespace(
                    project=project,
                    name=None,
                    ip=None,
                    ansible_user=None,
                    local_admin=None,
                    connection=None,
                    ssh_key=None,
                    ssh_port=None,
                ))
            elif choice == "2":
                cmd_host_list(argparse.Namespace(project=project))
            elif choice == "3":
                ssh_menu(project)
            elif choice == "4":
                host = choose_host_interactive(project)
                cmd_ping(argparse.Namespace(project=project, host=host))
            elif choice == "5":
                host = choose_host_interactive(project)
                inv, windows, host_data = _host_inventory_entry(project, host)
                del inv
                connection = str(
                    _effective_host_var(
                        windows,
                        host_data,
                        "ansible_connection",
                        "ssh",
                    ) or "ssh"
                ).lower()
                remote = yes_no(
                    "Read-only Fakten direkt per Ansible vom PC abrufen?",
                    True,
                )
                ask_vault = False
                if remote:
                    ask_vault = yes_no(
                        "Benötigt dieses Inventory ein Ansible-Vault-Passwort?",
                        connection in {"psrp", "winrm"},
                    )
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=host,
                    feature="all",
                    remote=remote,
                    ask_vault=ask_vault,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")


def menu(project: Path) -> None:
    """
    Die öffentliche, TUI-first Startansicht. Die historische Vollansicht
    bleibt als Untermenü erhalten, damit kein vorhandenes Feature verloren geht.
    """
    ensure_initialized(project, quiet=True)

    while True:
        config = get_config(project)
        profile = config.get("profile", {}) or {}
        profile_name = str(profile.get("name", "") or "").strip()
        setup_state = "bereit" if _mavi_profile_ready(config) else "Einrichtung offen"

        print(
            "\n"
            "╔══════════════════════════════════════╗\n"
            "║           MAVI PROVISIONER            ║\n"
            "╚══════════════════════════════════════╝\n"
            f" Umgebung: {profile_name or '(noch nicht benannt)'}  |  {setup_state}\n"
            "\n"
            "  1) Grundprofil & Softwarequelle\n"
            "  2) Zugangsdaten & Vault\n"
            "  3) Doctor & Bereitschaft\n"
            "  4) PCs & Verbindung\n"
            "  5) Software, Kataloge und Microsoft-Produkte\n"
            "  6) Drucker\n"
            "  7) Vollständige Funktionsoberfläche\n"
            "  0) Beenden\n"
        )

        choice = input("> ").strip()
        try:
            if choice == "1":
                mavi_setup_menu(project)
            elif choice == "2":
                mavi_credentials_menu(project)
            elif choice == "3":
                mavi_doctor_menu(project)
            elif choice == "4":
                mavi_pc_menu(project)
            elif choice == "5":
                print("\nDie vollständige Software- und Katalogverwaltung öffnet sich jetzt.")
                legacy_menu(project)
            elif choice == "6":
                printer_menu(project)
            elif choice == "7":
                legacy_menu(project)
            elif choice == "0":
                print("Tschüss.")
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mavi-provisioner",
        description=(
            "Interaktives Mavi-Frontend für Ansible-Windows-Provisioning "
            "mit mehreren Software-Katalogen. "
            "Ohne Unterbefehl startet das Menü."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Beispiele:
  mavi-provisioner
  mavi-provisioner setup
  mavi-provisioner doctor
  mavi-provisioner doctor --format json
  mavi-provisioner doctor PC-001 --remote
  mavi-provisioner doctor-collector --out ./Mavi-Doctor-Collector.ps1

  # Kataloge
  mavi-provisioner catalog list
  mavi-provisioner catalog create buero
  mavi-provisioner catalog create technik --copy-from default
  mavi-provisioner catalog set-default buero
  mavi-provisioner catalog copy default buero chrome pascom
  mavi-provisioner catalog copy default test --all --create-destination
  mavi-provisioner catalog repair --catalog default
  mavi-provisioner catalog repair --all

  # Software
  mavi-provisioner software add "S:\Tools\example-installer.exe"
  mavi-provisioner software add "S:\Tools\remote-support.msi" --catalog technik
  mavi-provisioner software list --serve-report
  mavi-provisioner winget add --query vlc
  mavi-provisioner store add --query "Microsoft To Do"
  mavi-provisioner software list
  mavi-provisioner software list --catalog buero
  mavi-provisioner software show pascom --catalog buero
  mavi-provisioner software edit pascom --catalog buero
  mavi-provisioner software remove pascom --catalog buero

  # WinGet
  mavi-provisioner winget add --query vlc
  mavi-provisioner winget add --id VideoLAN.VLC --scope machine

  # Parameter-Backups, unabhängig von der Installer-Version
  mavi-provisioner params backup --catalog default --all
  mavi-provisioner params backup --catalog default pascom citrixworkspaceapp_x64
  mavi-provisioner params list
  mavi-provisioner params restore pascom --catalog default
  mavi-provisioner params restore --catalog default --all

  # Microsoft Office / Project / Visio
  # Empfohlener Weg: expliziter Microsoft-Assistent.
  mavi-provisioner microsoft add
  mavi-provisioner microsoft add --catalog buero
  mavi-provisioner microsoft add --catalog buero --odt "S:\Microsoft\ODT\setup.exe"

  # Falls man versehentlich OfficeSetup.exe über "software add" auswählt,
  # bietet das Tool den Wechsel zum Microsoft-Assistenten an.

  # Installation
  mavi-provisioner install PC-001 --all
  mavi-provisioner install PC-001 --all --catalog buero
  mavi-provisioner install PC-001 remote_support --status-interval 5
  # Bootstrapper unbeaufsichtigt: context: machine_detached
  # Sichtbare Admin-GUI: context: machine_interactive
  # USER zuerst; sichtbarer UAC-Fallback nur bei benötigter Elevation: context: user_uac
  # Sichtbare Benutzer-GUI: context: user_interactive
  mavi-provisioner install PC-001 remote_support --no-live-probe
  mavi-provisioner install PC-001 browser remote_support --catalog default

  # TCP/IP-Drucker
  mavi-provisioner printer add --name "Büro 1. OG" --ip 10.10.20.50 --driver-dir "S:\Drucker\Treiber"
  mavi-provisioner printer list
  mavi-provisioner printer install PC-001 buero_1og
  mavi-provisioner printer install PC-001 --all

  # PCs
  mavi-provisioner host add PC-001 10.10.20.101
  mavi-provisioner host list
  mavi-provisioner ping PC-001

  # OpenSSH-Vollautomatik: nginx, CA, HTTPS und Windows-Starter
  mavi-provisioner ssh server-setup
  mavi-provisioner ssh auto PC-001
  mavi-provisioner ssh use PC-001
  mavi-provisioner ssh status PC-001
  mavi-provisioner ssh psrp PC-001
  mavi-provisioner ssh winrm-reset PC-001
  mavi-provisioner ssh winrm-reset PC-001 --disable-openssh

Ohne --catalog wird immer der aktuell gesetzte Standardkatalog verwendet. Im interaktiven Menü können PCs, Kataloge und Programme bequem per Nummer gewählt werden. Unter 'Kataloge verwalten' lassen sich bestehende Programme schnell bearbeiten, anzeigen, kopieren und entfernen. Strg+2 wechselt in unterstützten Programmauswahlen direkt in den Mehrfachmodus.
""",
    )

    parser.add_argument(
        "--project",
        type=Path,
        default=DEFAULT_PROJECT,
        help="Ansible-Laufzeitprojekt (Standard: ~/.local/share/mavi-provisioner)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    sub = parser.add_subparsers(dest="command")

    # Nur für den von ``software list --serve-report`` gestarteten,
    # kurzlebigen Kindprozess. Kein Verzeichnis wird freigegeben.
    p_report_serve = sub.add_parser(
        "_report-serve",
        help=argparse.SUPPRESS,
    )
    p_report_serve.add_argument("--file", type=Path, required=True)
    p_report_serve.add_argument("--bind", required=True)
    p_report_serve.add_argument("--port", type=int, required=True)
    p_report_serve.add_argument("--ttl", type=int, required=True)
    p_report_serve.set_defaults(func=cmd_internal_report_serve)

    p_init = sub.add_parser(
        "init",
        help="Kataloge und generische Playbooks anlegen/aktualisieren",
    )
    p_init.set_defaults(func=cmd_init)

    p_setup = sub.add_parser(
        "setup",
        help="Interaktives, nicht geheimes Umgebungsprofil einrichten",
    )
    p_setup.add_argument(
        "--advanced",
        action="store_true",
        help="Zusätzlich SMB-/Laufwerks- und Bootstrap-Details abfragen",
    )
    p_setup.set_defaults(func=cmd_setup)

    p_credentials = sub.add_parser(
        "credentials",
        help="Credentials ausschließlich verschlüsselt in Ansible Vault verwalten",
    )
    credentials_sub = p_credentials.add_subparsers(
        dest="credentials_command",
        required=True,
    )
    p_credentials_setup = credentials_sub.add_parser(
        "setup",
        help="Zentralen Windows-Ansible-Benutzer und verschlüsseltes Kennwort einrichten",
    )
    p_credentials_setup.add_argument(
        "--ansible-user",
        help=r"Nicht geheimer Benutzer, z. B. EXAMPLE\Provisioning-Admin",
    )
    p_credentials_setup.add_argument(
        "--force",
        action="store_true",
        help="Vorhandenen verschlüsselten ansible_password-Wert ersetzen",
    )
    p_credentials_setup.set_defaults(func=cmd_credentials_setup)

    p_credentials_set = credentials_sub.add_parser(
        "set",
        help="Verschlüsseltes Installer-Geheimnis als vault_*-Variable speichern",
    )
    p_credentials_set.add_argument("name", help="Variablenname mit vault_ oder mavi_vault_ Präfix")
    p_credentials_set.add_argument(
        "--force",
        action="store_true",
        help="Vorhandenen verschlüsselten Wert ersetzen",
    )
    p_credentials_set.set_defaults(func=cmd_credentials_set)

    p_doctor = sub.add_parser(
        "doctor",
        help="Read-only Voraussetzungen und optional Windows-Fakten prüfen",
    )
    p_doctor.add_argument(
        "host",
        nargs="?",
        help="Optionaler Inventory-Hostname für Ziel-PC-Prüfungen",
    )
    p_doctor.add_argument(
        "--feature",
        choices=("all", "ssh", "winrm", "software"),
        default="all",
        help="Prüfbereich (Standard: all)",
    )
    p_doctor.add_argument(
        "--remote",
        action="store_true",
        help="Read-only Fakten temporär per Ansible vom Ziel-PC abrufen",
    )
    p_doctor.add_argument(
        "--no-ask-vault",
        dest="ask_vault",
        action="store_false",
        help="Beim Remote-Doctor kein Vault-Passwort abfragen",
    )
    p_doctor.add_argument(
        "--facts",
        type=Path,
        help="Lokale Mavi-Doctor-Facts.json importieren",
    )
    p_doctor.add_argument(
        "--format",
        dest="output_format",
        choices=("text", "json"),
        default="text",
        help="Ausgabeformat; JSON eignet sich für Automatisierung",
    )
    p_doctor.set_defaults(func=cmd_doctor, ask_vault=True)

    p_doctor_collector = sub.add_parser(
        "doctor-collector",
        help="Offline-Collector explizit als PowerShell-Datei erzeugen",
    )
    p_doctor_collector.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Zielpfad der zu erzeugenden PowerShell-Datei",
    )
    p_doctor_collector.set_defaults(func=cmd_doctor_collector)

    # --------------------------
    # Catalog
    # --------------------------
    p_catalog = sub.add_parser(
        "catalog",
        help="Software-Kataloge erstellen, auswählen und kopieren",
    )
    cat_sub = p_catalog.add_subparsers(
        dest="catalog_command",
        required=True,
    )

    p_cl = cat_sub.add_parser(
        "list",
        help="Alle Kataloge und den Standardkatalog anzeigen",
    )
    p_cl.set_defaults(func=cmd_catalog_list)

    p_cc = cat_sub.add_parser(
        "create",
        help="Neuen Katalog erstellen",
    )
    p_cc.add_argument("name", help="Name des neuen Katalogs")
    p_cc.add_argument(
        "--copy-from",
        help="Neuen Katalog direkt als Kopie eines bestehenden Katalogs anlegen",
    )
    p_cc.add_argument(
        "--set-default",
        action="store_true",
        help="Den neuen Katalog direkt zum Standard machen",
    )
    p_cc.set_defaults(func=cmd_catalog_create)

    p_csd = cat_sub.add_parser(
        "set-default",
        help="Standardkatalog festlegen",
    )
    p_csd.add_argument("name", help="Vorhandener Katalog")
    p_csd.set_defaults(func=cmd_catalog_set_default)

    p_cp = cat_sub.add_parser(
        "copy",
        help="Software von einem Katalog in einen anderen kopieren",
    )
    p_cp.add_argument("source", help="Quellkatalog")
    p_cp.add_argument("destination", help="Zielkatalog")
    p_cp.add_argument(
        "software",
        nargs="*",
        help="Software-Schlüssel; ohne Angabe wird interaktiv gefragt",
    )
    p_cp.add_argument(
        "--all",
        action="store_true",
        help="Alle Softwareeinträge kopieren",
    )
    p_cp.add_argument(
        "--overwrite",
        action="store_true",
        help="Abweichende vorhandene Einträge im Ziel überschreiben",
    )
    p_cp.add_argument(
        "--create-destination",
        action="store_true",
        help="Zielkatalog automatisch anlegen, falls er fehlt",
    )
    p_cp.set_defaults(func=cmd_catalog_copy)

    p_cr = cat_sub.add_parser(
        "repair",
        help="Rohe Scan-/Jinja-Daten aus Katalogeinträgen entfernen",
    )
    p_cr.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_cr.add_argument(
        "--all",
        action="store_true",
        help="Alle Kataloge reparieren",
    )
    p_cr.set_defaults(func=cmd_catalog_repair)

    # --------------------------
    # Microsoft Office / Project / Visio
    # --------------------------
    p_ms = sub.add_parser(
        "microsoft",
        help="Microsoft Office, Project oder Visio über ODT/XML verwalten",
    )
    ms_sub = p_ms.add_subparsers(
        dest="microsoft_command",
        required=True,
    )

    p_ms_add = ms_sub.add_parser(
        "add",
        help="Microsoft-Produkt interaktiv zu einem Katalog hinzufügen",
    )
    p_ms_add.add_argument(
        "--catalog",
        help="Zielkatalog; ohne Angabe wird der Standard vorgeschlagen",
    )
    p_ms_add.add_argument(
        "--name",
        help="Anzeigename im Katalog",
    )
    p_ms_add.add_argument(
        "--key",
        help="Katalog-Schlüssel",
    )
    p_ms_add.add_argument(
        "--odt",
        help="Optionaler Pfad zur ODT setup.exe; sonst wird interaktiv gefragt",
    )
    p_ms_add.set_defaults(func=cmd_microsoft_add)

    # --------------------------
    # Software
    # --------------------------
    p_sw = sub.add_parser(
        "software",
        help="Software in Katalogen verwalten",
    )
    sw_sub = p_sw.add_subparsers(
        dest="software_command",
        required=True,
    )


    p_add = sw_sub.add_parser(
        "add",
        help="MSI/EXE mit festen oder manuell gesetzten Parametern hinzufügen",
    )
    p_add.add_argument("path", nargs="?", help="Installer-Pfad")
    p_add.add_argument("--name", help="Anzeigename")
    p_add.add_argument("--key", help="Katalog-Schlüssel")
    p_add.add_argument(
        "--catalog",
        help="Zielkatalog; ohne Angabe wird der Standard vorgeschlagen",
    )
    p_add.add_argument(
        "--allow-unsafe-missing-sha256",
        action="store_true",
        help=(
            "Explizite Legacy-Ausnahme: lokalen Installer ohne SHA-256 binden "
            "(unsicher; Standard ist fail-closed)"
        ),
    )
    p_add.set_defaults(func=cmd_software_add)

    p_list = sw_sub.add_parser(
        "list",
        help="Software eines Katalogs anzeigen",
    )
    p_list.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_list.add_argument(
        "--serve-report",
        action="store_true",
        help=(
            "HTML-Bericht kurzzeitig per tokenisiertem HTTP bereitstellen "
            "(Standard: nur lokale Datei)"
        ),
    )
    p_list.add_argument(
        "--report-bind",
        default="loopback",
        metavar="LOOPBACK|LAN|IP",
        help=(
            "Bind für --serve-report; Standard: loopback. LAN/private IP "
            "ist ein bewusstes, unverschlüsseltes Opt-in"
        ),
    )
    p_list.add_argument(
        "--report-port",
        type=int,
        default=REPORT_HTTP_PORT,
        help=f"TCP-Port des kurzzeitigen Reportservers (Standard: {REPORT_HTTP_PORT})",
    )
    p_list.add_argument(
        "--report-ttl",
        type=int,
        default=REPORT_HTTP_DEFAULT_TTL,
        help=(
            "Lebensdauer in Sekunden, begrenzt auf 30–3600 "
            f"(Standard: {REPORT_HTTP_DEFAULT_TTL})"
        ),
    )
    p_list.set_defaults(func=cmd_software_list)

    p_edit = sw_sub.add_parser(
        "edit",
        help="Bestehendes Paket interaktiv schnell bearbeiten",
    )
    p_edit.add_argument(
        "key",
        nargs="?",
        help="Software-Schlüssel; ohne Angabe interaktive Auswahl",
    )
    p_edit.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_edit.set_defaults(func=cmd_software_edit)

    p_show = sw_sub.add_parser(
        "show",
        help="Ein Paket vollständig anzeigen",
    )
    p_show.add_argument("key")
    p_show.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_show.set_defaults(func=cmd_software_show)

    p_rm = sw_sub.add_parser(
        "remove",
        help="Paket aus einem Katalog entfernen",
    )
    p_rm.add_argument("key")
    p_rm.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_rm.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Ohne Rückfrage löschen",
    )
    p_rm.set_defaults(func=cmd_software_remove)

    # --------------------------
    # WinGet
    # --------------------------
    p_winget = sub.add_parser(
        "winget",
        help="WinGet-Pakete suchen und zum Software-Katalog hinzufügen",
    )
    winget_sub = p_winget.add_subparsers(
        dest="winget_command",
        required=True,
    )

    p_wa = winget_sub.add_parser(
        "add",
        help="WinGet-Paket suchen/prüfen und zum Katalog hinzufügen",
    )
    p_wa.add_argument("--host", help="Referenz-PC für die WinGet-Suche")
    p_wa.add_argument("--query", help="Suchbegriff, z. B. vlc")
    p_wa.add_argument("--id", dest="package_id", help="Exakte WinGet-Paket-ID, z. B. VideoLAN.VLC")
    p_wa.add_argument("--source", default="winget", help="WinGet-Quelle (Standard: winget)")
    p_wa.add_argument("--scope", choices=["machine", "user"], help="Installationsbereich")
    p_wa.add_argument("--version", help="Optional feste Paketversion; Standard: aktuellste")
    p_wa.add_argument("--catalog", help="Zielkatalog")
    p_wa.add_argument("--name", help="Anzeigename")
    p_wa.add_argument("--key", help="Katalog-Schlüssel")
    p_wa.set_defaults(func=cmd_winget_add)

    # --------------------------
    # Microsoft Store (über WinGet msstore)
    # --------------------------
    p_store = sub.add_parser(
        "store",
        help="Microsoft-Store-Apps über die WinGet-Quelle msstore verwalten",
    )
    store_sub = p_store.add_subparsers(
        dest="store_command",
        required=True,
    )

    p_sa = store_sub.add_parser(
        "add",
        help="Microsoft-Store-App suchen und als USER-Paket zum Katalog hinzufügen",
    )
    p_sa.add_argument("--host", help="Referenz-PC für die Microsoft-Store-Suche")
    p_sa.add_argument("--query", help="Suchbegriff, z. B. Microsoft To Do")
    p_sa.add_argument("--id", dest="package_id", help="Exakte Microsoft-Store-ID")
    p_sa.add_argument("--catalog", help="Zielkatalog")
    p_sa.add_argument("--name", help="Anzeigename")
    p_sa.add_argument("--key", help="Katalog-Schlüssel")
    p_sa.set_defaults(func=cmd_store_add, source="msstore", scope="user", version=None)


    # --------------------------
    # Parameter-Backups
    # --------------------------
    p_params = sub.add_parser(
        "params",
        help="Installer-Parameter unabhängig vom Installer sichern/wiederherstellen",
    )
    params_sub = p_params.add_subparsers(
        dest="params_command",
        required=True,
    )

    p_pb = params_sub.add_parser(
        "backup",
        help="Flags/Kontext/Erkennungspfad aus einem Katalog sichern",
    )
    p_pb.add_argument(
        "software",
        nargs="*",
        help="Software-Schlüssel; ohne Angabe werden alle gesichert",
    )
    p_pb.add_argument(
        "--catalog",
        help="Quellkatalog; Standard: Default-Katalog",
    )
    p_pb.add_argument(
        "--all",
        action="store_true",
        help="Alle Programme im Katalog sichern",
    )
    p_pb.set_defaults(func=cmd_params_backup)

    p_pl = params_sub.add_parser(
        "list",
        help="Gesicherte Parameter-Profile anzeigen",
    )
    p_pl.set_defaults(func=cmd_params_list)

    p_pr = params_sub.add_parser(
        "restore",
        help="Gesicherte Parameter auf aktuellen Installer-Eintrag anwenden",
    )
    p_pr.add_argument(
        "profile",
        nargs="?",
        help="Profil/Software-Schlüssel; ohne Angabe interaktive Auswahl",
    )
    p_pr.add_argument(
        "--catalog",
        help="Zielkatalog; Standard: Default-Katalog",
    )
    p_pr.add_argument(
        "--target-key",
        help="Auf abweichenden Software-Schlüssel anwenden",
    )
    p_pr.add_argument(
        "--all",
        action="store_true",
        help="Alle passenden Profile auf den Katalog anwenden",
    )
    p_pr.add_argument(
        "--force",
        action="store_true",
        help="Auch bei geändertem Installer-Typ wiederherstellen",
    )
    p_pr.set_defaults(func=cmd_params_restore)

    # --------------------------
    # Printer
    # --------------------------
    p_printer = sub.add_parser(
        "printer",
        help="TCP/IP-Drucker und Treiberordner verwalten/installieren",
    )
    printer_sub = p_printer.add_subparsers(
        dest="printer_command",
        required=True,
    )

    p_pa = printer_sub.add_parser(
        "add",
        help="TCP/IP-Drucker samt Treiberordner zum Druckerkatalog hinzufügen",
    )
    p_pa.add_argument("--name", help="Windows-Druckername")
    p_pa.add_argument("--key", help="Drucker-Schlüssel im Katalog")
    p_pa.add_argument("--ip", help="IPv4-Adresse des Druckers")
    p_pa.add_argument(
        "--driver-dir",
        help=(
            "Vollständig entpackter Druckertreiber-Ordner; Mavi sucht "
            "die passende INF automatisch"
        ),
    )
    p_pa.add_argument(
        "--driver-inf",
        help="Direkter INF-Pfad (Legacy/Expertenmodus)",
    )
    p_pa.add_argument(
        "--driver-name",
        help="Exakter Windows-Druckertreibername; sonst INF-Auswahl",
    )
    p_pa.add_argument(
        "--port-name",
        help="TCP/IP-Portname; Standard: IP_<Adresse>",
    )
    p_pa.add_argument(
        "--port-number",
        type=int,
        default=9100,
        help="RAW-TCP-Port (Standard: 9100)",
    )
    p_pa.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Vorhandenen Katalogeintrag ohne Rückfrage überschreiben",
    )
    p_pa.set_defaults(func=cmd_printer_add)

    p_plist = printer_sub.add_parser(
        "list",
        help="Druckerkatalog anzeigen",
    )
    p_plist.set_defaults(func=cmd_printer_list)

    p_pshow = printer_sub.add_parser(
        "show",
        help="Druckereintrag vollständig anzeigen",
    )
    p_pshow.add_argument("key")
    p_pshow.set_defaults(func=cmd_printer_show)

    p_premove = printer_sub.add_parser(
        "remove",
        help="Drucker nur aus dem Katalog entfernen",
    )
    p_premove.add_argument("key")
    p_premove.add_argument("-y", "--yes", action="store_true")
    p_premove.set_defaults(func=cmd_printer_remove)

    p_pinstall = printer_sub.add_parser(
        "install",
        help="Einen oder mehrere TCP/IP-Drucker systemweit installieren",
    )
    p_pinstall.add_argument("host", help="Inventory-Hostname")
    p_pinstall.add_argument(
        "printers",
        nargs="*",
        help="Drucker-Schlüssel",
    )
    p_pinstall.add_argument(
        "--all",
        action="store_true",
        help="Alle Drucker aus dem Druckerkatalog installieren",
    )
    p_pinstall.set_defaults(func=cmd_printer_install)

    # --------------------------
    # Host
    # --------------------------
    p_host = sub.add_parser(
        "host",
        help="Windows-PCs im Inventory verwalten",
    )
    host_sub = p_host.add_subparsers(
        dest="host_command",
        required=True,
    )

    p_ha = host_sub.add_parser(
        "add",
        help="Neuen Windows-PC hinzufügen",
    )
    p_ha.add_argument("name", nargs="?")
    p_ha.add_argument("ip", nargs="?")
    p_ha.add_argument(
        "--ansible-user",
        help=(
            r"Optionaler host-spezifischer Benutzer, z. B. EXAMPLE\Admin. "
            "Ohne Angabe wird der zentrale Domänen-/Ansible-User geerbt."
        ),
    )
    p_ha.add_argument(
        "--local-admin",
        help=(
            "Veraltet: lokaler Admin-Name. Nur für Rückwärtskompatibilität; "
            "Standard ist jetzt der zentrale Domänen-User."
        ),
    )
    p_ha.add_argument(
        "--connection",
        choices=["inherit", "psrp", "ssh"],
        default="inherit",
        help="Verbindung für diesen Host; Standard: zentrale Inventory-Einstellung erben",
    )
    p_ha.add_argument(
        "--ssh-key",
        help="Privater SSH-Key für --connection ssh; Standard: Projekt/.ssh/mavi_windows_ed25519",
    )
    p_ha.add_argument(
        "--ssh-port",
        type=int,
        help="SSH-Port für --connection ssh; Standard: 22",
    )
    p_ha.set_defaults(func=cmd_host_add)

    p_hl = host_sub.add_parser(
        "list",
        help="Windows-PCs anzeigen",
    )
    p_hl.set_defaults(func=cmd_host_list)

    # --------------------------
    # OpenSSH / Windows
    # --------------------------
    p_ssh = sub.add_parser(
        "ssh",
        help="OpenSSH für Windows-Hosts einrichten und verwalten",
    )
    ssh_sub = p_ssh.add_subparsers(
        dest="ssh_command",
        required=True,
    )

    p_sk = ssh_sub.add_parser(
        "keygen",
        help="Dedizierten Mavi-Ed25519-Key auf dem Ansible-Server anlegen",
    )
    p_sk.add_argument("--key", help="Alternativer privater Key-Pfad")
    p_sk.add_argument("-y", "--yes", action="store_true", help="Key ohne Rückfrage erzeugen")
    p_sk.set_defaults(func=cmd_ssh_keygen)

    p_server_setup = ssh_sub.add_parser(
        "server-setup",
        help="nginx, private Mavi-CA, SAN-Zertifikat, Webroot und Firewall automatisch einrichten",
    )
    p_server_setup.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="für den internen sudo-Neustart; die Einrichtung bleibt vollautomatisch",
    )
    p_server_setup.set_defaults(func=cmd_ssh_server_setup)

    p_sg = ssh_sub.add_parser(
        "guide",
        aliases=["auto"],
        help="komplette OpenSSH-Vollautomatik vorbereiten und den Laptop-Starter ablegen",
    )
    p_sg.add_argument("host", nargs="?", help="Optionaler Inventory-Host für IP/User-Hinweise")
    p_sg.add_argument("--key", help="Alternativer privater Key-Pfad; .pub wird daneben erwartet")
    p_sg.add_argument("--msi", help="Optionaler Windows-/UNC-Pfad zur OpenSSH-Win64-MSI; sonst Windows Capability/FoD")
    p_sg.set_defaults(func=cmd_ssh_guide)

    p_sc = ssh_sub.add_parser(
        "setup-check",
        help="nginx/HTTPS/Zertifikat automatisch einrichten und anschließend diagnostizieren",
    )
    p_sc.add_argument(
        "--msi",
        help="Optionale OpenSSH-MSI für SHA-256- und Authenticode-Diagnose",
    )
    p_sc.set_defaults(func=cmd_ssh_setup_check)

    p_su = ssh_sub.add_parser(
        "use",
        help="Inventory-Host auf OpenSSH + PowerShell + SSH-Key umstellen",
    )
    p_su.add_argument("host", help="Inventory-Hostname")
    p_su.add_argument("--key", help="Alternativer privater SSH-Key")
    p_su.add_argument("--port", type=int, help="SSH-Port; Standard: 22")
    p_su.add_argument("-y", "--yes", action="store_true", help="gescannten SSH-Host-Key ohne Rückfrage übernehmen")
    p_su.set_defaults(func=cmd_ssh_use)

    p_sp = ssh_sub.add_parser(
        "psrp",
        help="Inventory-Host auf zuvor geprüftes PSRP/WinRM HTTPS + Kerberos umstellen",
    )
    p_sp.add_argument("host", help="Inventory-Hostname")
    p_sp.set_defaults(func=cmd_ssh_use_psrp)

    p_swh = ssh_sub.add_parser(
        "winrm-https",
        aliases=["winrm-kerberos"],
        help="WinRM über bestehendes OpenSSH auf HTTPS + Kerberos-only härten und HTTP/5985 entfernen",
    )
    p_swh.add_argument("host", help="Inventory-Hostname mit eingerichteter OpenSSH-Key-Verbindung")
    p_swh.set_defaults(func=cmd_ssh_winrm_https)

    p_swr = ssh_sub.add_parser(
        "winrm-reset",
        aliases=["winrm-disable"],
        help="WinRM/Kerberos über OpenSSH vollständig auf Stand 0 zurücksetzen",
    )
    p_swr.add_argument("host", help="Inventory-Hostname; OpenSSH muss auf Windows erreichbar sein")
    p_swr.add_argument("--key", help="Alternativer privater SSH-Key für den Rückbau")
    p_swr.add_argument("--port", type=int, help="SSH-Port für den Rückbau; Standard aus der Konfiguration")
    p_swr.add_argument(
        "--disable-openssh",
        action="store_true",
        help="nach dem WinRM-Rückbau auch Mavi-SSH-Key/Firewall entfernen und sshd deaktivieren",
    )
    p_swr.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Stand-0-Rückbau ohne Bestätigungsfrage starten",
    )
    p_swr.set_defaults(func=cmd_ssh_winrm_reset)

    p_ss = ssh_sub.add_parser(
        "status",
        help="Lokalen SSH-/Ansible-Status und optional einen Host anzeigen",
    )
    p_ss.add_argument("host", nargs="?", help="Optionaler Inventory-Hostname")
    p_ss.add_argument("--key", help="Alternativer privater SSH-Key")
    p_ss.set_defaults(func=cmd_ssh_status)

    p_sr = ssh_sub.add_parser(
        "remove-keys",
        help="Mavi-Public-Key(s) von einem Windows-PC entfernen",
    )
    p_sr.add_argument("host", help="Inventory-Hostname")
    p_sr.add_argument("-y", "--yes", action="store_true", help="ohne Rückfrage entfernen")
    p_sr.set_defaults(func=cmd_ssh_remove_keys)

    p_ping = sub.add_parser(
        "ping",
        help="Ansible win_ping über die konfigurierte Verbindung ausführen",
    )
    p_ping.add_argument("host")
    p_ping.set_defaults(func=cmd_ping)

    # --------------------------
    # Install
    # --------------------------
    p_install = sub.add_parser(
        "install",
        help="Software aus einem Katalog installieren",
    )
    p_install.add_argument(
        "host",
        help="Inventory-Hostname",
    )
    p_install.add_argument(
        "software",
        nargs="*",
        help="Ein oder mehrere Software-Schlüssel",
    )
    p_install.add_argument(
        "--all",
        action="store_true",
        help="Alle Pakete aus dem gewählten Katalog installieren",
    )
    p_install.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_install.add_argument(
        "--target-user",
        help=r"Benutzer für interaktive Kontexte, z. B. EXAMPLE\Max.Mustermann",
    )
    p_install.add_argument(
        "--check",
        action="store_true",
        help="Ansible Check Mode",
    )
    p_install.add_argument(
        "--status-interval",
        type=float,
        default=10.0,
        help=(
            "Sekunden zwischen Mavi-Live-Meldungen während ein Installer "
            "läuft (Standard: 10; 0 = aus)"
        ),
    )
    p_install.add_argument(
        "--no-live-probe",
        dest="live_probe",
        action="store_false",
        help=(
            "Remote-Prozess-/Log-Probe während laufender Installer "
            "deaktivieren"
        ),
    )
    p_install.set_defaults(
        func=cmd_install,
        live_probe=True,
    )

    return parser



def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        menu(args.project.resolve())
        return

    args.project = args.project.resolve()
    args.func(args)


if __name__ == "__main__":
    main()
