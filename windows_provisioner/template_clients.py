# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Ansible-Vorlagen für Windows-Clients.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations


CLIENT_OPTIMIZE_PLAYBOOK_TEMPLATE = r"""---
- name: MAVI Windows-Client optimieren
  hosts: windows
  gather_facts: false

  tasks:
    - name: Schnellstart und Bildschirmtimeout verwalten
      ansible.windows.win_powershell:
        error_action: continue
        script: |
          [CmdletBinding()]
          param(
            [int]$DisableFastStartup = 0,
            [long]$MonitorTimeoutAcMinutes = -1,
            [long]$MonitorTimeoutDcMinutes = -1
          )

          Set-StrictMode -Version Latest
          $ErrorActionPreference = 'Stop'

          $powerCfg = Join-Path $env:SystemRoot 'System32\powercfg.exe'
          $videoSubgroup = '7516b95f-f776-4464-8c53-06167f40cc99'
          $videoTimeout = '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
          $fastStartupPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
          $fastStartupPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
          $errors = [System.Collections.Generic.List[object]]::new()

          $disableFastStartupRequested = ($DisableFastStartup -eq 1)

          $result = [ordered]@{
              Schema = 1
              Success = $true
              Changed = $false
              ComputerName = $env:COMPUTERNAME
              FastStartup = [ordered]@{
                  RequestedDisable = $disableFastStartupRequested
                  PolicyValue = $null
                  RegistryValueBefore = $null
                  RegistryValueAfter = $null
                  EnabledBefore = $null
                  EnabledAfter = $null
                  Status = 'QUERY_ONLY'
                  Changed = $false
              }
              Power = [ordered]@{
                  ActiveScheme = [ordered]@{ Guid = ''; Name = '' }
                  Ac = [ordered]@{
                      RequestedMinutes = if ($MonitorTimeoutAcMinutes -ge 0) { $MonitorTimeoutAcMinutes } else { $null }
                      BeforeSeconds = $null
                      AfterSeconds = $null
                      Status = 'QUERY_ONLY'
                      Changed = $false
                  }
                  Dc = [ordered]@{
                      RequestedMinutes = if ($MonitorTimeoutDcMinutes -ge 0) { $MonitorTimeoutDcMinutes } else { $null }
                      BeforeSeconds = $null
                      AfterSeconds = $null
                      Status = 'QUERY_ONLY'
                      Changed = $false
                  }
              }
              Errors = @()
          }

          function Add-MaviError {
              param([string]$Area, [string]$Message)
              $errors.Add([ordered]@{ Area = $Area; Message = $Message }) | Out-Null
          }

          function Get-DwordValue {
              param([string]$Path, [string]$Name)
              try {
                  $value = Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop
                  return [int]$value
              }
              catch {
                  return $null
              }
          }

          function Invoke-MaviPowerCfg {
              param([string[]]$Arguments)
              $text = (& $powerCfg @Arguments 2>&1 | Out-String).Trim()
              if ($LASTEXITCODE -ne 0) {
                  throw "powercfg endete mit Code $LASTEXITCODE."
              }
              return $text
          }

          function Get-MaviMonitorPowerState {
              $activeText = Invoke-MaviPowerCfg @('/GETACTIVESCHEME')
              $guidMatch = [regex]::Match(
                  $activeText,
                  '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
              )
              if (-not $guidMatch.Success) {
                  throw 'Aktives Energieschema konnte nicht ermittelt werden.'
              }

              $guid = $guidMatch.Value
              $nameMatch = [regex]::Match($activeText, '\((?<Name>[^()]*)\)\s*\*?\s*$')
              $queryText = Invoke-MaviPowerCfg @('/QUERY', $guid, $videoSubgroup, $videoTimeout)
              $indexes = [regex]::Matches($queryText, '(?i)0x([0-9a-f]{1,8})')
              if ($indexes.Count -lt 2) {
                  throw 'AC/DC-Bildschirmtimeout konnte nicht gelesen werden.'
              }

              return [pscustomobject]@{
                  Guid = $guid
                  Name = if ($nameMatch.Success) { $nameMatch.Groups['Name'].Value.Trim() } else { '' }
                  AcSeconds = [Convert]::ToUInt32($indexes[$indexes.Count - 2].Groups[1].Value, 16)
                  DcSeconds = [Convert]::ToUInt32($indexes[$indexes.Count - 1].Groups[1].Value, 16)
              }
          }

          try {
              try {
                  $policyValue = Get-DwordValue -Path $fastStartupPolicyPath -Name 'HiberbootEnabled'
                  $beforeValue = Get-DwordValue -Path $fastStartupPath -Name 'HiberbootEnabled'
                  $result.FastStartup.PolicyValue = $policyValue
                  $result.FastStartup.RegistryValueBefore = $beforeValue
                  $result.FastStartup.EnabledBefore = if ($null -ne $policyValue) {
                      $policyValue -ne 0
                  }
                  elseif ($null -eq $beforeValue) { $null }
                  else { $beforeValue -ne 0 }

                  if ($disableFastStartupRequested) {
                      if ($policyValue -eq 1) {
                          $result.FastStartup.Status = 'POLICY_CONFLICT'
                          Add-MaviError -Area 'FastStartup' -Message 'Eine Windows-Richtlinie erzwingt den Schnellstart.'
                      }
                      elseif ($beforeValue -eq 0) {
                          $result.FastStartup.Status = 'ALREADY_DISABLED'
                      }
                      else {
                          if (-not (Test-Path -LiteralPath $fastStartupPath)) {
                              New-Item -Path $fastStartupPath -Force | Out-Null
                          }
                          New-ItemProperty -LiteralPath $fastStartupPath -Name 'HiberbootEnabled' -PropertyType DWord -Value 0 -Force | Out-Null
                          $result.FastStartup.Status = 'DISABLED'
                      }
                  }

                  $afterValue = Get-DwordValue -Path $fastStartupPath -Name 'HiberbootEnabled'
                  $result.FastStartup.RegistryValueAfter = $afterValue
                  $result.FastStartup.EnabledAfter = if ($null -ne $policyValue) {
                      $policyValue -ne 0
                  }
                  elseif ($null -eq $afterValue) { $null }
                  else { $afterValue -ne 0 }
                  $result.FastStartup.Changed = ($beforeValue -ne $afterValue)
                  if (
                      $disableFastStartupRequested -and
                      $policyValue -ne 1 -and
                      $afterValue -ne 0
                  ) {
                      $result.FastStartup.Status = 'ERROR'
                      Add-MaviError -Area 'FastStartup' -Message 'Der deaktivierte Schnellstart konnte nicht verifiziert werden.'
                  }
              }
              catch {
                  $result.FastStartup.Status = 'ERROR'
                  Add-MaviError -Area 'FastStartup' -Message 'Der Schnellstartstatus konnte nicht verarbeitet werden.'
              }

              $beforePower = $null
              $requestedAcSeconds = if ($MonitorTimeoutAcMinutes -ge 0) {
                  [long]$MonitorTimeoutAcMinutes * 60
              }
              else { $null }
              $requestedDcSeconds = if ($MonitorTimeoutDcMinutes -ge 0) {
                  [long]$MonitorTimeoutDcMinutes * 60
              }
              else { $null }
              try {
                  $beforePower = Get-MaviMonitorPowerState
                  $result.Power.ActiveScheme.Guid = $beforePower.Guid
                  $result.Power.ActiveScheme.Name = $beforePower.Name
                  $result.Power.Ac.BeforeSeconds = $beforePower.AcSeconds
                  $result.Power.Dc.BeforeSeconds = $beforePower.DcSeconds
              }
              catch {
                  Add-MaviError -Area 'PowerQuery' -Message 'Das aktive Energieschema oder der Bildschirmtimeout konnte nicht gelesen werden.'
                  $result.Power.Ac.Status = 'ERROR'
                  $result.Power.Dc.Status = 'ERROR'
              }

              if ($null -ne $beforePower) {
                  $activateScheme = $false

                  if ($null -ne $requestedAcSeconds) {
                      try {
                          if ([long]$beforePower.AcSeconds -eq $requestedAcSeconds) {
                              $result.Power.Ac.Status = 'UNCHANGED'
                          }
                          else {
                              Invoke-MaviPowerCfg @('/SETACVALUEINDEX', $beforePower.Guid, $videoSubgroup, $videoTimeout, [string]$requestedAcSeconds) | Out-Null
                              $result.Power.Ac.Status = 'SET'
                              $activateScheme = $true
                          }
                      }
                      catch {
                          $result.Power.Ac.Status = 'ERROR'
                          Add-MaviError -Area 'PowerAC' -Message 'Der Bildschirmtimeout im Netzbetrieb konnte nicht gesetzt werden.'
                      }
                  }

                  if ($null -ne $requestedDcSeconds) {
                      try {
                          if ([long]$beforePower.DcSeconds -eq $requestedDcSeconds) {
                              $result.Power.Dc.Status = 'UNCHANGED'
                          }
                          else {
                              Invoke-MaviPowerCfg @('/SETDCVALUEINDEX', $beforePower.Guid, $videoSubgroup, $videoTimeout, [string]$requestedDcSeconds) | Out-Null
                              $result.Power.Dc.Status = 'SET'
                              $activateScheme = $true
                          }
                      }
                      catch {
                          $result.Power.Dc.Status = 'ERROR'
                          Add-MaviError -Area 'PowerDC' -Message 'Der Bildschirmtimeout im Akkubetrieb konnte nicht gesetzt werden.'
                      }
                  }

                  if ($activateScheme) {
                      try {
                          Invoke-MaviPowerCfg @('/SETACTIVE', $beforePower.Guid) | Out-Null
                      }
                      catch {
                          Add-MaviError -Area 'PowerActivate' -Message 'Das geänderte Energieschema konnte nicht erneut aktiviert werden.'
                      }
                  }

                  try {
                      $afterPower = Get-MaviMonitorPowerState
                      $result.Power.ActiveScheme.Guid = $afterPower.Guid
                      $result.Power.ActiveScheme.Name = $afterPower.Name
                      $result.Power.Ac.AfterSeconds = $afterPower.AcSeconds
                      $result.Power.Dc.AfterSeconds = $afterPower.DcSeconds
                      $result.Power.Ac.Changed = ($beforePower.AcSeconds -ne $afterPower.AcSeconds)
                      $result.Power.Dc.Changed = ($beforePower.DcSeconds -ne $afterPower.DcSeconds)
                      if (
                          $null -ne $requestedAcSeconds -and
                          $result.Power.Ac.Status -ne 'ERROR' -and
                          [long]$afterPower.AcSeconds -ne $requestedAcSeconds
                      ) {
                          $result.Power.Ac.Status = 'ERROR'
                          Add-MaviError -Area 'PowerAC' -Message 'Der Bildschirmtimeout im Netzbetrieb entspricht nach dem Setzen nicht dem gewünschten Wert.'
                      }
                      if (
                          $null -ne $requestedDcSeconds -and
                          $result.Power.Dc.Status -ne 'ERROR' -and
                          [long]$afterPower.DcSeconds -ne $requestedDcSeconds
                      ) {
                          $result.Power.Dc.Status = 'ERROR'
                          Add-MaviError -Area 'PowerDC' -Message 'Der Bildschirmtimeout im Akkubetrieb entspricht nach dem Setzen nicht dem gewünschten Wert.'
                      }
                  }
                  catch {
                      if ($null -ne $requestedAcSeconds) {
                          $result.Power.Ac.Status = 'ERROR'
                      }
                      if ($null -ne $requestedDcSeconds) {
                          $result.Power.Dc.Status = 'ERROR'
                      }
                      Add-MaviError -Area 'PowerVerify' -Message 'Die geänderten Bildschirmtimeouts konnten nicht verifiziert werden.'
                  }
              }
          }
          catch {
              Add-MaviError -Area 'Unhandled' -Message 'Die Client-Optimierung wurde unerwartet unterbrochen.'
          }
          finally {
              $result.Changed = [bool](
                  $result.FastStartup.Changed -or
                  $result.Power.Ac.Changed -or
                  $result.Power.Dc.Changed
              )
              $result.Errors = @($errors.ToArray())
              $result.Success = ($errors.Count -eq 0)

              $json = $result | ConvertTo-Json -Compress -Depth 8
              $marker = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
              $Ansible.Result = @{ Marker = $marker }
              $Ansible.Changed = [bool]$result.Changed
          }
        parameters:
          DisableFastStartup: "{{ (client_disable_fast_startup | default(false) | bool) | ternary(1, 0) }}"
          MonitorTimeoutAcMinutes: "{{ client_monitor_timeout_ac_minutes | default(-1) | int }}"
          MonitorTimeoutDcMinutes: "{{ client_monitor_timeout_dc_minutes | default(-1) | int }}"
      register: mavi_client_optimize
      become: true
      become_method: runas
      become_user: SYSTEM
      failed_when: false

    - name: Strukturiertes Optimierungsergebnis ausgeben
      ansible.builtin.debug:
        msg: >-
          MAVI_CLIENT_OPTIMIZE_B64={{
            mavi_client_optimize.result.Marker | default('')
          }}
"""

CLIENT_UNINSTALL_PLAYBOOK_TEMPLATE = r"""---
- name: MAVI klassische Windows-Programme verwalten
  hosts: windows
  gather_facts: false

  tasks:
    - name: Programminventar erfassen oder einzelnes Programm deinstallieren
      ansible.windows.win_powershell:
        error_action: continue
        script: |
          [CmdletBinding()]
          param(
            [ValidateSet('inventory', 'uninstall')][string]$Action = 'inventory',
            [string]$ProgramId = '',
            [string]$ExpectedDisplayName = '',
            [string]$ExpectedScope = '',
            [string]$ExpectedUserSid = '',
            [int]$TimeoutMinutes = 45
          )

          Set-StrictMode -Version Latest
          $ErrorActionPreference = 'Stop'
          $uninstallRelativePath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'

          function Get-MaviInteractiveUser {
              $userName = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
              if ([string]::IsNullOrWhiteSpace($userName)) {
                  return [pscustomobject]@{ Name = ''; Sid = '' }
              }

              try {
                  $sid = ([System.Security.Principal.NTAccount]$userName).Translate(
                      [System.Security.Principal.SecurityIdentifier]
                  ).Value
                  return [pscustomobject]@{ Name = $userName; Sid = [string]$sid }
              }
              catch {
                  return [pscustomobject]@{ Name = $userName; Sid = '' }
              }
          }

          function New-MaviProgramId {
              param(
                [string]$Hive,
                [string]$View,
                [string]$Sid,
                [string]$KeyName
              )

              $canonical = ('{0}|{1}|{2}|{3}' -f $Hive, $View, $Sid, $KeyName).ToUpperInvariant()
              $sha = [System.Security.Cryptography.SHA256]::Create()
              try {
                  $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))
                  return (([BitConverter]::ToString($bytes)) -replace '-', '').ToLowerInvariant()
              }
              finally {
                  $sha.Dispose()
              }
          }

          function Split-MaviUninstallCommand {
              param([string]$Command)

              $rawCommand = ([string]$Command).Trim()
              if ([string]::IsNullOrWhiteSpace($rawCommand)) {
                  return $null
              }

              if ($rawCommand.StartsWith('"')) {
                  $match = [regex]::Match($rawCommand, '^"(?<File>[^"]+)"\s*(?<Args>.*)$')
              }
              else {
                  $match = [regex]::Match(
                      $rawCommand,
                      '^(?<File>.*?\.(?:exe|com|cmd|bat))(?=\s|$)\s*(?<Args>.*)$',
                      [Text.RegularExpressions.RegexOptions]::IgnoreCase
                  )
              }

              if (-not $match.Success) {
                  return $null
              }

              return [pscustomobject]@{
                  File = $match.Groups['File'].Value.Trim()
                  Arguments = $match.Groups['Args'].Value.Trim()
              }
          }

          function Get-MaviProductCode {
              param(
                [string]$KeyName,
                [string]$QuietCommand,
                [string]$UninstallCommand,
                [bool]$WindowsInstaller
              )

              $guidPattern = '(?i)\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}'
              if (
                  $WindowsInstaller -and
                  $KeyName -match '(?i)^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$'
              ) {
                  return $Matches[0].ToUpperInvariant()
              }

              foreach ($command in @($QuietCommand, $UninstallCommand)) {
                  if ($command -match '(?i)\bmsiexec(?:\.exe)?\b' -and $command -match $guidPattern) {
                      return $Matches[0].ToUpperInvariant()
                  }
              }

              return ''
          }

          function Test-MaviM365 {
              param(
                [string]$DisplayName,
                [string]$KeyName,
                [string]$QuietCommand,
                [string]$UninstallCommand
              )

              $combined = "$DisplayName $KeyName $QuietCommand $UninstallCommand"
              if ($combined -match '(?i)(2024|LTSC|Project|Visio|Copilot)') {
                  return $false
              }

              if ($combined -match '(?i)\b(?:O365[A-Za-z0-9]*Retail|M365Apps[A-Za-z0-9]*)\b') {
                  return $true
              }

              return $DisplayName -match '(?i)\b(?:Microsoft 365 Apps|Microsoft Office 365|Office 365)\b'
          }

          function Get-MaviRegistryRoots {
              param([object]$Identity)

              $roots = @(
                  [pscustomobject]@{
                      Hive = [Microsoft.Win32.RegistryHive]::LocalMachine
                      HiveLabel = 'HKLM'
                      View = [Microsoft.Win32.RegistryView]::Registry64
                      ViewLabel = '64'
                      Sid = ''
                      RelativePath = $uninstallRelativePath
                      Scope = 'machine'
                      Source = 'HKLM-64'
                  },
                  [pscustomobject]@{
                      Hive = [Microsoft.Win32.RegistryHive]::LocalMachine
                      HiveLabel = 'HKLM'
                      View = [Microsoft.Win32.RegistryView]::Registry32
                      ViewLabel = '32'
                      Sid = ''
                      RelativePath = $uninstallRelativePath
                      Scope = 'machine'
                      Source = 'HKLM-32'
                  }
              )

              if (-not [string]::IsNullOrWhiteSpace([string]$Identity.Sid)) {
                  $roots += [pscustomobject]@{
                      Hive = [Microsoft.Win32.RegistryHive]::Users
                      HiveLabel = 'HKU'
                      View = [Microsoft.Win32.RegistryView]::Registry64
                      ViewLabel = '64'
                      Sid = [string]$Identity.Sid
                      RelativePath = "$($Identity.Sid)\$uninstallRelativePath"
                      Scope = 'user'
                      Source = "HKU:$($Identity.Sid)-64"
                  }
                  $roots += [pscustomobject]@{
                      Hive = [Microsoft.Win32.RegistryHive]::Users
                      HiveLabel = 'HKU'
                      View = [Microsoft.Win32.RegistryView]::Registry32
                      ViewLabel = '32'
                      Sid = [string]$Identity.Sid
                      RelativePath = "$($Identity.Sid)\$uninstallRelativePath"
                      Scope = 'user'
                      Source = "HKU:$($Identity.Sid)-32"
                  }
              }

              return @($roots)
          }

          function Get-MaviProgramRows {
              param([object]$Identity)

              $rows = [System.Collections.Generic.List[object]]::new()
              foreach ($root in @(Get-MaviRegistryRoots -Identity $Identity)) {
                  $baseKey = $null
                  $uninstallKey = $null
                  try {
                      $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($root.Hive, $root.View)
                      $uninstallKey = $baseKey.OpenSubKey([string]$root.RelativePath)
                      if ($null -eq $uninstallKey) {
                          continue
                      }

                      foreach ($keyName in @($uninstallKey.GetSubKeyNames())) {
                          $programKey = $null
                          try {
                              $programKey = $uninstallKey.OpenSubKey($keyName)
                              if ($null -eq $programKey) {
                                  continue
                              }

                              $displayName = [string]$programKey.GetValue('DisplayName', '')
                              if ([string]::IsNullOrWhiteSpace($displayName)) {
                                  continue
                              }

                              $systemComponent = $programKey.GetValue('SystemComponent', 0)
                              if ($null -ne $systemComponent -and [string]$systemComponent -eq '1') {
                                  continue
                              }

                              $noRemove = $programKey.GetValue('NoRemove', 0)
                              if ($null -ne $noRemove -and [string]$noRemove -eq '1') {
                                  continue
                              }

                              $parentKey = [string]$programKey.GetValue('ParentKeyName', '')
                              if (-not [string]::IsNullOrWhiteSpace($parentKey)) {
                                  continue
                              }

                              $releaseType = [string]$programKey.GetValue('ReleaseType', '')
                              if ($releaseType -match '(?i)(Update|Hotfix|Security Update)') {
                                  continue
                              }

                              if (
                                  $keyName -match '(?i)^KB\d+$' -or
                                  $displayName -match '(?i)^(?:KB\d+|Update for |Security Update for |Hotfix for |Aktualisierung für |Sicherheitsupdate für )'
                              ) {
                                  continue
                              }

                              $quietCommand = [string]$programKey.GetValue(
                                  'QuietUninstallString',
                                  '',
                                  [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                              )
                              $uninstallCommand = [string]$programKey.GetValue(
                                  'UninstallString',
                                  '',
                                  [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                              )
                              $windowsInstaller = (
                                  [string]$programKey.GetValue('WindowsInstaller', 0) -eq '1'
                              )
                              $productCode = Get-MaviProductCode `
                                  -KeyName $keyName `
                                  -QuietCommand $quietCommand `
                                  -UninstallCommand $uninstallCommand `
                                  -WindowsInstaller $windowsInstaller
                              $isM365 = Test-MaviM365 `
                                  -DisplayName $displayName `
                                  -KeyName $keyName `
                                  -QuietCommand $quietCommand `
                                  -UninstallCommand $uninstallCommand
                              $uninstallParts = Split-MaviUninstallCommand -Command $uninstallCommand

                              $method = 'unsupported'
                              if (-not [string]::IsNullOrWhiteSpace($quietCommand) -and $null -ne (Split-MaviUninstallCommand -Command $quietCommand)) {
                                  $method = 'quiet'
                              }
                              elseif (-not [string]::IsNullOrWhiteSpace($productCode)) {
                                  $method = 'msi'
                              }
                              elseif (
                                  $isM365 -and
                                  $null -ne $uninstallParts -and
                                  $uninstallParts.File -match '(?i)(^|\\)OfficeClickToRun\.exe$' -and
                                  $uninstallParts.Arguments -match '(?i)(^|\s)productstoremove='
                              ) {
                                  $method = 'office_c2r'
                              }

                              $stableId = New-MaviProgramId `
                                  -Hive $root.HiveLabel `
                                  -View $root.ViewLabel `
                                  -Sid $root.Sid `
                                  -KeyName $keyName

                              $rows.Add([pscustomobject]@{
                                  Id = $stableId
                                  DisplayName = $displayName.Trim()
                                  DisplayVersion = ([string]$programKey.GetValue('DisplayVersion', '')).Trim()
                                  Publisher = ([string]$programKey.GetValue('Publisher', '')).Trim()
                                  Scope = [string]$root.Scope
                                  RegistryHive = [string]$root.HiveLabel
                                  RegistryView = [string]$root.ViewLabel
                                  UserSid = [string]$root.Sid
                                  UninstallKey = [string]$keyName
                                  Source = [string]$root.Source
                                  SilentMethod = $method
                                  CanUninstall = ($method -ne 'unsupported')
                                  IsM365 = [bool]$isM365
                                  QuietCommand = $quietCommand
                                  UninstallCommand = $uninstallCommand
                                  ProductCode = $productCode
                              }) | Out-Null
                          }
                          finally {
                              if ($null -ne $programKey) {
                                  $programKey.Dispose()
                              }
                          }
                      }
                  }
                  finally {
                      if ($null -ne $uninstallKey) {
                          $uninstallKey.Dispose()
                      }
                      if ($null -ne $baseKey) {
                          $baseKey.Dispose()
                      }
                  }
              }

              return @($rows | Sort-Object DisplayName, Scope, DisplayVersion, Id)
          }

          function ConvertTo-MaviPublicProgram {
              param([object]$Program)
              return [ordered]@{
                  id = [string]$Program.Id
                  display_name = [string]$Program.DisplayName
                  display_version = [string]$Program.DisplayVersion
                  publisher = [string]$Program.Publisher
                  scope = [string]$Program.Scope
                  registry_hive = [string]$Program.RegistryHive
                  registry_view = [string]$Program.RegistryView
                  user_sid = [string]$Program.UserSid
                  uninstall_key = [string]$Program.UninstallKey
                  source = [string]$Program.Source
                  silent_method = [string]$Program.SilentMethod
                  can_uninstall = [bool]$Program.CanUninstall
                  is_m365 = [bool]$Program.IsM365
              }
          }

          function Find-MaviProgramById {
              param([string]$Id, [object]$Identity)
              foreach ($program in @(Get-MaviProgramRows -Identity $Identity)) {
                  if ([string]$program.Id -eq $Id) {
                      return $program
                  }
              }
              return $null
          }

          function Get-MaviProgramVerification {
              param(
                [string]$Id,
                [string]$Scope,
                [string]$ExpectedSid,
                [object]$InitialIdentity
              )

              $verificationIdentity = $InitialIdentity
              if ($Scope -eq 'user') {
                  try {
                      $verificationIdentity = Get-MaviInteractiveUser
                  }
                  catch {
                      return [pscustomobject]@{ ContextValid = $false; Program = $null }
                  }
                  if (
                      [string]::IsNullOrWhiteSpace([string]$verificationIdentity.Sid) -or
                      [string]$verificationIdentity.Sid -ne $ExpectedSid
                  ) {
                      return [pscustomobject]@{ ContextValid = $false; Program = $null }
                  }
              }

              return [pscustomobject]@{
                  ContextValid = $true
                  Program = (Find-MaviProgramById -Id $Id -Identity $verificationIdentity)
              }
          }

          function New-MaviExecutionPlan {
              param([object]$Program)

              if ($Program.SilentMethod -eq 'msi') {
                  return [pscustomobject]@{
                      File = (Join-Path $env:SystemRoot 'System32\msiexec.exe')
                      Arguments = "/x $($Program.ProductCode) /qn /norestart"
                  }
              }

              if ($Program.SilentMethod -eq 'quiet') {
                  $parts = Split-MaviUninstallCommand -Command $Program.QuietCommand
                  if ($null -eq $parts) {
                      return $null
                  }

                  if (
                      [IO.Path]::GetFileName($parts.File) -match '(?i)^msiexec(?:\.exe)?$' -and
                      -not [string]::IsNullOrWhiteSpace([string]$Program.ProductCode)
                  ) {
                      return [pscustomobject]@{
                          File = (Join-Path $env:SystemRoot 'System32\msiexec.exe')
                          Arguments = "/x $($Program.ProductCode) /qn /norestart"
                      }
                  }
                  return $parts
              }

              if ($Program.SilentMethod -eq 'office_c2r') {
                  $parts = Split-MaviUninstallCommand -Command $Program.UninstallCommand
                  if ($null -eq $parts) {
                      return $null
                  }
                  $arguments = [string]$parts.Arguments
                  $arguments = $arguments -replace '(?i)(^|\s)displaylevel=\S+', ' '
                  $arguments = $arguments -replace '(?i)(^|\s)forceappshutdown=\S+', ' '
                  $arguments = ("$arguments displaylevel=false forceappshutdown=true" -replace '\s+', ' ').Trim()
                  return [pscustomobject]@{
                      File = [string]$parts.File
                      Arguments = $arguments
                  }
              }

              return $null
          }

          function ConvertTo-MaviExitCode {
              param([int]$ExitCode)
              if ($ExitCode -lt 0) {
                  return [long]([uint32]$ExitCode)
              }
              return [long]$ExitCode
          }

          function Invoke-MaviProcess {
              param([object]$Plan, [int]$LimitMinutes)

              $job = $null
              try {
                  $job = Start-Job -ScriptBlock {
                      param([string]$RawFile, [string]$RawArguments)
                      try {
                          $file = [Environment]::ExpandEnvironmentVariables($RawFile).Trim()
                          $arguments = [Environment]::ExpandEnvironmentVariables($RawArguments).Trim()
                          if ([string]::IsNullOrWhiteSpace($file)) {
                              throw 'Leerer Programmaufruf.'
                          }
                          $start = @{
                              FilePath = $file
                              PassThru = $true
                              Wait = $true
                              WindowStyle = 'Hidden'
                              ErrorAction = 'Stop'
                          }
                          if (-not [string]::IsNullOrWhiteSpace($arguments)) {
                              $start.ArgumentList = $arguments
                          }
                          $process = Start-Process @start
                          $exitCode = if ($process.ExitCode -lt 0) {
                              [long]([uint32]$process.ExitCode)
                          }
                          else { [long]$process.ExitCode }
                          return [pscustomobject]@{
                              Started = $true
                              Completed = $true
                              StillRunning = $false
                              ExitCode = $exitCode
                          }
                      }
                      catch {
                          return [pscustomobject]@{
                              Started = $false
                              Completed = $false
                              StillRunning = $false
                              ExitCode = $null
                          }
                      }
                  } -ArgumentList @([string]$Plan.File, [string]$Plan.Arguments)

                  $finishedJob = Wait-Job -Job $job -Timeout ([int]($LimitMinutes * 60))
                  if ($null -eq $finishedJob) {
                      return [pscustomobject]@{
                          Started = $false
                          Completed = $false
                          StillRunning = $true
                          ExitCode = $null
                      }
                  }
                  $execution = @(Receive-Job -Job $job -ErrorAction SilentlyContinue) |
                      Select-Object -Last 1
                  if ($null -eq $execution) {
                      return [pscustomobject]@{
                          Started = $false
                          Completed = $false
                          StillRunning = $false
                          ExitCode = $null
                      }
                  }
                  return $execution
              }
              catch {
                  return [pscustomobject]@{
                      Started = $false
                      Completed = $false
                      StillRunning = $false
                      ExitCode = $null
                  }
              }
              finally {
                  if ($null -ne $job) {
                      Stop-Job -Job $job -ErrorAction SilentlyContinue
                      Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                  }
              }
          }

          function Invoke-MaviProcessAsUser {
              param(
                [object]$Plan,
                [object]$Identity,
                [int]$LimitMinutes
              )

              $taskName = "MAVI-Client-Uninstall-$([guid]::NewGuid().ToString('N'))"
              $profilePath = [string](Get-ItemPropertyValue `
                  -LiteralPath "Registry::HKEY_USERS\$($Identity.Sid)\Volatile Environment" `
                  -Name 'USERPROFILE' `
                  -ErrorAction SilentlyContinue)
              if ([string]::IsNullOrWhiteSpace($profilePath)) {
                  return [pscustomobject]@{ Started = $false; Completed = $false; StillRunning = $false; ExitCode = $null }
              }

              $userTemp = Join-Path $profilePath 'AppData\Local\Temp'
              if (-not (Test-Path -LiteralPath $userTemp)) {
                  return [pscustomobject]@{ Started = $false; Completed = $false; StillRunning = $false; ExitCode = $null }
              }

              $resultPath = Join-Path $userTemp "$taskName.json"
              $payload = @{
                  File = [string]$Plan.File
                  Arguments = [string]$Plan.Arguments
                  ResultPath = $resultPath
              } | ConvertTo-Json -Compress
              $payloadMarker = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))

              $childScript = @'
          $ErrorActionPreference = 'Stop'
          $payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__MAVI_PAYLOAD__'))
          $payload = $payloadJson | ConvertFrom-Json
          $initial = @{ Finished = $false; Started = $false; StillRunning = $true; ExitCode = $null; Pid = $null }
          $initial | ConvertTo-Json -Compress | Set-Content -LiteralPath $payload.ResultPath -Encoding UTF8 -Force
          try {
              $file = [Environment]::ExpandEnvironmentVariables([string]$payload.File).Trim()
              $arguments = [Environment]::ExpandEnvironmentVariables([string]$payload.Arguments).Trim()
              if ([string]::IsNullOrWhiteSpace($file)) {
                  throw 'Leerer Programmaufruf.'
              }
              $start = @{
                  FilePath = $file
                  PassThru = $true
                  Wait = $true
                  WindowStyle = 'Hidden'
                  ErrorAction = 'Stop'
              }
              if (-not [string]::IsNullOrWhiteSpace($arguments)) {
                  $start.ArgumentList = $arguments
              }
              $process = Start-Process @start
              $exitCode = if ($process.ExitCode -lt 0) {
                  [long]([uint32]$process.ExitCode)
              }
              else { [long]$process.ExitCode }
              @{
                  Finished = $true
                  Started = $true
                  StillRunning = $false
                  ExitCode = $exitCode
                  Pid = $process.Id
              } | ConvertTo-Json -Compress | Set-Content -LiteralPath $payload.ResultPath -Encoding UTF8 -Force
          }
          catch {
              @{ Finished = $true; Started = $false; StillRunning = $false; ExitCode = $null; Pid = $null } |
                  ConvertTo-Json -Compress | Set-Content -LiteralPath $payload.ResultPath -Encoding UTF8 -Force
          }
          '@
              $childScript = $childScript.Replace('__MAVI_PAYLOAD__', $payloadMarker)
              $encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
              $taskAction = New-ScheduledTaskAction `
                  -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
                  -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encodedScript"
              $principal = New-ScheduledTaskPrincipal `
                  -UserId $Identity.Name `
                  -LogonType Interactive `
                  -RunLevel Limited
              $settings = New-ScheduledTaskSettingsSet `
                  -ExecutionTimeLimit (New-TimeSpan -Minutes ($LimitMinutes + 5)) `
                  -AllowStartIfOnBatteries `
                  -DontStopIfGoingOnBatteries

              try {
                  Register-ScheduledTask `
                      -TaskName $taskName `
                      -Action $taskAction `
                      -Principal $principal `
                      -Settings $settings `
                      -Force | Out-Null
                  Start-ScheduledTask -TaskName $taskName

                  $deadline = [DateTime]::UtcNow.AddMinutes($LimitMinutes).AddSeconds(30)
                  $last = $null
                  while ([DateTime]::UtcNow -lt $deadline) {
                      if (Test-Path -LiteralPath $resultPath) {
                          try {
                              $last = Get-Content -LiteralPath $resultPath -Raw -ErrorAction Stop | ConvertFrom-Json
                              if ([bool]$last.Finished) {
                                  break
                              }
                          }
                          catch {}
                      }
                      Start-Sleep -Seconds 2
                  }

                  if ($null -eq $last) {
                      return [pscustomobject]@{ Started = $false; Completed = $false; StillRunning = $true; ExitCode = $null }
                  }
                  return [pscustomobject]@{
                      Started = [bool]$last.Started
                      Completed = ([bool]$last.Finished -and -not [bool]$last.StillRunning)
                      StillRunning = [bool]$last.StillRunning
                      ExitCode = $last.ExitCode
                  }
              }
              catch {
                  return [pscustomobject]@{ Started = $false; Completed = $false; StillRunning = $false; ExitCode = $null }
              }
              finally {
                  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                  Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
              }
          }

          function New-MaviUninstallResult {
              param([string]$Id)
              return [ordered]@{
                  schema = 1
                  action = 'uninstall'
                  id = $Id
                  name = ''
                  status = 'FEHLER'
                  method = 'unsupported'
                  scope = ''
                  execution_user = ''
                  exit_code = $null
                  reboot_required = $false
                  still_running = $false
                  stop_series = $false
                  message = ''
              }
          }

          $output = $null
          try {
              $identity = Get-MaviInteractiveUser

              if ($Action -eq 'inventory') {
                  $publicPrograms = @(
                      foreach ($program in @(Get-MaviProgramRows -Identity $identity)) {
                          ConvertTo-MaviPublicProgram -Program $program
                      }
                  )
                  $output = [ordered]@{
                      schema = 1
                      action = 'inventory'
                      success = $true
                      interactive_user = [string]$identity.Name
                      interactive_user_sid = [string]$identity.Sid
                      programs = @($publicPrograms)
                      message = ''
                  }
              }
              else {
                  $output = New-MaviUninstallResult -Id $ProgramId
                  if ([string]::IsNullOrWhiteSpace($ProgramId)) {
                      $output.message = 'Keine stabile Programm-ID angegeben.'
                  }
                  elseif ($TimeoutMinutes -lt 1) {
                      $output.message = 'Das Deinstallations-Zeitlimit ist ungültig.'
                  }
                  elseif (
                      [string]::IsNullOrWhiteSpace($ExpectedDisplayName) -or
                      $ExpectedScope -notin @('machine', 'user') -or
                      ($ExpectedScope -eq 'user' -and [string]::IsNullOrWhiteSpace($ExpectedUserSid))
                  ) {
                      $output.message = 'Die erwarteten Programmdaten sind unvollständig.'
                  }
                  elseif (
                      $ExpectedScope -eq 'user' -and
                      (
                          [string]::IsNullOrWhiteSpace([string]$identity.Sid) -or
                          [string]$identity.Sid -ne $ExpectedUserSid
                      )
                  ) {
                      $output.message = 'Der bei der Auswahl angemeldete Benutzer ist nicht mehr interaktiv angemeldet.'
                      $output.stop_series = $true
                  }
                  else {
                      $program = Find-MaviProgramById -Id $ProgramId -Identity $identity
                      if ($null -eq $program) {
                          $output.status = 'BEREITS ENTFERNT'
                          $output.message = 'Der Registry-Eintrag ist bereits nicht mehr vorhanden.'
                      }
                      elseif (
                          [string]$program.DisplayName -cne $ExpectedDisplayName -or
                          [string]$program.Scope -ne $ExpectedScope -or
                          (
                              $ExpectedScope -eq 'user' -and
                              [string]$program.UserSid -ne $ExpectedUserSid
                          )
                      ) {
                          $output.message = 'Der Registry-Eintrag wurde seit der Auswahl verändert; es wurde nichts gestartet.'
                      }
                      else {
                          $output.name = [string]$program.DisplayName
                          $output.method = [string]$program.SilentMethod
                          $output.scope = [string]$program.Scope
                          $output.execution_user = if ($program.Scope -eq 'user') { [string]$identity.Name } else { 'SYSTEM' }

                          if ($program.SilentMethod -eq 'unsupported') {
                              $output.status = 'ÜBERSPRUNGEN'
                              $output.message = 'Kein unterstützter Silent-Uninstaller registriert.'
                          }
                          elseif (
                              $program.Scope -eq 'user' -and
                              (
                                  [string]::IsNullOrWhiteSpace([string]$identity.Sid) -or
                                  [string]$identity.Sid -ne [string]$program.UserSid
                              )
                          ) {
                              $output.status = 'FEHLER'
                              $output.message = 'Der zugehörige Benutzer ist nicht mehr interaktiv angemeldet.'
                          }
                          else {
                              $plan = New-MaviExecutionPlan -Program $program
                              if ($null -eq $plan) {
                                  $output.status = 'ÜBERSPRUNGEN'
                                  $output.message = 'Der Silent-Uninstall-Aufruf konnte nicht eindeutig aufgelöst werden.'
                              }
                              else {
                                  $execution = if ($program.Scope -eq 'user') {
                                      Invoke-MaviProcessAsUser -Plan $plan -Identity $identity -LimitMinutes $TimeoutMinutes
                                  }
                                  else {
                                      Invoke-MaviProcess -Plan $plan -LimitMinutes $TimeoutMinutes
                                  }

                                  $output.exit_code = $execution.ExitCode
                                  $output.still_running = [bool]$execution.StillRunning
                                  if ($null -ne $execution.ExitCode -and [long]$execution.ExitCode -in @(1641, 3010)) {
                                      $output.reboot_required = $true
                                  }

                                  if (
                                      $execution.StillRunning -or
                                      ($execution.Started -and -not $execution.Completed)
                                  ) {
                                      $output.status = 'FEHLER'
                                      $output.stop_series = $true
                                      $output.message = "Zeitlimit von $TimeoutMinutes Minute(n) erreicht; die Serie wurde angehalten."
                                  }
                                  elseif (-not $execution.Started) {
                                      $output.status = 'FEHLER'
                                      $output.message = 'Der Silent-Uninstaller konnte nicht gestartet werden.'
                                  }
                                  elseif ($null -ne $execution.ExitCode -and [long]$execution.ExitCode -eq 1618) {
                                      $output.status = 'FEHLER'
                                      $output.stop_series = $true
                                      $output.message = 'Windows meldet eine bereits laufende Installation; die Serie wurde angehalten.'
                                  }
                                  else {
                                      $verifyDeadline = [DateTime]::UtcNow.AddSeconds(120)
                                      $verification = Get-MaviProgramVerification `
                                          -Id $ProgramId `
                                          -Scope $ExpectedScope `
                                          -ExpectedSid $ExpectedUserSid `
                                          -InitialIdentity $identity
                                      while (
                                          $verification.ContextValid -and
                                          $null -ne $verification.Program -and
                                          [DateTime]::UtcNow -lt $verifyDeadline
                                      ) {
                                          Start-Sleep -Seconds 5
                                          $verification = Get-MaviProgramVerification `
                                              -Id $ProgramId `
                                              -Scope $ExpectedScope `
                                              -ExpectedSid $ExpectedUserSid `
                                              -InitialIdentity $identity
                                      }

                                      if (-not $verification.ContextValid) {
                                          $output.status = 'FEHLER'
                                          $output.stop_series = $true
                                          $output.message = 'Der angemeldete Benutzer wechselte während der Nachprüfung; die Serie wurde angehalten.'
                                      }
                                      elseif ($null -eq $verification.Program) {
                                          $output.status = 'ENTFERNT'
                                          $output.message = if ($output.reboot_required) {
                                              'Deinstalliert; Windows meldet einen erforderlichen Neustart.'
                                          }
                                          else {
                                              'Deinstallation abgeschlossen und Registry-Eintrag entfernt.'
                                          }
                                      }
                                      else {
                                          $output.status = 'FEHLER'
                                          $output.message = 'Der Uninstaller wurde beendet, der Registry-Eintrag ist aber weiterhin vorhanden.'
                                      }
                                  }
                              }
                          }
                      }
                  }
              }
          }
          catch {
              if ($Action -eq 'inventory') {
                  $output = [ordered]@{
                      schema = 1
                      action = 'inventory'
                      success = $false
                      interactive_user = ''
                      interactive_user_sid = ''
                      programs = @()
                      message = 'Das klassische Programminventar konnte nicht gelesen werden.'
                  }
              }
              else {
                  $output = New-MaviUninstallResult -Id $ProgramId
                  $output.message = 'Die Deinstallation wurde unerwartet unterbrochen.'
              }
          }
          finally {
              $json = $output | ConvertTo-Json -Compress -Depth 8
              $marker = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
              $Ansible.Result = @{ Marker = $marker }
              $Ansible.Changed = ($Action -eq 'uninstall' -and $output.status -eq 'ENTFERNT')
          }
        parameters:
          Action: "{{ client_uninstall_action | default('inventory') }}"
          ProgramId: "{{ client_uninstall_program_id | default('') }}"
          ExpectedDisplayName: "{{ client_uninstall_expected_display_name | default('') }}"
          ExpectedScope: "{{ client_uninstall_expected_scope | default('') }}"
          ExpectedUserSid: "{{ client_uninstall_expected_user_sid | default('') }}"
          TimeoutMinutes: "{{ client_uninstall_timeout_minutes | default(45) | int }}"
      register: mavi_client_uninstall
      become: true
      become_method: runas
      become_user: SYSTEM
      failed_when: false
      no_log: true

    - name: Strukturiertes Client-Programm-Ergebnis ausgeben
      ansible.builtin.debug:
        msg: >-
          MAVI_CLIENT_UNINSTALL_B64={{
            mavi_client_uninstall.result.Marker | default('')
          }}
"""
