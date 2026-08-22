# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""
Mavi Provisioner
================

TUI-first provisioning for Windows endpoints with Ansible.

v0.9.10 safely removes a selected Windows PC from the Ansible inventory via
the TUI or ``host remove``. It reloads and validates the inventory after the
confirmation prompt so unrelated concurrent changes are preserved, and it
aborts if the selected entry changed. The endpoint and its remote configuration
remain untouched.

v0.9.9 binds the standalone connectivity check to the same private,
pre-validated Kerberos session as installation and client actions. ``win_ping``
uses the detected Ansible Python runtime and a short-lived ticket cache while
named inventory credentials are overlaid with empty values. A temporary
single-host inventory prevents pattern-like aliases from expanding the target
set. The temporary inventory, Vault file and Kerberos cache are always removed
after the ping. Ambiguous remote-result markers and incomplete verified v2
bootstrap instance state now fail closed before cleanup state is committed.

v0.9.8 adds inventory and live remote-management audits for individual hosts
or the complete Windows inventory. The live check is strictly read-only and
classifies WinRM, OpenSSH, Mavi certificates and the documented reset state
through the host's current management transport.

v0.9.7 adds a Windows-client workflow for managing Fast Startup and separate
AC/DC monitor timeouts, plus searchable multi-selection and sequential silent
uninstallation of classic programs. Every action and reachability check stays
inside one bound Ansible session with the same private Kerberos ticket cache.

v0.9.6 binds the complete software installation run to one Ansible session.
The main playbook, installed precheck, live probes, post-install checks and
reachability checks now use the same validated inventory, Ansible entry point,
Ansible Python runtime and private Kerberos ticket cache.

v0.9.5 prevents the 180-second timeout during the WinRM reset. Listener
removal is now verified while WinRM is still running. After the service has
been stopped and disabled, Mavi confirms the final state only through the
local service manager and the registry start value, without contacting the
already disabled WSMan or CIM channel again.

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
Store packages, Windows-client optimization and program cleanup, printer
deployment, OpenSSH bootstrap, and an optional WinRM HTTPS/Kerberos endpoint.
Secrets belong in Ansible Vault or another secret provider, never in a profile
or repository.
"""

from .settings import VERSION
from .cli import main

__all__ = ("VERSION", "main")
