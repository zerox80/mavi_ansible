#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mavi Provisioner contributors
"""Kompatibler Programmeinstieg für Mavi Provisioner."""

from windows_provisioner import VERSION, main

__all__ = ("VERSION", "main")


if __name__ == "__main__":
    main()
