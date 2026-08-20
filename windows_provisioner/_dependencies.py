# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
# Zentrale Laufzeitabhängigkeiten für alle Provisioner-Module.
"""Standardbibliothek und optionale Python-Abhängigkeiten."""

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

__all__ = (
    "Any",
    "ET",
    "Path",
    "argparse",
    "base64",
    "binascii",
    "csv",
    "getpass",
    "hashlib",
    "html",
    "ipaddress",
    "json",
    "os",
    "pefile",
    "queue",
    "re",
    "secrets",
    "shutil",
    "signal",
    "socket",
    "ssl",
    "struct",
    "subprocess",
    "sys",
    "tempfile",
    "threading",
    "time",
    "urllib",
    "yaml",
)
