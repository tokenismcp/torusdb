# SPDX-License-Identifier: Apache-2.0
"""Dependency-free base error shared by the custody tools and the vault."""


class CustodyError(Exception):
    """Base class for threshold-custody / key-material failures."""
