# SPDX-License-Identifier: Apache-2.0
"""All open packages share one version; docs name the current dialect/wire."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _toml_version(path):
    m = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / path).read_text(), re.M)
    return m.group(1)


def test_open_packages_share_one_version():
    import torussql
    import nokey_server
    versions = {
        "driver pyproject": _toml_version("drivers/python/pyproject.toml"),
        "driver __version__": torussql.__version__,
        "parser pyproject": _toml_version("parser/pyproject.toml"),
        "server pyproject": _toml_version("server/pyproject.toml"),
        "server banner": nokey_server.SERVER_VERSION,
        "npm": json.loads((ROOT / "drivers/typescript/package.json").read_text())["version"],
        "cargo": _toml_version("drivers/rust/Cargo.toml"),
    }
    assert len(set(versions.values())) == 1, versions


def test_changelog_and_spec_describe_current_release():
    ver = _toml_version("drivers/python/pyproject.toml")
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert re.search(rf"^## \[{re.escape(ver)}\]", changelog, re.M), "CHANGELOG lacks current version"
    assert (ROOT / "spec/TorusSQL-Spec-v0.5.md").exists()
    assert "protocol 2" in (ROOT / "docs/versioning.md").read_text().lower()


def test_server_pins_matching_driver():
    ver = _toml_version("server/pyproject.toml")
    assert f'"torussql=={ver}"' in (ROOT / "server/pyproject.toml").read_text()
