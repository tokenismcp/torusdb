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
        "core pyproject": _toml_version("core/pyproject.toml"),
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


def test_open_source_tree_has_no_proprietary_dependency():
    """The whole open tree must run without ec-fhe-engine / ec-fhe-query."""
    bad = re.compile(r"^\s*(from|import)\s+(ecfhe|ecfhe_query)\b", re.M)
    skip = {"test_versions.py", "test_custody_e2e.py"}   # guarded optional imports
    for p in ROOT.rglob("*.py"):
        if (set(p.parts) & {"node_modules", "target", "build", ".git", ".venv"}) or p.name in skip:
            continue
        assert not bad.search(p.read_text()), f"{p} imports the proprietary engine"
    for toml in ("drivers/python", "server", "core", "parser"):
        assert "ec-fhe" not in (ROOT / toml / "pyproject.toml").read_text()


def test_server_wheel_ships_every_top_level_module():
    """A module imported by nokey_server.py but missing from py-modules only fails
    after `pip install` — catch it here."""
    import re
    src = (ROOT / "server/nokey_server.py").read_text()
    listed = re.search(r"py-modules\s*=\s*\[([^\]]*)\]", (ROOT / "server/pyproject.toml").read_text()).group(1)
    listed = set(re.findall(r'"([^"]+)"', listed))
    local = {p.stem for p in (ROOT / "server").glob("*.py")}
    imported = set(re.findall(r"^(?:import|from)\s+(\w+)", src, re.M))
    assert (imported & local) - {"nokey_server"} <= listed, (imported & local) - listed
