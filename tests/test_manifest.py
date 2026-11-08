import json
from pathlib import Path

import pytest

from security_check.manifest import ManifestError, add_project, is_too_broad, remove_project
from security_check.paths import Locations


def test_rejects_home_and_root(tmp_path: Path) -> None:
    assert is_too_broad(tmp_path, tmp_path) is True
    assert is_too_broad(Path("/"), tmp_path) is True
    child = tmp_path / "app"
    child.mkdir()
    assert is_too_broad(child, tmp_path) is False


def test_add_and_remove(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    project = home / "app"
    project.mkdir()
    locations = Locations(home / "SecurityCheck", home / "support", home / "log" / "security-check.log")

    added = add_project(locations, project, None, home)

    assert added.name == "app"
    with pytest.raises(ManifestError):
        add_project(locations, project, None, home)
    remove_project(locations, "app")
    assert json.loads(locations.manifest_path.read_text(encoding="utf-8"))["projects"] == []
