from pathlib import Path

from security_check.discover import classify_requirements, discover


def test_classify_requirements_pinned_and_range() -> None:
    assert classify_requirements("requests==2.32.0\n") == "pinned"
    assert classify_requirements('pkg==1.0; python_version>="3"\n') == "pinned"
    assert classify_requirements("requests>=2\n") == "unpinned"
    assert classify_requirements("# nothing\n") == "empty"


def test_discover_skips_vendor_directories_and_deep_files(tmp_path: Path) -> None:
    keep = tmp_path / "uv.lock"
    keep.write_text("lock", encoding="utf-8")
    nested = tmp_path / "node_modules" / "pkg" / "uv.lock"
    nested.parent.mkdir(parents=True)
    nested.write_text("lock", encoding="utf-8")
    deep = tmp_path.joinpath("a", "b", "c", "d", "e", "f", "g")
    deep.mkdir(parents=True)
    (deep / "Cargo.lock").write_text("lock", encoding="utf-8")
    pinned = tmp_path / "requirements.txt"
    pinned.write_text("requests==2.32.0\n", encoding="utf-8")
    loose = tmp_path / "sub" / "requirements.txt"
    loose.parent.mkdir()
    loose.write_text("requests>=1\n", encoding="utf-8")

    found = discover(tmp_path)

    assert keep in found.lockfiles
    assert pinned in found.lockfiles
    assert nested not in found.lockfiles
    assert deep / "Cargo.lock" not in found.lockfiles
    assert loose in found.unpinned
    assert found.too_many is False


def test_discover_stops_at_fifty_lockfiles(tmp_path: Path) -> None:
    for index in range(51):
        directory = tmp_path / f"pkg{index}"
        directory.mkdir()
        (directory / "uv.lock").write_text("lock", encoding="utf-8")

    found = discover(tmp_path)

    assert found.too_many is True
    assert found.lockfiles == []
