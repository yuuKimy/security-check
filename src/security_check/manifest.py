from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from security_check.paths import Locations, write_private_text


@dataclass(frozen=True)
class Project:
    name: str
    path: Path


class ManifestError(ValueError):
    pass


def is_too_broad(path: Path, home: Path) -> bool:
    resolved = path.expanduser().resolve()
    root = Path(resolved.anchor)
    return resolved == root or resolved == home.expanduser().resolve()


def load_manifest(path: Path) -> list[Project]:
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError("マニフェストを解釈できない") from error
    projects = raw.get("projects") if isinstance(raw, dict) else None
    if not isinstance(projects, list):
        raise ManifestError("マニフェストを解釈できない")
    loaded: list[Project] = []
    for item in projects:
        if not isinstance(item, dict):
            raise ManifestError("マニフェストを解釈できない")
        name = item.get("name")
        project_path = item.get("path")
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(project_path, str)
            or not project_path.strip()
        ):
            raise ManifestError("マニフェストを解釈できない")
        loaded.append(Project(name=name.strip(), path=Path(project_path)))
    return loaded


def save_manifest(path: Path, projects: list[Project]) -> None:
    payload = {"projects": [{"name": project.name, "path": str(project.path)} for project in projects]}
    write_private_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def add_project(locations: Locations, path: Path, name: str | None, home: Path) -> Project:
    if not path.expanduser().is_dir():
        raise ManifestError("ディレクトリではありません")
    resolved = path.expanduser().resolve()
    if is_too_broad(resolved, home):
        raise ManifestError("ホームディレクトリ全体とルートは登録できません")
    chosen = name.strip() if name else resolved.name
    if not chosen:
        raise ManifestError("プロジェクト名が空です")
    projects = load_manifest(locations.manifest_path)
    if any(item.path.expanduser().resolve() == resolved for item in projects):
        raise ManifestError("同じパスは登録済みです")
    if any(item.name == chosen for item in projects):
        raise ManifestError("同じ名前は登録済みです。--name で別の名前を指定してください")
    project = Project(name=chosen, path=resolved)
    projects.append(project)
    save_manifest(locations.manifest_path, projects)
    return project


def remove_project(locations: Locations, name: str) -> None:
    projects = load_manifest(locations.manifest_path)
    kept = [project for project in projects if project.name != name]
    if len(kept) == len(projects):
        raise ManifestError("その名前のプロジェクトはありません")
    save_manifest(locations.manifest_path, kept)
