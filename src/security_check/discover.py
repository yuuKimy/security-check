from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRECTORIES = {"node_modules", ".venv", "venv", ".git", "dist", "build", "vendor", "target"}
LOCKFILES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "go.mod",
    "Cargo.lock",
    "Gemfile.lock",
}
MAX_DEPTH = 6
MAX_LOCKFILES = 50


@dataclass
class Discovery:
    lockfiles: list[Path] = field(default_factory=list)
    unpinned: list[Path] = field(default_factory=list)
    too_many: bool = False


def classify_requirements(text: str) -> str:
    saw_pin = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement", "-c ", "--constraint", "-e ", "--editable")):
            return "unpinned"
        line = line.split(";", 1)[0].strip()
        if "==" in line and not any(operator in line for operator in (">=", "<=", "~=", "!=", ">", "<")):
            saw_pin = True
            continue
        return "unpinned"
    return "pinned" if saw_pin else "empty"


def discover(root: Path) -> Discovery:
    resolved_root = root.resolve()
    found = Discovery()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        try:
            relative_dir = current.resolve().relative_to(resolved_root)
        except ValueError:
            dirnames[:] = []
            continue
        depth = 0 if relative_dir == Path(".") else len(relative_dir.parts)
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRECTORIES]
        if depth >= MAX_DEPTH:
            dirnames[:] = []
        if depth > MAX_DEPTH:
            continue
        for name in filenames:
            candidate = current / name
            try:
                if not candidate.resolve().is_relative_to(resolved_root):
                    continue
            except OSError:
                continue
            if name in LOCKFILES:
                found.lockfiles.append(candidate)
            elif name == "requirements.txt":
                try:
                    kind = classify_requirements(candidate.read_text(encoding="utf-8"))
                except OSError:
                    found.unpinned.append(candidate)
                    continue
                if kind == "pinned":
                    found.lockfiles.append(candidate)
                elif kind == "unpinned":
                    found.unpinned.append(candidate)
    found.lockfiles.sort()
    found.unpinned.sort()
    if len(found.lockfiles) > MAX_LOCKFILES:
        found.too_many = True
        found.lockfiles = []
    return found
