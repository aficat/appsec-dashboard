from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    ".idea",
    ".vscode",
}


SKILL_TO_EXTENSIONS = {
    # C/C++ + headers + build scripts commonly relevant for native security review
    "c-python-security": {
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cc",
        ".hh",
        ".inc",
        ".py",
        ".sh",
        ".mk",
        ".m4",
        # Native projects often embed web/admin UIs; keep basic coverage.
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
    },
    # Generic OWASP can apply anywhere; include common web/server config files
    "owasp-top10": {
        ".py",
        ".sh",
        ".conf",
        ".ini",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".xml",
        # Web app sources where OWASP issues live (XSS, SSRF, auth, etc).
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".html",
        ".css",
        ".md",
    },
    # reporting skill doesn't change scan scope
    "security-report": set(),
}


@dataclass(frozen=True)
class ScanResult:
    repo_path: str
    skills: list[str]
    included_extensions: list[str]
    ignored_extensions: list[str]
    extension_counts: dict[str, int]
    included_counts: dict[str, int]
    ignored_counts: dict[str, int]
    top_included_files: list[str]
    top_ignored_files: list[str]


def _read_skill_names(skills_dir: Path) -> list[str]:
    if not skills_dir.is_dir():
        return []
    out: list[str] = []
    for child in skills_dir.iterdir():
        if child.is_dir() and (child / "SKILL.md").exists():
            out.append(child.name)
    return sorted(out)


def _infer_included_extensions(skill_names: Iterable[str]) -> set[str]:
    exts: set[str] = set()
    for name in skill_names:
        exts |= SKILL_TO_EXTENSIONS.get(name, set())
    # If we can't infer anything, default to "everything" by using empty set sentinel later.
    return exts


def _iter_repo_files(repo: Path, ignore_dirs: set[str]) -> Iterable[Path]:
    for root, dirs, files in os.walk(repo):
        # mutate dirs in-place to prune traversal
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            yield Path(root) / f


def _file_ext(p: Path) -> str:
    # Treat dotfiles without suffix as "(none)".
    if p.name.startswith(".") and p.suffix == "":
        return "(dotfile)"
    return p.suffix.lower() if p.suffix else "(none)"


def scan(repo_path: str, skills_dir: str, ignore_dirs: set[str] | None = None, top_n: int = 12) -> ScanResult:
    repo = Path(repo_path).resolve()
    skills = _read_skill_names(Path(skills_dir).resolve())
    ignore = set(DEFAULT_IGNORE_DIRS) if ignore_dirs is None else set(ignore_dirs)

    included_exts = _infer_included_extensions(skills)
    ext_counter: Counter[str] = Counter()
    included_files: dict[str, list[str]] = defaultdict(list)
    ignored_files: dict[str, list[str]] = defaultdict(list)

    for p in _iter_repo_files(repo, ignore):
        ext = _file_ext(p)
        ext_counter[ext] += 1

        # If included_exts is empty, interpret as "no restriction".
        if not included_exts or ext in included_exts:
            if len(included_files[ext]) < top_n:
                included_files[ext].append(str(p.relative_to(repo)))
        else:
            if len(ignored_files[ext]) < top_n:
                ignored_files[ext].append(str(p.relative_to(repo)))

    included_counts: dict[str, int] = {}
    ignored_counts: dict[str, int] = {}

    for ext, count in ext_counter.items():
        if not included_exts or ext in included_exts:
            included_counts[ext] = count
        else:
            ignored_counts[ext] = count

    # flatten top files (sorted by count desc)
    top_included: list[str] = []
    for ext, _ in sorted(included_counts.items(), key=lambda kv: kv[1], reverse=True):
        top_included.extend(included_files.get(ext, []))

    top_ignored: list[str] = []
    for ext, _ in sorted(ignored_counts.items(), key=lambda kv: kv[1], reverse=True):
        top_ignored.extend(ignored_files.get(ext, []))

    included_extensions = sorted(included_counts.keys())
    ignored_extensions = sorted(ignored_counts.keys())

    return ScanResult(
        repo_path=str(repo),
        skills=skills,
        included_extensions=included_extensions,
        ignored_extensions=ignored_extensions,
        extension_counts=dict(ext_counter),
        included_counts=dict(sorted(included_counts.items(), key=lambda kv: kv[1], reverse=True)),
        ignored_counts=dict(sorted(ignored_counts.items(), key=lambda kv: kv[1], reverse=True)),
        top_included_files=top_included[:top_n],
        top_ignored_files=top_ignored[:top_n],
    )


def _to_markdown(r: ScanResult) -> str:
    md: list[str] = []
    md.append("# Filetype Scan (skills-informed)")
    md.append("")
    md.append(f"- **Repo**: `{r.repo_path}`")
    md.append(f"- **Skills detected**: {', '.join(r.skills) if r.skills else '(none)'}")
    md.append("")

    if not r.included_extensions:
        md.append("## Included file types")
        md.append("")
        md.append("_No filetype allowlist inferred from skills (treating as “all file types”)._")
    else:
        md.append("## Included file types (by extension)")
        md.append("")
        for ext, count in r.included_counts.items():
            md.append(f"- `{ext}`: {count}")

    md.append("")
    md.append("## Ignored file types (by extension)")
    md.append("")
    if not r.ignored_extensions:
        md.append("_None (based on current inferred allowlist)._")
    else:
        for ext, count in r.ignored_counts.items():
            md.append(f"- `{ext}`: {count}")

    md.append("")
    md.append("## Example included files")
    md.append("")
    if r.top_included_files:
        for p in r.top_included_files:
            md.append(f"- `{p}`")
    else:
        md.append("_None recorded._")

    md.append("")
    md.append("## Example ignored files")
    md.append("")
    if r.top_ignored_files:
        for p in r.top_ignored_files:
            md.append(f"- `{p}`")
    else:
        md.append("_None recorded._")

    md.append("")
    return "\n".join(md)


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory repo filetypes and infer include/ignore from skills.")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1] / "repo"), help="Path to cloned repo")
    parser.add_argument(
        "--skills",
        default=str(Path(__file__).resolve().parents[1] / "skills"),
        help="Path to skills directory",
    )
    parser.add_argument("--format", choices=["md", "json"], default="md")
    args = parser.parse_args()

    res = scan(repo_path=args.repo, skills_dir=args.skills)
    if args.format == "json":
        print(json.dumps(res.__dict__, indent=2))
    else:
        print(_to_markdown(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

