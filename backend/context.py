"""
Assembles code context around a Semgrep finding for the AI prompt.

assemble_context(repo_path, finding) -> {finding, files: {path: contents}}
  - always includes the flagged file
  - follows import/require statements (regex, no AST) to pull in related files
  - also scans routes/, middleware/, auth/, db/, models/ dirs for relevant files
  - caps at 10 files total so prompt stays within model context limits
  - supports JS/TS (require, import) and Python (import, from ... import)
"""
import os
import re

_IMPORT_RE: dict[str, re.Pattern] = {
    ".py": re.compile(r"^\s*(?:from\s+([\w./]+)\s+import|import\s+([\w./]+))", re.MULTILINE),
    ".js": re.compile(r"""(?:require|import)\s*\(?['"](\.[^'"]+)['"]\)?"""),
    ".ts": re.compile(r"""(?:require|import)\s*\(?['"](\.[^'"]+)['"]\)?"""),
    ".jsx": re.compile(r"""(?:require|import)\s*\(?['"](\.[^'"]+)['"]\)?"""),
    ".tsx": re.compile(r"""(?:require|import)\s*\(?['"](\.[^'"]+)['"]\)?"""),
}

_CONTEXT_DIRS = ["routes", "middleware", "auth", "db", "models"]
_MAX_FILES = 10


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _resolve_import(base_dir: str, imp: str, src_ext: str) -> str | None:
    candidates = [imp, imp + src_ext, imp + ".py", imp + ".js", imp + ".ts", imp + ".jsx", imp + ".tsx"]
    for c in candidates:
        full = os.path.normpath(os.path.join(base_dir, c))
        if os.path.isfile(full):
            return full
    return None


def assemble_context(repo_path: str, finding: dict) -> dict:
    rel_path = finding.get("path", "")
    flagged_abs = os.path.join(repo_path, rel_path)

    files: dict[str, str] = {}

    content = _read(flagged_abs)
    if content is not None:
        files[rel_path] = content

    ext = os.path.splitext(rel_path)[1]
    pattern = _IMPORT_RE.get(ext)
    if pattern and content:
        base_dir = os.path.dirname(flagged_abs)
        for match in pattern.finditer(content):
            imp = next((g for g in match.groups() if g), None)
            if not imp:
                continue
            imp_path = imp.replace(".", os.sep) if ext == ".py" else imp
            resolved = _resolve_import(base_dir, imp_path, ext)
            if resolved and os.path.exists(resolved):
                rel = os.path.relpath(resolved, repo_path)
                if rel not in files and len(files) < _MAX_FILES:
                    c = _read(resolved)
                    if c is not None:
                        files[rel] = c

    for dirname in _CONTEXT_DIRS:
        dirpath = os.path.join(repo_path, dirname)
        if not os.path.isdir(dirpath) or len(files) >= _MAX_FILES:
            continue
        for fname in sorted(os.listdir(dirpath))[:3]:
            fpath = os.path.join(dirpath, fname)
            if os.path.isfile(fpath) and len(files) < _MAX_FILES:
                rel = os.path.relpath(fpath, repo_path)
                if rel not in files:
                    c = _read(fpath)
                    if c is not None:
                        files[rel] = c

    return {"finding": finding, "files": files}
