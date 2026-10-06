"""Surface detection patterns for the deterministic repo profiler."""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from shift_left.config import resolve_repo_root
from shift_left.profiler.path_exclusions import is_excluded_test_path

_EXTENSION_LANGUAGES: dict[str, str] = {
    ".py": "Python",
    ".pyw": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".java": "Java",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".php": "PHP",
    ".sql": "SQL",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
}

_MANIFEST_FILES = (
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Gemfile",
    "pom.xml",
    "Cargo.toml",
)

_MANIFEST_SURFACE_HINTS: dict[str, list[str]] = {
    "sqlalchemy": ["database_driver", "orm"],
    "psycopg": ["database_driver"],
    "psycopg2": ["database_driver"],
    "mysql-connector": ["database_driver"],
    "pymysql": ["database_driver"],
    "sqlite3": ["database_driver"],
    "django": ["web_framework", "orm"],
    "flask": ["web_framework"],
    "fastapi": ["web_framework"],
    "starlette": ["web_framework"],
    "express": ["web_framework"],
    "rails": ["web_framework"],
    "jinja2": ["template_engine"],
    "mako": ["template_engine"],
    "pickle": ["serialization"],
    "yaml.load": ["serialization"],
    "pyyaml": ["serialization"],
    "requests": ["http_client"],
    "httpx": ["http_client"],
    "urllib3": ["http_client"],
    "aiohttp": ["http_client"],
    "cryptography": ["crypto_api"],
    "pycrypto": ["crypto_api"],
    "bcrypt": ["crypto_api"],
    "passlib": ["crypto_api"],
    "jose": ["crypto_api"],
    "subprocess": ["subprocess_shell"],
    "os.system": ["subprocess_shell"],
    "shell=True": ["subprocess_shell"],
}

_IMPORT_MODULE_SURFACES: dict[str, str] = {
    "sqlite3": "database_driver",
    "psycopg2": "database_driver",
    "psycopg": "database_driver",
    "pymysql": "database_driver",
    "mysql.connector": "database_driver",
    "sqlalchemy": "orm",
    "flask": "web_framework",
    "django": "web_framework",
    "fastapi": "web_framework",
    "starlette": "web_framework",
    "jinja2": "template_engine",
    "mako": "template_engine",
    "pickle": "serialization",
    "yaml": "serialization",
    "marshal": "serialization",
    "subprocess": "subprocess_shell",
    "requests": "http_client",
    "httpx": "http_client",
    "aiohttp": "http_client",
    "urllib.request": "http_client",
    "cryptography": "crypto_api",
    "Crypto": "crypto_api",
    "hashlib": "crypto_api",
    "hmac": "crypto_api",
    "pathlib": "file_path_api",
    "shutil": "file_path_api",
    "os": "file_path_api",
}

_AUTHZ_IDENT_RE = re.compile(
    r"^(permission|authorize|authentication|is_authenticated|login_required)$",
    re.IGNORECASE,
)

_IMPORT_SURFACE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("database_driver", re.compile(r"\b(import|from)\s+(sqlite3|psycopg2|psycopg|pymysql|mysql\.connector)\b")),
    ("orm", re.compile(r"\b(import|from)\s+sqlalchemy\b")),
    ("web_framework", re.compile(r"\b(import|from)\s+(flask|django|fastapi|starlette)\b")),
    ("template_engine", re.compile(r"\b(import|from)\s+(jinja2|mako)\b")),
    ("serialization", re.compile(r"\b(import|from)\s+(pickle|yaml|marshal)\b")),
    ("subprocess_shell", re.compile(r"\b(import|from)\s+subprocess\b|os\.system\s*\(")),
    ("http_client", re.compile(r"\b(import|from)\s+(requests|httpx|aiohttp|urllib\.request)\b")),
    ("crypto_api", re.compile(r"\b(import|from)\s+(cryptography|Crypto|hashlib|hmac)\b")),
    ("file_path_api", re.compile(r"\b(open\s*\(|pathlib\.|os\.path\.|shutil\.)")),
]

_CALLSITE_SURFACE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "raw_sql_callsite",
        re.compile(
            r"""(?x)
            (?:\.execute\s*\(\s*f["']|
             \.execute\s*\(\s*["'][^"']*%|
             \.execute\s*\(\s*["'][^"']*\{|
             cursor\.execute\s*\([^)]*\+|
             raw\s*\(\s*f["'])
            """
        ),
    ),
    ("subprocess_shell", re.compile(r"subprocess\.(run|Popen|call)\s*\([^)]*shell\s*=\s*True")),
    ("serialization", re.compile(r"\b(pickle\.loads|yaml\.load|marshal\.loads)\s*\(")),
    ("http_client", re.compile(r"\b(requests\.(get|post|put|delete)|httpx\.(get|post)|urlopen)\s*\(")),
    ("file_path_api", re.compile(r"\b(os\.path\.join|Path\s*\([^)]*\+)\s*\(")),
]

_SQL_KEYWORD_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b", re.IGNORECASE)
_EXECUTE_METHODS = frozenset({"execute", "executemany", "raw"})
_PLACEHOLDER_RE = re.compile(r"(?:\?|%\s*\(|%\s*[a-zA-Z_])")

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "dist",
        "build",
    }
)


@dataclass(frozen=True)
class EvidenceItem:
    surface: str
    file: str
    line: int | None
    detail: str


@dataclass(frozen=True)
class ManifestEvidence:
    manifest: str
    entry: str
    surfaces: tuple[str, ...]


def surface_to_cwe_path() -> Path:
    return resolve_repo_root() / "data" / "cwe" / "surface-to-cwe.json"


@lru_cache(maxsize=1)
def load_surface_to_cwe() -> dict[str, dict[str, Any]]:
    path = surface_to_cwe_path()
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload.get("surfaces", {})


def languages_by_extension(repo_root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in _iter_source_files(repo_root):
        language = _EXTENSION_LANGUAGES.get(path.suffix.lower())
        if language:
            counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items()))


def _iter_source_files(repo_root: Path):
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def scan_manifests(repo_root: Path) -> list[ManifestEvidence]:
    evidence: list[ManifestEvidence] = []
    for manifest_name in _MANIFEST_FILES:
        manifest_path = repo_root / manifest_name
        if not manifest_path.is_file():
            continue
        text = manifest_path.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            lowered = line.lower()
            matched: set[str] = set()
            for needle, surfaces in _MANIFEST_SURFACE_HINTS.items():
                if needle in lowered:
                    matched.update(surfaces)
            if matched:
                evidence.append(
                    ManifestEvidence(
                        manifest=manifest_name,
                        entry=f"{manifest_name}:{line_no}: {line.strip()[:120]}",
                        surfaces=tuple(sorted(matched)),
                    )
                )
    return evidence


def _surface_for_import_module(module: str) -> str | None:
    if module in _IMPORT_MODULE_SURFACES:
        return _IMPORT_MODULE_SURFACES[module]
    root = module.split(".", 1)[0]
    return _IMPORT_MODULE_SURFACES.get(root)


def _line_detail(lines: list[str], line_no: int) -> str:
    if 0 < line_no <= len(lines):
        return lines[line_no - 1].strip()[:160]
    return ""


def _append_surface_hit(
    items: list[EvidenceItem],
    *,
    rel: str,
    lines: list[str],
    line_no: int,
    surface: str,
) -> None:
    items.append(
        EvidenceItem(
            surface=surface,
            file=rel,
            line=line_no,
            detail=_line_detail(lines, line_no),
        )
    )


class _PythonImportSurfaceVisitor(ast.NodeVisitor):
    def __init__(self, *, rel: str, lines: list[str], items: list[EvidenceItem]) -> None:
        self._rel = rel
        self._lines = lines
        self._items = items

    def _record(self, surface: str, line_no: int) -> None:
        _append_surface_hit(
            self._items,
            rel=self._rel,
            lines=self._lines,
            line_no=line_no,
            surface=surface,
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            surface = _surface_for_import_module(alias.name)
            if surface:
                self._record(surface, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            surface = _surface_for_import_module(node.module)
            if surface:
                self._record(surface, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            self._record("file_path_api", node.lineno)
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "system"
        ):
            self._record("subprocess_shell", node.lineno)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and _AUTHZ_IDENT_RE.match(node.id):
            self._record("authz_api", node.lineno)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if _AUTHZ_IDENT_RE.match(node.attr):
            self._record("authz_api", node.lineno)
        self.generic_visit(node)


def _scan_python_import_surfaces(rel: str, text: str) -> list[EvidenceItem]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    items: list[EvidenceItem] = []
    _PythonImportSurfaceVisitor(rel=rel, lines=lines, items=items).visit(tree)
    return items


def scan_import_surfaces(repo_root: Path) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for path in _iter_source_files(repo_root):
        if path.suffix.lower() not in {".py", ".js", ".ts", ".go", ".java", ".rb", ".rs"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(repo_root).as_posix()
        if is_excluded_test_path(rel):
            continue
        if path.suffix.lower() == ".py":
            items.extend(_scan_python_import_surfaces(rel, text))
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for surface, pattern in _IMPORT_SURFACE_PATTERNS:
                if pattern.search(line):
                    items.append(
                        EvidenceItem(
                            surface=surface,
                            file=rel,
                            line=line_no,
                            detail=line.strip()[:160],
                        )
                    )
    return items


def _contains_sql_keyword(text: str) -> bool:
    return bool(_SQL_KEYWORD_RE.search(text))


def _expr_static_sql_text(expr: ast.expr) -> str:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    if isinstance(expr, ast.JoinedStr):
        parts: list[str] = []
        for value in expr.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
        return "".join(parts)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left = _expr_static_sql_text(expr.left)
        right = _expr_static_sql_text(expr.right)
        if left or right:
            return left + right
    return ""


def _expr_has_dynamic_interpolation(expr: ast.expr) -> bool:
    if isinstance(expr, ast.JoinedStr):
        return any(isinstance(value, ast.FormattedValue) for value in expr.values)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _expr_has_dynamic_interpolation(expr.left) or _expr_has_dynamic_interpolation(expr.right)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        return _contains_sql_keyword(_expr_static_sql_text(expr.left))
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        if expr.func.attr == "format" and _contains_sql_keyword(_expr_static_sql_text(expr.func.value)):
            return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        if isinstance(expr.left, ast.Name) or isinstance(expr.right, ast.Name):
            static = _expr_static_sql_text(expr)
            if _contains_sql_keyword(static):
                return True
    return False


def _expr_builds_dynamic_sql(expr: ast.expr) -> bool:
    static_text = _expr_static_sql_text(expr)
    if not _contains_sql_keyword(static_text) and not (
        isinstance(expr, ast.JoinedStr)
        or (isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)))
        or (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format")
    ):
        return False
    if isinstance(expr, ast.JoinedStr):
        return _contains_sql_keyword(static_text) and _expr_has_dynamic_interpolation(expr)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        return _contains_sql_keyword(static_text)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        if _expr_has_dynamic_interpolation(expr):
            return True
        if isinstance(expr.left, ast.Name) or isinstance(expr.right, ast.Name):
            return _contains_sql_keyword(static_text)
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            return _contains_sql_keyword(_expr_static_sql_text(expr.func.value))
        if isinstance(expr.func, ast.Name) and expr.func.id == "text":
            return expr.args and _expr_builds_dynamic_sql(expr.args[0])
    return False


def _is_db_execute_call(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr in _EXECUTE_METHODS
    if isinstance(call.func, ast.Name):
        return call.func.id == "text"
    if isinstance(call.func, ast.Attribute) and call.func.attr == "text":
        return True
    return False


def _is_parameterized_execute(call: ast.Call) -> bool:
    if len(call.args) < 2:
        return False
    first = call.args[0]
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        return False
    if not _PLACEHOLDER_RE.search(first.value):
        return False
    second = call.args[1]
    return isinstance(second, (ast.Tuple, ast.List))


def _first_arg_uses_tracked_sql(call: ast.Call, sql_vars: set[str]) -> bool:
    if not call.args:
        return False
    first = call.args[0]
    if isinstance(first, ast.Name) and first.id in sql_vars:
        return True
    if _expr_builds_dynamic_sql(first):
        return not _is_parameterized_execute(call)
    if (
        isinstance(call.func, ast.Name)
        and call.func.id == "text"
        and call.args
        and _expr_builds_dynamic_sql(call.args[0])
    ):
        return True
    if (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "text"
        and call.args
        and _expr_builds_dynamic_sql(call.args[0])
    ):
        return True
    return False


def _scan_function_deferred_sql(
    node: ast.AST,
    *,
    rel: str,
    lines: list[str],
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    sql_vars: set[str] = set()

    for child in ast.walk(node):
        if isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Name) and _expr_builds_dynamic_sql(child.value):
                    sql_vars.add(target.id)
        if isinstance(child, ast.AnnAssign):
            if isinstance(child.target, ast.Name) and child.value and _expr_builds_dynamic_sql(child.value):
                sql_vars.add(child.target.id)

    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or not _is_db_execute_call(child):
            continue
        if not _first_arg_uses_tracked_sql(child, sql_vars):
            continue
        line_no = child.lineno
        detail = lines[line_no - 1].strip()[:160] if 0 < line_no <= len(lines) else ""
        items.append(
            EvidenceItem(
                surface="raw_sql_callsite",
                file=rel,
                line=line_no,
                detail=detail,
            )
        )
    return items


def _scan_python_deferred_sql(rel: str, text: str) -> list[EvidenceItem]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    items: list[EvidenceItem] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            items.extend(_scan_function_deferred_sql(node, rel=rel, lines=lines))
        elif isinstance(node, (ast.Assign, ast.Expr)):
            scoped = ast.Module(body=[node], type_ignores=[])
            items.extend(_scan_function_deferred_sql(scoped, rel=rel, lines=lines))
    return items


class _PythonCallsiteSurfaceVisitor(ast.NodeVisitor):
    def __init__(self, *, rel: str, lines: list[str], items: list[EvidenceItem]) -> None:
        self._rel = rel
        self._lines = lines
        self._items = items

    def _record(self, surface: str, line_no: int) -> None:
        _append_surface_hit(
            self._items,
            rel=self._rel,
            lines=self._lines,
            line_no=line_no,
            surface=surface,
        )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if (
                isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
                and func.attr in {"run", "Popen", "call"}
            ):
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        self._record("subprocess_shell", node.lineno)
            if isinstance(func.value, ast.Name) and func.value.id in {"pickle", "yaml", "marshal"}:
                if func.attr == "loads":
                    self._record("serialization", node.lineno)
            if isinstance(func.value, ast.Name) and func.value.id == "requests":
                if func.attr in {"get", "post", "put", "delete"}:
                    self._record("http_client", node.lineno)
            if isinstance(func.value, ast.Name) and func.value.id == "httpx":
                if func.attr in {"get", "post"}:
                    self._record("http_client", node.lineno)
            if (
                isinstance(func.value, ast.Attribute)
                and isinstance(func.value.value, ast.Name)
                and func.value.value.id == "urllib"
                and func.value.attr == "request"
                and func.attr == "urlopen"
            ):
                self._record("http_client", node.lineno)
            if (
                isinstance(func.value, ast.Attribute)
                and isinstance(func.value.value, ast.Name)
                and func.value.value.id == "os"
                and func.value.attr == "path"
                and func.attr == "join"
            ):
                self._record("file_path_api", node.lineno)
        if isinstance(func, ast.Name) and func.id == "urlopen":
            self._record("http_client", node.lineno)
        if isinstance(func, ast.Name) and func.id == "Path" and node.args:
            first = node.args[0]
            if isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
                self._record("file_path_api", node.lineno)
        self.generic_visit(node)


def _scan_python_callsite_surfaces(rel: str, text: str) -> list[EvidenceItem]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    items: list[EvidenceItem] = []
    _PythonCallsiteSurfaceVisitor(rel=rel, lines=lines, items=items).visit(tree)
    items.extend(_scan_python_deferred_sql(rel, text))
    return items


def scan_callsite_surfaces(repo_root: Path) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for path in _iter_source_files(repo_root):
        if path.suffix.lower() not in {".py", ".js", ".ts"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(repo_root).as_posix()
        if is_excluded_test_path(rel):
            continue
        if path.suffix.lower() == ".py":
            items.extend(_scan_python_callsite_surfaces(rel, text))
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for surface, pattern in _CALLSITE_SURFACE_PATTERNS:
                if pattern.search(line):
                    items.append(
                        EvidenceItem(
                            surface=surface,
                            file=rel,
                            line=line_no,
                            detail=line.strip()[:160],
                        )
                    )
    return items
