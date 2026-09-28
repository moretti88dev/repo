"""Motor de varredura: percorre o repositório e aplica as regras de sast.rules."""

import os
from dataclasses import dataclass
from typing import List

from .rules import RULES, SEVERITY_ORDER

DEFAULT_EXCLUDE_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "out", "target",
    "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
    ".next", ".nuxt", "coverage", ".idea", ".vscode", "bin", "obj",
}

# Extensões binárias/irrelevantes — não vale a pena ler como texto
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".gz", ".tar", ".rar", ".7z", ".jar", ".war", ".exe", ".dll",
    ".so", ".dylib", ".class", ".pyc", ".pdf", ".mp4", ".mp3", ".mov",
    ".lock",
}

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str
    recommendation: str
    file: str
    line: int
    snippet: str

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


def _iter_files(repo_path: str, exclude_dirs):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith(".git")]
        for fname in files:
            yield os.path.join(root, fname)


def _read_text(path: str):
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE_BYTES:
            return None
    except OSError:
        return None
    _, ext = os.path.splitext(path)
    if ext.lower() in BINARY_EXT:
        return None
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(4096)
            if b"\x00" in chunk:
                return None  # heurística simples de arquivo binário
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def scan_repository(repo_path: str, extra_exclude_dirs=None, skip_files=None) -> List[Finding]:
    """Percorre repo_path aplicando todas as regras e retorna a lista de Findings.

    skip_files: caminhos absolutos a ignorar (ex.: o próprio relatório de saída,
    para evitar que uma reexecução escaneie o relatório da execução anterior).
    """
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
    if extra_exclude_dirs:
        exclude_dirs.update(extra_exclude_dirs)
    skip_files = {os.path.abspath(p) for p in (skip_files or [])}

    findings: List[Finding] = []

    for filepath in _iter_files(repo_path, exclude_dirs):
        if os.path.abspath(filepath) in skip_files:
            continue
        rel_path = os.path.relpath(filepath, repo_path)
        basename = os.path.basename(filepath)

        applicable_rules = [r for r in RULES if r.matches_file(basename)]
        if not applicable_rules:
            continue

        content = _read_text(filepath)
        if content is None:
            continue

        lines = content.splitlines()
        for rule in applicable_rules:
            for lineno, line in enumerate(lines, start=1):
                if rule.pattern.search(line):
                    snippet = line.strip()
                    if len(snippet) > 160:
                        snippet = snippet[:157] + "..."
                    findings.append(Finding(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        recommendation=rule.recommendation,
                        file=rel_path.replace(os.sep, "/"),
                        line=lineno,
                        snippet=snippet,
                    ))

    return findings
