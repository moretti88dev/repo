"""
Verificação best-effort de dependências para as categorias 'CVE Exploits' e
'Dependency Confusion'.

Não requer rede/instalação: se as ferramentas de auditoria (npm, pip-audit,
etc.) não estiverem disponíveis no ambiente, o módulo apenas reporta os
manifestos encontrados e recomenda rodar a auditoria externamente.
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List

MANIFESTS = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "Pipfile": "pip",
    "composer.json": "composer",
    "go.mod": "go",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "Gemfile": "bundler",
}

INTERNAL_NAME_HINTS = ("internal", "corp", "private", "-org-", "company")


@dataclass
class DependencyFinding:
    category: str
    severity: str
    description: str
    recommendation: str
    file: str
    line: int = 0
    snippet: str = ""


def _run(cmd, cwd, timeout=60):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _npm_audit(repo_path: str, manifest_dir: str) -> List[DependencyFinding]:
    findings = []
    if not shutil.which("npm"):
        return findings
    result = _run(["npm", "audit", "--json"], cwd=manifest_dir)
    if not result or not result.stdout:
        return findings
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return findings

    vulns = data.get("vulnerabilities", {})
    for pkg, info in vulns.items():
        severity = str(info.get("severity", "medium")).upper()
        severity = severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"
        rel_manifest = os.path.relpath(os.path.join(manifest_dir, "package.json"), repo_path)
        findings.append(DependencyFinding(
            category="CVE Exploits",
            severity=severity,
            description=f"Dependência npm '{pkg}' possui vulnerabilidade(s) conhecida(s) (npm audit).",
            recommendation="Rodar 'npm audit fix' ou atualizar a dependência para uma versão corrigida.",
            file=rel_manifest.replace(os.sep, "/"),
        ))
    return findings


def _pip_audit(repo_path: str, manifest_path: str) -> List[DependencyFinding]:
    findings = []
    if not shutil.which("pip-audit"):
        return findings
    result = _run(["pip-audit", "-r", manifest_path, "-f", "json"], cwd=repo_path)
    if not result or not result.stdout:
        return findings
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return findings

    rel_manifest = os.path.relpath(manifest_path, repo_path).replace(os.sep, "/")
    dependencies = data if isinstance(data, list) else data.get("dependencies", [])
    for dep in dependencies:
        for vuln in dep.get("vulns", []):
            findings.append(DependencyFinding(
                category="CVE Exploits",
                severity="HIGH",
                description=(
                    f"Dependência Python '{dep.get('name')}=={dep.get('version')}' possui vulnerabilidade "
                    f"conhecida {vuln.get('id', '')}."
                ),
                recommendation="Atualizar para uma versão corrigida listada pelo pip-audit.",
                file=rel_manifest,
            ))
    return findings


def _dependency_confusion_heuristic(repo_path: str, manifest_path: str) -> List[DependencyFinding]:
    """Heurística offline: sinaliza dependências com nome 'interno' para confirmação manual
    de que estão publicadas em registry privado com escopo reservado."""
    findings = []
    rel_manifest = os.path.relpath(manifest_path, repo_path).replace(os.sep, "/")
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return findings

    if manifest_path.endswith("package.json"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings
        deps = {}
        for key in ("dependencies", "devDependencies"):
            deps.update(data.get(key, {}) or {})
        for name in deps:
            if name.startswith("@"):
                continue  # já escopado
            if any(hint in name.lower() for hint in INTERNAL_NAME_HINTS):
                findings.append(DependencyFinding(
                    category="Dependency Confusion",
                    severity="MEDIUM",
                    description=(
                        f"Dependência '{name}' parece ser um pacote interno mas não está escopada "
                        f"(sem prefixo @org/) — risco de dependency confusion se o nome não estiver "
                        f"reservado também no registry público."
                    ),
                    recommendation=(
                        "Publicar pacotes internos com escopo reservado (@sua-org/pacote) e/ou registrar "
                        "o nome no registry público para evitar sequestro; configurar .npmrc apontando "
                        "explicitamente para o registry privado por escopo."
                    ),
                    file=rel_manifest,
                ))
    return findings


def check_dependencies(repo_path: str) -> List[DependencyFinding]:
    findings: List[DependencyFinding] = []
    found_manifests = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "vendor", "venv", ".venv"}]
        for fname in files:
            if fname in MANIFESTS:
                found_manifests.append(os.path.join(root, fname))

    if not found_manifests:
        return findings

    for manifest_path in found_manifests:
        rel = os.path.relpath(manifest_path, repo_path).replace(os.sep, "/")
        findings.append(DependencyFinding(
            category="CVE Exploits",
            severity="INFO",
            description=f"Manifesto de dependências encontrado: {rel}.",
            recommendation=(
                "Rodar auditoria de dependências (npm audit / pip-audit / safety / Trivy / Grype) "
                "periodicamente e no CI/CD para detectar CVEs em bibliotecas de terceiros."
            ),
            file=rel,
        ))

        basename = os.path.basename(manifest_path)
        manifest_dir = os.path.dirname(manifest_path)

        if basename == "package.json":
            findings.extend(_npm_audit(repo_path, manifest_dir))
            findings.extend(_dependency_confusion_heuristic(repo_path, manifest_path))
        elif basename in ("requirements.txt", "Pipfile"):
            findings.extend(_pip_audit(repo_path, manifest_path))

    return findings
