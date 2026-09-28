#!/usr/bin/env python3
"""
SAST Scanner - CLI de análise estática de segurança local.

Uso:
    python scan.py /caminho/para/o/repositorio
    python scan.py /caminho/para/o/repositorio -o relatorio.txt
    python scan.py /caminho/para/o/repositorio --exclude tests fixtures

Não requer nenhuma dependência externa (usa apenas a biblioteca padrão do
Python 3.8+). Auditoria de dependências (npm audit / pip-audit) é usada
automaticamente se as ferramentas já estiverem instaladas no ambiente;
caso contrário, o scanner apenas reporta os manifestos encontrados.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sast.engine import scan_repository
from sast.dependency_check import check_dependencies
from sast.report import build_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analisa estaticamente um repositório local em busca de vulnerabilidades "
                     "e gera um relatório .txt priorizado por ordem de correção."
    )
    parser.add_argument(
        "repo_path",
        help="Caminho local do repositório a ser analisado (ex.: /home/user/meu-projeto).",
    )
    parser.add_argument(
        "-o", "--output",
        default="sast_report.txt",
        help="Caminho do arquivo de relatório .txt a ser gerado (padrão: sast_report.txt).",
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="Nomes de diretórios adicionais a excluir da varredura.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    repo_path = os.path.abspath(args.repo_path)
    if not os.path.isdir(repo_path):
        print(f"Erro: caminho de repositório inválido: {repo_path}", file=sys.stderr)
        sys.exit(1)

    output_path = os.path.abspath(args.output)

    print(f"[*] Iniciando análise SAST em: {repo_path}")

    print("[*] Aplicando regras de detecção de padrões...")
    findings = scan_repository(repo_path, extra_exclude_dirs=args.exclude, skip_files=[output_path])
    print(f"    -> {len(findings)} achado(s) de padrão de código.")

    print("[*] Verificando dependências (CVE Exploits / Dependency Confusion)...")
    dependency_findings = check_dependencies(repo_path)
    print(f"    -> {len(dependency_findings)} achado(s) relacionados a dependências.")

    build_report(repo_path, findings, dependency_findings, output_path)

    print(f"[+] Relatório gerado em: {output_path}")


if __name__ == "__main__":
    main()
