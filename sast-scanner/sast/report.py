"""Geração do relatório .txt priorizado por ordem de correção."""

from collections import defaultdict
from datetime import datetime
from typing import List

from .rules import SEVERITY_ORDER, MANUAL_REVIEW_CATEGORIES

SEVERITY_LABEL_PT = {
    "CRITICAL": "CRÍTICA",
    "HIGH": "ALTA",
    "MEDIUM": "MÉDIA",
    "LOW": "BAIXA",
    "INFO": "INFORMATIVA",
}

BAR = "=" * 78
SUB = "-" * 78


def _severity_summary(all_items):
    counts = defaultdict(int)
    for item in all_items:
        counts[item.severity] += 1
    return counts


def build_report(repo_path: str, findings: List, dependency_findings: List, output_path: str) -> None:
    all_items = list(findings) + list(dependency_findings)

    # Prioridade de correção: severidade (desc) -> categoria com mais achados primeiro -> arquivo -> linha
    category_counts = defaultdict(int)
    for item in all_items:
        category_counts[item.category] += 1

    def sort_key(item):
        return (
            -SEVERITY_ORDER.get(item.severity, 0),
            -category_counts[item.category],
            item.category,
            item.file,
            item.line,
        )

    ordered = sorted(all_items, key=sort_key)

    counts = _severity_summary(all_items)
    total = len(all_items)

    lines = []
    lines.append(BAR)
    lines.append("RELATÓRIO DE ANÁLISE ESTÁTICA DE SEGURANÇA (SAST)")
    lines.append(BAR)
    lines.append(f"Repositório analisado : {repo_path}")
    lines.append(f"Data/hora da análise  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Total de achados      : {total}")
    lines.append("")
    lines.append("Resumo por severidade (ordem de prioridade de correção):")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if counts.get(sev):
            lines.append(f"  [{SEVERITY_LABEL_PT[sev]:<12}] {counts[sev]:>4} achado(s)")
    lines.append("")
    lines.append("Legenda de prioridade: CRÍTICA > ALTA > MÉDIA > BAIXA > INFORMATIVA.")
    lines.append("Dentro de cada severidade, achados são agrupados pela categoria com maior")
    lines.append("número de ocorrências (maior impacto potencial) primeiro.")
    lines.append(BAR)
    lines.append("")

    if not ordered:
        lines.append("Nenhum achado automatizado. Ainda assim, consulte a seção de itens que")
        lines.append("exigem revisão manual abaixo.")
        lines.append("")
    else:
        lines.append("SEÇÃO 1 - ACHADOS PRIORIZADOS (ordem de correção sugerida)")
        lines.append(BAR)
        lines.append("")
        for idx, item in enumerate(ordered, start=1):
            rule_id = getattr(item, "rule_id", "DEP")
            lines.append(f"#{idx:03d} [{SEVERITY_LABEL_PT.get(item.severity, item.severity)}] "
                         f"{item.category}  (regra: {rule_id})")
            lines.append(f"      Arquivo   : {item.file}:{item.line}")
            lines.append(f"      Descrição : {item.description}")
            if item.snippet:
                lines.append(f"      Trecho    : {item.snippet}")
            lines.append(f"      Correção  : {item.recommendation}")
            lines.append(SUB)
        lines.append("")

    lines.append("SEÇÃO 2 - CATEGORIAS QUE EXIGEM REVISÃO MANUAL / TESTE DINÂMICO")
    lines.append(BAR)
    lines.append("As categorias abaixo não são confiavelmente detectáveis apenas por análise")
    lines.append("estática de padrões (regex). Priorize a revisão manual seguindo a mesma")
    lines.append("ordem de severidade.")
    lines.append("")
    manual_sorted = sorted(MANUAL_REVIEW_CATEGORIES, key=lambda t: -SEVERITY_ORDER.get(t[1], 0))
    for category, severity, guidance in manual_sorted:
        lines.append(f"[{SEVERITY_LABEL_PT.get(severity, severity)}] {category}")
        lines.append(f"      {guidance}")
        lines.append(SUB)
    lines.append("")

    lines.append(BAR)
    lines.append("FIM DO RELATÓRIO")
    lines.append(BAR)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
