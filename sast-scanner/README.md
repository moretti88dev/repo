# SAST Scanner (local)

Ferramenta de análise estática de segurança (SAST) para rodar **100% local**,
sem enviar código para nenhum serviço externo. Analisa um repositório
informado pelo usuário e gera um relatório `.txt` com os achados **em ordem
de prioridade de correção**.

Cobre heuristicamente as seguintes categorias:

API Key Leaks, Account Takeover, Brute Force Rate Limit, Business Logic
Errors\*, CORS Misconfiguration, CRLF Injection, CSS Injection, CSV
Injection, CVE Exploits, Clickjacking, Client Side Path Traversal, Command
Injection, Cross-Site Request Forgery, DNS Rebinding, DOM Clobbering,
Denial of Service, Dependency Confusion, Directory Traversal, Encoding
Transformations\*, External Variable Modification, File Inclusion, Google
Web Toolkit, GraphQL Injection, HTTP Parameter Pollution, Headless Browser,
Hidden Parameters, Insecure Deserialization, Insecure Direct Object
References, Insecure Management Interface\*, Insecure Randomness, Insecure
Source Code Management, JSON Web Token, Java RMI, LDAP Injection, LaTeX
Injection, Mass Assignment, Methodology and Resources\*, NoSQL Injection,
OAuth Misconfiguration, ORM Leak, Open Redirect, Prompt Injection,
Prototype Pollution, Race Condition\*, Regular Expression\*, Request
Smuggling, Reverse Proxy Misconfigurations\*, SAML Injection, SQL
Injection, Server Side Include Injection, Server Side Request Forgery,
Server Side Template Injection, Tabnabbing, Type Juggling, Upload Insecure
Files, Virtual Hosts\*, Web Cache Deception\*, Web Sockets, XPATH
Injection, XS-Leak\*, XSLT Injection, XSS Injection, XXE Injection, Zip
Slip.

\* Categorias marcadas com asterisco são, total ou parcialmente, difíceis de
detectar de forma confiável só com análise estática de padrões — elas
sempre aparecem na **Seção 2** do relatório com orientação para revisão
manual/teste dinâmico, independentemente do que for encontrado
automaticamente.

## Requisitos

- Python 3.8+ (não é necessária nenhuma biblioteca de terceiros).
- Opcional: `npm` e/ou `pip-audit` instalados no ambiente para auditoria
  automática de dependências vulneráveis (CVE Exploits). Se não estiverem
  disponíveis, o scanner apenas lista os manifestos encontrados e recomenda
  rodar a auditoria manualmente.

## Como rodar

```bash
cd sast-scanner

# informe o caminho local do repositório a ser analisado
python3 scan.py /caminho/para/o/repositorio

# opcional: escolher o nome/local do relatório de saída
python3 scan.py /caminho/para/o/repositorio -o /caminho/para/relatorio.txt

# opcional: excluir diretórios adicionais da varredura
python3 scan.py /caminho/para/o/repositorio --exclude tests fixtures docs
```

Ao final, será impresso o caminho do relatório gerado, por exemplo:

```
[*] Iniciando análise SAST em: /home/user/meu-projeto
[*] Aplicando regras de detecção de padrões...
    -> 42 achado(s) de padrão de código.
[*] Verificando dependências (CVE Exploits / Dependency Confusion)...
    -> 3 achado(s) relacionados a dependências.
[+] Relatório gerado em: /home/user/meu-projeto/sast-scanner/sast_report.txt
```

## Formato do relatório

O `.txt` gerado tem duas seções:

1. **Achados priorizados** — cada achado automático (arquivo, linha, trecho,
   descrição, recomendação de correção), ordenado por:
   1. Severidade: `CRÍTICA` → `ALTA` → `MÉDIA` → `BAIXA` → `INFORMATIVA`
   2. Categoria com mais ocorrências primeiro (maior superfície de impacto)
   3. Arquivo e linha
2. **Categorias que exigem revisão manual/teste dinâmico** — categorias que
   uma ferramenta puramente estática não consegue confirmar sozinha (ex.:
   Business Logic Errors, Race Condition), com orientação do que testar.

## Estrutura do projeto

```
sast-scanner/
├── scan.py                  # CLI de entrada
├── sast/
│   ├── rules.py              # Regras (padrões) por categoria + severidade
│   ├── engine.py              # Percorre o repositório e aplica as regras
│   ├── dependency_check.py    # CVE Exploits / Dependency Confusion (manifestos + npm/pip-audit)
│   └── report.py               # Geração do relatório .txt priorizado
└── README.md
```

## Limitações (leia antes de confiar cegamente no relatório)

- É um scanner **baseado em padrões (regex)**, não em análise semântica de
  fluxo de dados (taint analysis). Isso significa: bom recall, mas **pode
  gerar falsos positivos** — todo achado deve ser confirmado manualmente
  antes de virar tarefa de correção.
- Não substitui um pentest, DAST ou revisão de código humana, especialmente
  para as categorias de lógica de negócio, condição de corrida e
  configuração de infraestrutura/rede.
- A verificação de CVEs depende de ferramentas externas (`npm audit`,
  `pip-audit`) já instaladas localmente; sem elas, apenas os manifestos de
  dependência são listados para auditoria manual.
