# SAST Scanner (local)

Ferramenta de linha de comando para análise estática de segurança (SAST),
feita para rodar **100% localmente** — nenhum código é enviado para
serviços externos. Você informa o caminho de um repositório na sua máquina,
o scanner varre os arquivos aplicando um conjunto de regras de detecção de
vulnerabilidades e gera um relatório `.txt` com os achados **em ordem de
prioridade de correção**.

O código da ferramenta está em [`sast-scanner/`](./sast-scanner).

## O que o projeto faz

1. **Recebe o caminho de um repositório local** (via argumento de linha de
   comando).
2. **Percorre os arquivos do repositório** (ignorando diretórios irrelevantes
   como `.git`, `node_modules`, `vendor`, `dist`, `venv`, etc.) e aplica
   dezenas de regras baseadas em padrões (regex) para detectar indícios de
   vulnerabilidades conhecidas — SQL Injection, XSS, SSRF, SSTI, XXE, IDOR,
   CSRF, JWT mal configurado, segredos/API keys expostos, Zip Slip,
   Prototype Pollution, entre outras.
3. **Analisa manifestos de dependências** (`package.json`,
   `requirements.txt`, `composer.json`, etc.) e, se as ferramentas
   estiverem instaladas no ambiente (`npm audit`, `pip-audit`), roda a
   auditoria automaticamente para apontar dependências com CVEs conhecidas;
   também aplica uma heurística para sinalizar risco de *Dependency
   Confusion*.
4. **Gera um relatório `.txt`** com todos os achados ordenados por
   prioridade de correção (severidade, depois categoria com mais
   ocorrências), incluindo arquivo, linha, trecho de código e recomendação
   de correção para cada item.
5. **Lista separadamente as categorias que exigem revisão manual/teste
   dinâmico** — vulnerabilidades como *Business Logic Errors* e *Race
   Condition* não são detectáveis com confiança apenas por análise
   estática de padrões, então o relatório sempre inclui uma seção com
   orientação de como testá-las manualmente.

## Categorias de vulnerabilidade cobertas

API Key Leaks, Account Takeover, Brute Force Rate Limit, Business Logic
Errors, CORS Misconfiguration, CRLF Injection, CSS Injection, CSV
Injection, CVE Exploits, Clickjacking, Client Side Path Traversal, Command
Injection, Cross-Site Request Forgery, DNS Rebinding, DOM Clobbering,
Denial of Service, Dependency Confusion, Directory Traversal, Encoding
Transformations, External Variable Modification, File Inclusion, Google
Web Toolkit, GraphQL Injection, HTTP Parameter Pollution, Headless
Browser, Hidden Parameters, Insecure Deserialization, Insecure Direct
Object References, Insecure Management Interface, Insecure Randomness,
Insecure Source Code Management, JSON Web Token, Java RMI, LDAP Injection,
LaTeX Injection, Mass Assignment, Methodology and Resources, NoSQL
Injection, OAuth Misconfiguration, ORM Leak, Open Redirect, Prompt
Injection, Prototype Pollution, Race Condition, Regular Expression,
Request Smuggling, Reverse Proxy Misconfigurations, SAML Injection, SQL
Injection, Server Side Include Injection, Server Side Request Forgery,
Server Side Template Injection, Tabnabbing, Type Juggling, Upload
Insecure Files, Virtual Hosts, Web Cache Deception, Web Sockets, XPATH
Injection, XS-Leak, XSLT Injection, XSS Injection, XXE Injection, Zip
Slip.

## Como usar

Requer apenas Python 3.8+ (sem dependências externas obrigatórias).

```bash
cd sast-scanner

# informe o caminho local do repositório a ser analisado
python3 scan.py /caminho/para/o/repositorio

# opcional: escolher o nome/local do relatório de saída
python3 scan.py /caminho/para/o/repositorio -o /caminho/para/relatorio.txt

# opcional: excluir diretórios adicionais da varredura
python3 scan.py /caminho/para/o/repositorio --exclude tests fixtures docs
```

Ao final, o caminho do relatório gerado é impresso no terminal.

Detalhes de arquitetura, formato do relatório e limitações estão no
[`README.md`](./sast-scanner/README.md) dentro de `sast-scanner/`.
