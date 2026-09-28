"""
Definição das regras de detecção (padrões regex) usadas pelo motor de varredura.

Cada regra é heurística: reduz falso-negativo priorizando cobertura, o que pode
gerar falso-positivo ocasional. Todo achado deve ser confirmado manualmente
antes da correção (ver README.md).
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern

# Ordem de prioridade de correção (maior = corrigir primeiro)
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    description: str
    recommendation: str
    pattern: Pattern
    extensions: Optional[List[str]] = None  # None = qualquer arquivo de texto
    flags_note: str = ""

    def matches_file(self, filename: str) -> bool:
        if self.extensions is None:
            return True
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in self.extensions)


def _r(pattern: str, flags=re.IGNORECASE) -> Pattern:
    return re.compile(pattern, flags)


WEB_EXT = [".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".php", ".py", ".rb",
           ".java", ".go", ".vue", ".svelte", ".mjs", ".cjs"]
SERVER_EXT = [".js", ".jsx", ".ts", ".tsx", ".php", ".py", ".rb", ".java", ".go",
              ".cs", ".mjs", ".cjs"]
CONFIG_EXT = [".conf", ".config", ".yml", ".yaml", ".json", ".env", ".ini",
              ".xml", ".toml", ".properties"]

RULES: List[Rule] = [

    # ---------------------------------------------------------------- API Key Leaks
    Rule("SECRET-001", "API Key Leaks", "CRITICAL",
         "Possível chave de API/segredo (AWS, Google, Stripe, Slack, GitHub) hardcoded no código-fonte.",
         "Remover o segredo do código, revogar/rotacionar a chave exposta e usar variáveis de ambiente "
         "ou um cofre de segredos (Vault, AWS Secrets Manager, etc.).",
         _r(r"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|sk_live_[0-9a-zA-Z]{24,}|"
            r"xox[baprs]-[0-9a-zA-Z-]{10,}|ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{20,}|"
            r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----)")),
    Rule("SECRET-002", "API Key Leaks", "HIGH",
         "Variável nomeada como chave/senha/token com valor literal atribuído diretamente no código.",
         "Externalizar credenciais para variáveis de ambiente/secret manager; nunca versionar segredos.",
         _r(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|pwd)"
            r"\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),

    # ---------------------------------------------------------------- Account Takeover
    Rule("ATO-001", "Account Takeover", "HIGH",
         "Endpoint/rota de redefinição de senha ou troca de e-mail sem indício de verificação de token/OTP.",
         "Garantir que reset de senha, troca de e-mail e 'esqueci minha senha' exijam token de uso único, "
         "com expiração curta e vinculado à sessão/usuário; invalidar sessões antigas após troca de credenciais.",
         _r(r"reset[-_]?password|forgot[-_]?password|change[-_]?email", re.IGNORECASE),
         extensions=SERVER_EXT),
    Rule("ATO-002", "Account Takeover", "MEDIUM",
         "Comparação de token/OTP usando operador de igualdade simples (vulnerável a timing attack).",
         "Usar comparação de tempo constante (ex.: hmac.compare_digest, crypto.timingSafeEqual).",
         _r(r"(otp|token|reset_?code)\s*==\s*(req|request|input|user)")),

    # ---------------------------------------------------------------- Brute Force / Rate Limit
    Rule("BFRL-001", "Brute Force Rate Limit", "HIGH",
         "Rota de login/autenticação sem referência a rate limiting, captcha ou bloqueio de tentativas nas proximidades.",
         "Aplicar rate limiting (ex.: express-rate-limit, django-ratelimit), captcha e bloqueio "
         "progressivo/lockout após N tentativas falhas de login.",
         _r(r"(app|router)\.(post|get)\(['\"](\/)?(login|signin|auth|token)['\"]", re.IGNORECASE),
         extensions=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]),

    # ---------------------------------------------------------------- Business Logic Errors
    # Não determinável por regex — ver manual_review.py

    # ---------------------------------------------------------------- CORS Misconfiguration
    Rule("CORS-001", "CORS Misconfiguration", "HIGH",
         "Cabeçalho Access-Control-Allow-Origin refletindo qualquer origem ('*') combinado (ou não) com credenciais.",
         "Nunca usar '*' junto de Access-Control-Allow-Credentials: true; usar allowlist explícita de origens confiáveis.",
         _r(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]")),
    Rule("CORS-002", "CORS Misconfiguration", "HIGH",
         "CORS configurado para refletir dinamicamente o header Origin da requisição (origin: true / origin reflection).",
         "Validar a origem contra uma allowlist fixa em vez de refletir automaticamente req.headers.origin.",
         _r(r"(cors\s*\(\s*\{[^}]*origin\s*:\s*true)|"
            r"(res\.(setHeader|header)\(\s*['\"]Access-Control-Allow-Origin['\"]\s*,\s*(req|request)\.headers)")),

    # ---------------------------------------------------------------- CRLF Injection
    Rule("CRLF-001", "CRLF Injection", "HIGH",
         "Escrita de header HTTP concatenando entrada do usuário sem sanitização, com risco de injeção de \\r\\n.",
         "Sanitizar/validar entradas antes de escrevê-las em headers; usar APIs que já codificam automaticamente.",
         _r(r"(setHeader|header)\(\s*['\"][^'\"]+['\"]\s*,\s*[^)]*\b(req|request|params|query)\b")),

    # ---------------------------------------------------------------- CSS Injection
    Rule("CSSI-001", "CSS Injection", "MEDIUM",
         "Entrada do usuário injetada em atributo style/CSS dinâmico.",
         "Evitar montar CSS a partir de entrada do usuário; usar listas de classes permitidas (allowlist).",
         _r(r"style\s*=\s*\{?[^\n]*\+\s*(req|user|input|params)\.")),

    # ---------------------------------------------------------------- CSV Injection
    Rule("CSVI-001", "CSV Injection", "MEDIUM",
         "Geração de CSV a partir de dados do usuário sem escapar células iniciadas com =, +, -, @ (formula injection).",
         "Prefixar/escapar células que iniciem com =, +, -, @, \\t, \\r ao exportar para CSV/Excel.",
         _r(r"(to_?csv|csv\.writer|writeCsv|generateCsv)\s*\(", re.IGNORECASE)),

    # ---------------------------------------------------------------- CVE Exploits / Dependency Confusion
    # Ver dependency_check.py (analisa manifestos de dependências)

    # ---------------------------------------------------------------- Clickjacking
    Rule("CLICK-001", "Clickjacking", "MEDIUM",
         "Nenhum indício de proteção contra Clickjacking (X-Frame-Options / frame-ancestors) próximo à configuração de headers.",
         "Definir X-Frame-Options: DENY/SAMEORIGIN ou Content-Security-Policy: frame-ancestors 'none'/'self'.",
         _r(r"(helmet\s*\(\s*\)|app\.use\s*\(\s*helmet)"), extensions=[".js", ".ts"]),

    # ---------------------------------------------------------------- Client Side Path Traversal
    Rule("CSPT-001", "Client Side Path Traversal", "MEDIUM",
         "Construção de URL/fetch no cliente concatenando entrada do usuário, com risco de path traversal client-side.",
         "Validar/normalizar o path e usar endpoints com parâmetros (não path concatenado) no client-side.",
         _r(r"(fetch|axios\.\w+|\.ajax)\s*\(\s*[`'\"][^`'\"]*\$\{?\s*(location|params|query|input)")),

    # ---------------------------------------------------------------- Command Injection
    Rule("CMDI-001", "Command Injection", "CRITICAL",
         "Execução de comando de sistema (exec/system/popen/shell=True) com dados potencialmente controlados pelo usuário.",
         "Evitar shell=True/exec com concatenação; usar listas de argumentos, APIs nativas e nunca "
         "repassar entrada do usuário diretamente para o shell.",
         _r(r"(os\.system|os\.popen|subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True|"
            r"child_process\.(exec|execSync)|Runtime\.getRuntime\(\)\.exec|shell_exec|proc_open|"
            r"popen\(|pcntl_exec)")),
    Rule("CMDI-002", "Command Injection", "HIGH",
         "Chamada de exec/eval concatenando strings, possível injeção de comando/código.",
         "Nunca concatenar entrada do usuário em comandos de shell ou eval(); usar parametrização/allowlist.",
         _r(r"(exec|eval)\s*\([^\n]*['\"`]\s*\+")),

    # ---------------------------------------------------------------- Cross-Site Request Forgery
    Rule("CSRF-001", "Cross-Site Request Forgery", "HIGH",
         "Formulário HTML com method POST sem campo de token CSRF aparente.",
         "Implementar proteção CSRF (synchronizer token, cookies SameSite=Strict/Lax, ou double-submit cookie).",
         _r(r"<form[^>]*method\s*=\s*['\"]post['\"](?![^>]*csrf)", re.IGNORECASE),
         extensions=[".html", ".htm", ".php", ".jsx", ".tsx"]),
    Rule("CSRF-002", "Cross-Site Request Forgery", "MEDIUM",
         "Configuração de cookie de sessão sem atributo SameSite.",
         "Definir cookies sensíveis com SameSite=Strict ou Lax e Secure=true.",
         _r(r"(set-?cookie\s*[:=(]|\.cookie\s*=)(?![^;\n]*samesite)", re.IGNORECASE)),

    # ---------------------------------------------------------------- DNS Rebinding
    Rule("DNSR-001", "DNS Rebinding", "MEDIUM",
         "Validação de host baseada apenas no header Host, sem allowlist — risco de DNS Rebinding em serviços internos.",
         "Validar conexões a serviços internos por IP/allowlist fixa, não apenas pelo header Host.",
         _r(r"(req|request)\.headers\[['\"]host['\"]\]|\.get\(['\"]host['\"]\)")),

    # ---------------------------------------------------------------- DOM Clobbering
    Rule("DOMC-001", "DOM Clobbering", "MEDIUM",
         "Uso de variável global obtida implicitamente de elemento DOM (window.NOME) sem verificação de tipo.",
         "Usar document.getElementById explicitamente e validar o tipo do elemento retornado antes de usá-lo.",
         _r(r"window\.\w+\s*&&\s*window\.\w+\.(src|href|action)")),

    # ---------------------------------------------------------------- Denial of Service
    Rule("DOS-001", "Denial of Service", "MEDIUM",
         "Leitura de arquivo/upload ou parsing sem limite de tamanho aparente, possível esgotamento de recursos.",
         "Definir limites de tamanho de upload/body (ex.: express.json({limit}), MAX_CONTENT_LENGTH) e timeouts.",
         _r(r"(bodyParser|express\.json|express\.urlencoded)\s*\(\s*\)(?!.*limit)")),
    Rule("DOS-002", "Denial of Service", "HIGH",
         "Regex com padrão vulnerável a ReDoS (grupos aninhados com quantificadores sobrepostos).",
         "Reescrever o regex evitando quantificadores aninhados (ex.: (a+)+) ou usar bibliotecas com timeout/RE2.",
         _r(r"\([^()]*[+*]\)[+*]")),

    # ---------------------------------------------------------------- Dependency Confusion
    # Ver dependency_check.py

    # ---------------------------------------------------------------- Directory Traversal / File Inclusion
    Rule("PATH-001", "Directory Traversal", "CRITICAL",
         "Leitura/escrita de arquivo concatenando path com entrada do usuário, sem sanitização de '..'.",
         "Normalizar o path (realpath/resolve) e validar que o resultado final está dentro do diretório permitido.",
         _r(r"(fs\.(readFile|writeFile|createReadStream)|open\(|fopen\(|File\()\s*\(?\s*[^)]*"
            r"(req\.|request\.|params\.|query\.|input)")),
    Rule("PATH-002", "Directory Traversal", "HIGH",
         "Padrão literal de path traversal ('../' repetido) encontrado no código-fonte.",
         "Investigar o contexto: pode ser um teste, payload de exemplo ou uma vulnerabilidade real de path traversal.",
         _r(r"(\.\./){2,}|(\.\.\\){2,}")),
    Rule("LFI-001", "File Inclusion", "CRITICAL",
         "Inclusão dinâmica de arquivo (include/require/import_module) usando entrada potencialmente controlada pelo usuário.",
         "Nunca incluir arquivos com base em entrada do usuário; usar allowlist fixa de arquivos permitidos.",
         _r(r"(include|include_once|require|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)")),

    # ---------------------------------------------------------------- Encoding Transformations
    Rule("ENC-001", "Encoding Transformations", "LOW",
         "Uso de base64/hex/URL-encode que pode mascarar dados sensíveis ou ser usado para bypass de filtros.",
         "Revisar se a codificação é usada como mecanismo de segurança (não é) e se há validação após decodificar.",
         _r(r"(atob|btoa|Base64\.decode|base64_decode)\s*\(")),

    # ---------------------------------------------------------------- External Variable Modification (PHP register_globals-like)
    Rule("EVM-001", "External Variable Modification", "HIGH",
         "Uso de extract()/variáveis dinâmicas ($$var) a partir de entrada externa — pode sobrescrever variáveis internas.",
         "Evitar extract() sobre dados de entrada; nomear e validar variáveis explicitamente.",
         _r(r"extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|"
            r"\$\$\w+\s*=")),

    # ---------------------------------------------------------------- Google Web Toolkit
    Rule("GWT-001", "Google Web Toolkit", "INFO",
         "Indícios de uso de Google Web Toolkit (GWT-RPC), superfície de ataque específica (deserialização customizada).",
         "Revisar manualmente os endpoints *.rpc/gwt e políticas de serialização (ver GWT AMF/RPC security guidance).",
         _r(r"(gwt-rpc|com\.google\.gwt|\.gwt\.rpc)")),

    # ---------------------------------------------------------------- GraphQL Injection
    Rule("GQL-001", "GraphQL Injection", "HIGH",
         "Servidor GraphQL sem indício de desabilitar introspection/limitar profundidade de query.",
         "Desabilitar introspection em produção, limitar profundidade/complexidade de queries e aplicar rate limiting.",
         _r(r"(ApolloServer|graphqlHTTP|buildSchema)\s*\(")),
    Rule("GQL-002", "GraphQL Injection", "CRITICAL",
         "Resolver GraphQL passando argumentos diretamente para consulta ao banco sem sanitização aparente.",
         "Validar/parametrizar argumentos do resolver antes de repassá-los à camada de dados.",
         _r(r"resolve\s*:\s*(async\s*)?\([^)]*\)\s*=>\s*\{[^}]*(query|find)\([^)]*args")),

    # ---------------------------------------------------------------- HTTP Parameter Pollution
    Rule("HPP-001", "HTTP Parameter Pollution", "MEDIUM",
         "Leitura de query string sem uso de middleware de proteção contra HTTP Parameter Pollution.",
         "Usar biblioteca como 'hpp' (Node) para normalizar parâmetros duplicados, ou validar explicitamente arrays.",
         _r(r"req\.query\[['\"]?\w+['\"]?\]")),

    # ---------------------------------------------------------------- Headless Browser
    Rule("HDLS-001", "Headless Browser", "MEDIUM",
         "Uso de Puppeteer/Playwright/Selenium renderizando URL/HTML potencialmente controlado pelo usuário (risco de SSRF/XSS server-side).",
         "Restringir URLs permitidas (allowlist), desabilitar acesso a rede interna e sandboxing do navegador headless.",
         _r(r"(puppeteer\.launch|playwright\.(chromium|firefox|webkit)|new\s+Builder\(\)\.forBrowser)")),

    # ---------------------------------------------------------------- Hidden Parameters
    Rule("HIDP-001", "Hidden Parameters", "LOW",
         "Campo de formulário do tipo hidden que pode carregar dados sensíveis/controle de lógica de negócio.",
         "Nunca confiar em campos hidden para controle de autorização/preço; validar sempre no backend.",
         _r(r"<input[^>]*type\s*=\s*['\"]hidden['\"]", re.IGNORECASE),
         extensions=[".html", ".htm", ".php", ".jsx", ".tsx"]),

    # ---------------------------------------------------------------- Insecure Deserialization
    Rule("DESER-001", "Insecure Deserialization", "CRITICAL",
         "Desserialização de dados potencialmente não confiáveis (pickle/yaml.load/unserialize/ObjectInputStream).",
         "Usar formatos seguros (JSON) ou desserializadores restritos (yaml.safe_load, allowlist de classes); "
         "nunca desserializar dados de entrada não confiáveis diretamente.",
         _r(r"(pickle\.loads?|yaml\.load\((?!.*Loader=yaml\.SafeLoader)|unserialize\s*\(|"
            r"ObjectInputStream|readObject\s*\(|Marshal\.load)")),

    # ---------------------------------------------------------------- Insecure Direct Object References
    Rule("IDOR-001", "Insecure Direct Object References", "HIGH",
         "Busca de recurso por ID vindo diretamente da requisição sem checagem aparente de propriedade/autorização.",
         "Validar que o usuário autenticado tem permissão sobre o recurso (ex.: WHERE id = ? AND user_id = ?).",
         _r(r"(find(ById)?|findOne|get)\s*\(\s*(req\.params\.id|request\.params\.id|params\[['\"]id['\"]\])\s*\)")),

    # ---------------------------------------------------------------- Insecure Management Interface
    Rule("MGMT-001", "Insecure Management Interface", "HIGH",
         "Referência a painel administrativo/management (actuator, phpmyadmin, adminer, django admin) possivelmente exposto.",
         "Restringir acesso a interfaces administrativas por rede interna/VPN e autenticação forte (MFA).",
         _r(r"(phpmyadmin|adminer\.php|/actuator(/|$)|django-admin|wp-admin|/console(/|$))", re.IGNORECASE)),

    # ---------------------------------------------------------------- Insecure Randomness
    Rule("RAND-001", "Insecure Randomness", "HIGH",
         "Uso de gerador de números pseudoaleatórios não criptográfico (Math.random/random.random/rand()) em contexto de segurança.",
         "Usar geradores criptograficamente seguros: crypto.randomBytes (Node), secrets (Python), SecureRandom (Java).",
         _r(r"(Math\.random\(\)|random\.random\(\)|(?<!s)rand\(\)|mt_rand\()")),

    # ---------------------------------------------------------------- Insecure Source Code Management
    Rule("SCM-001", "Insecure Source Code Management", "HIGH",
         "Arquivo .env/.git/.svn/.htpasswd presente na raiz do projeto ou de um diretório publicável (webroot).",
         "Nunca versionar .env com segredos reais; garantir que .git/.svn não fiquem acessíveis via webserver.",
         _r(r"^\.(env|git-credentials|htpasswd)$", re.IGNORECASE)),

    # ---------------------------------------------------------------- JSON Web Token
    Rule("JWT-001", "JSON Web Token", "CRITICAL",
         "Verificação de JWT aceitando algoritmo 'none' ou sem especificar algoritmos permitidos (risco de alg confusion).",
         "Especificar explicitamente os algoritmos permitidos (ex.: algorithms: ['RS256']) e nunca aceitar 'none'.",
         _r(r"(algorithms?\s*[:=]\s*\[?\s*['\"]none['\"]|jwt\.decode\([^)]*verify\s*=\s*False)")),
    Rule("JWT-002", "JSON Web Token", "HIGH",
         "Segredo de assinatura JWT hardcoded/curto no código-fonte.",
         "Usar segredo forte (>= 256 bits) armazenado fora do código-fonte (variável de ambiente/secret manager).",
         _r(r"jwt\.sign\s*\([^)]*,\s*['\"][^'\"]{1,20}['\"]")),

    # ---------------------------------------------------------------- Java RMI
    Rule("RMI-001", "Java RMI", "HIGH",
         "Uso de Java RMI (Registry/UnicastRemoteObject) — superfície de ataque para desserialização remota.",
         "Restringir RMI à rede interna, usar RMI SSL Socket Factory e manter JDK/patches de desserialização atualizados.",
         _r(r"(java\.rmi\.registry|UnicastRemoteObject|LocateRegistry)")),

    # ---------------------------------------------------------------- LDAP Injection
    Rule("LDAPI-001", "LDAP Injection", "CRITICAL",
         "Construção de filtro LDAP concatenando entrada do usuário diretamente na string de busca.",
         "Usar bibliotecas com escaping de filtro LDAP (ex.: ldap3 escape_filter_chars) e nunca concatenar entrada bruta.",
         _r(r"(search\s*\(|LdapContext|DirContext)[^\n]*['\"]\s*\+\s*(req|user|input|params)")),

    # ---------------------------------------------------------------- LaTeX Injection
    Rule("LATEX-001", "LaTeX Injection", "HIGH",
         "Geração de documento LaTeX/PDF a partir de entrada do usuário sem escapar comandos especiais (\\input, \\write18).",
         "Escapar caracteres especiais do LaTeX e desabilitar shell-escape (\\write18) ao compilar documentos de usuários.",
         _r(r"(pdflatex|xelatex|latexmk)\s")),

    # ---------------------------------------------------------------- Mass Assignment
    Rule("MASS-001", "Mass Assignment", "HIGH",
         "Criação/atualização de modelo usando diretamente o corpo da requisição inteiro (mass assignment).",
         "Usar allowlist explícita de campos permitidos (DTO/serializer) em vez de repassar req.body diretamente.",
         _r(r"\.(create|update|save)\s*\(\s*(req\.body|request\.body|\*\*request\.form|\$request->all\(\))")),

    # ---------------------------------------------------------------- Methodology and Resources
    # Categoria informativa — sem detecção automática (ver manual_review.py)

    # ---------------------------------------------------------------- NoSQL Injection
    Rule("NOSQLI-001", "NoSQL Injection", "CRITICAL",
         "Query MongoDB/NoSQL construída com objeto derivado diretamente da entrada do usuário (operator injection: $where, $ne, $gt).",
         "Validar/tipar entrada, usar $eq explícito e bibliotecas de sanitização (ex.: mongo-sanitize).",
         _r(r"(find|findOne|update|deleteMany)\s*\(\s*(req\.body|req\.query|req\.params)")),

    # ---------------------------------------------------------------- OAuth Misconfiguration
    Rule("OAUTH-001", "OAuth Misconfiguration", "HIGH",
         "Configuração OAuth com redirect_uri não validado contra allowlist ou uso de response_type inseguro (token implícito).",
         "Validar redirect_uri contra allowlist exata registrada; preferir Authorization Code + PKCE ao invés de Implicit Flow.",
         _r(r"(response_type\s*=\s*['\"]?token['\"]?|redirect_uri\s*[:=]\s*(req\.|request\.|params\.))")),

    # ---------------------------------------------------------------- ORM Leak
    Rule("ORM-001", "ORM Leak", "MEDIUM",
         "Serialização de objeto de modelo ORM inteiro na resposta (toJSON/toDict sem allowlist), pode vazar campos sensíveis.",
         "Definir explicitamente quais campos são serializados na resposta (DTO/serializer), nunca o modelo inteiro.",
         _r(r"(res\.json\(\s*(user|account|customer)\s*\)|JsonResponse\(model_to_dict\()")),

    # ---------------------------------------------------------------- Open Redirect
    Rule("REDIR-001", "Open Redirect", "HIGH",
         "Redirecionamento HTTP usando parâmetro controlado pelo usuário sem validação de allowlist.",
         "Validar o destino do redirecionamento contra uma allowlist de paths/domínios internos.",
         _r(r"(redirect|location\.href|window\.location)\s*[=(]\s*[^;)\n]*"
            r"(req\.query|req\.params|request\.GET|params\.get)")),

    # ---------------------------------------------------------------- Prompt Injection
    Rule("PROMPT-001", "Prompt Injection", "HIGH",
         "Entrada do usuário concatenada diretamente em prompt enviado a um LLM, sem delimitação/sanitização.",
         "Separar instruções do sistema de dados do usuário (delimitadores, templates estruturados), validar/filtrar "
         "saídas do modelo antes de executar ações sensíveis, e nunca dar ao LLM permissão irrestrita de tool-use.",
         _r(r"(messages\s*[:=]\s*\[|prompt\s*[:=]\s*[`'\"])[^\n]*\+\s*(req\.|request\.|input|user)")),

    # ---------------------------------------------------------------- Prototype Pollution
    Rule("PROTO-001", "Prototype Pollution", "CRITICAL",
         "Merge/extend/clone recursivo de objeto usando chaves controladas pelo usuário (__proto__, constructor, prototype).",
         "Usar Object.create(null), bloquear chaves __proto__/constructor/prototype em merges, ou bibliotecas atualizadas "
         "(lodash >= 4.17.21) que já mitigam prototype pollution.",
         _r(r"(_\.merge|_\.extend|\$\.extend|deepmerge|Object\.assign)\s*\([^)]*"
            r"(req\.body|request\.body|JSON\.parse)")),

    # ---------------------------------------------------------------- Race Condition
    Rule("RACE-001", "Race Condition", "MEDIUM",
         "Padrão check-then-act (verificar saldo/estoque e depois atualizar) sem indício de transação/lock atômico.",
         "Usar transações com isolamento adequado, operações atômicas (ex.: UPDATE ... WHERE saldo >= valor) ou locks distribuídos.",
         _r(r"(if\s*\([^)]*(balance|saldo|stock|estoque)[^)]*>)[^\n]{0,200}(update|save)\s*\(", re.DOTALL)),

    # ---------------------------------------------------------------- Regular Expression (ReDoS) — ver DOS-002

    # ---------------------------------------------------------------- Request Smuggling
    Rule("SMUG-001", "Request Smuggling", "MEDIUM",
         "Manipulação manual dos headers Content-Length/Transfer-Encoding, risco de HTTP Request Smuggling se houver proxy na frente.",
         "Garantir que proxy e backend usem a mesma implementação/versão HTTP e não permitam Content-Length e "
         "Transfer-Encoding simultâneos ambíguos.",
         _r(r"(transfer-encoding['\"]?\s*[:,]\s*['\"]chunked['\"].*content-length)", re.DOTALL)),

    # ---------------------------------------------------------------- Reverse Proxy Misconfigurations
    Rule("PROXY-001", "Reverse Proxy Misconfigurations", "MEDIUM",
         "Configuração Nginx/Apache com proxy_pass genérico ou sem restrição de métodos/headers sensíveis.",
         "Restringir proxy_pass a paths específicos, remover/filtrar headers internos (X-Forwarded-*) não confiáveis.",
         _r(r"proxy_pass\s+http"), extensions=[".conf", ".config"]),
    Rule("PROXY-002", "Reverse Proxy Misconfigurations", "LOW",
         "trust proxy habilitado de forma ampla (true) — pode permitir spoofing de X-Forwarded-For.",
         "Configurar 'trust proxy' com o número exato de saltos de proxy confiáveis, não 'true'.",
         _r(r"trust\s*proxy['\"]?\s*,\s*true")),

    # ---------------------------------------------------------------- SAML Injection
    Rule("SAML-001", "SAML Injection", "CRITICAL",
         "Processamento de resposta SAML sem indício de validação de assinatura (signature) antes do parsing.",
         "Sempre validar a assinatura XML do SAMLResponse contra o certificado do IdP antes de processar o conteúdo, "
         "e proteger contra XML Signature Wrapping.",
         _r(r"(saml.*parse|parseSamlResponse|SamlResponse)\s*\(", re.IGNORECASE)),

    # ---------------------------------------------------------------- SQL Injection
    Rule("SQLI-001", "SQL Injection", "CRITICAL",
         "Query SQL construída por concatenação/f-string/template literal com entrada potencialmente controlada pelo usuário.",
         "Usar sempre queries parametrizadas/prepared statements (nunca concatenar strings em SQL).",
         _r(r"(SELECT|INSERT|UPDATE|DELETE)\b[^\n]*['\"`]\s*\+"
            r"|f['\"](SELECT|INSERT|UPDATE|DELETE)[^'\"]*\{"
            r"|execute\s*\(\s*['\"`](SELECT|INSERT|UPDATE|DELETE)[^'\"`]*['\"`]\s*%")),
    Rule("SQLI-002", "SQL Injection", "CRITICAL",
         "Uso de query template literal com interpolação direta ${...} em comando SQL.",
         "Substituir por placeholders parametrizados (?, $1, :param) e passar valores separadamente.",
         _r(r"[`'\"](SELECT|INSERT|UPDATE|DELETE)[^`'\"]*\$\{")),

    # ---------------------------------------------------------------- Server Side Include Injection
    Rule("SSI-001", "Server Side Include Injection", "HIGH",
         "Diretiva SSI (<!--#exec/include-->) presente ou geração dinâmica de .shtml a partir de entrada do usuário.",
         "Desabilitar SSI em diretórios que aceitam upload/entrada de usuário, ou sanitizar rigorosamente o conteúdo.",
         _r(r"<!--#\s*(exec|include|echo)\b")),

    # ---------------------------------------------------------------- Server Side Request Forgery
    Rule("SSRF-001", "Server Side Request Forgery", "CRITICAL",
         "Requisição HTTP no servidor (fetch/requests/curl/urlopen) usando URL/host controlado pela entrada do usuário.",
         "Validar destino contra allowlist de hosts/IPs, bloquear ranges internos (RFC1918, 169.254.169.254) e "
         "desabilitar redirects automáticos para hosts não confiáveis.",
         _r(r"(requests\.(get|post)|urllib\.request\.urlopen|axios\.(get|post)|fetch)\s*\(\s*"
            r"(req\.|request\.|params\.|query\.|input)")),

    # ---------------------------------------------------------------- Server Side Template Injection
    Rule("SSTI-001", "Server Side Template Injection", "CRITICAL",
         "Renderização de template a partir de string construída com entrada do usuário (render_template_string, "
         "Template(), Jinja2/Twig/Handlebars dinâmico).",
         "Nunca passar entrada do usuário como template a ser compilado; usar apenas como dado (contexto), "
         "não como código de template.",
         _r(r"(render_template_string|Template\s*\(\s*(req\.|request\.|input)|"
            r"\.render\s*\(\s*(req\.body|request\.body))")),

    # ---------------------------------------------------------------- Tabnabbing
    Rule("TABN-001", "Tabnabbing", "LOW",
         "Link com target=\"_blank\" sem rel=\"noopener noreferrer\" — permite reverse tabnabbing.",
         "Adicionar rel=\"noopener noreferrer\" em todo link/target=_blank apontando para destino externo.",
         _r(r"target\s*=\s*['\"]_blank['\"](?![^>]*noopener)", re.IGNORECASE),
         extensions=[".html", ".htm", ".jsx", ".tsx", ".vue"]),

    # ---------------------------------------------------------------- Type Juggling
    Rule("TYPEJ-001", "Type Juggling", "MEDIUM",
         "Comparação PHP com == (loose comparison) envolvendo hash/senha/token — vulnerável a type juggling.",
         "Usar comparação estrita (===) ou hash_equals() para comparar hashes, senhas e tokens em PHP.",
         _r(r"(md5|sha1|hash|password)\([^)]*\)\s*==\s*\$")),

    # ---------------------------------------------------------------- Upload Insecure Files
    Rule("UPLOAD-001", "Upload Insecure Files", "CRITICAL",
         "Manipulação de upload de arquivo sem validação aparente de extensão/tipo MIME antes de salvar.",
         "Validar extensão E tipo MIME real (magic bytes), renomear arquivo, armazenar fora do webroot executável "
         "e limitar tamanho.",
         _r(r"(multer\s*\(\s*\{[^}]*dest|move_uploaded_file|\.save\s*\(\s*(upload_path|UPLOAD_FOLDER))")),

    # ---------------------------------------------------------------- Virtual Hosts
    Rule("VHOST-001", "Virtual Hosts", "LOW",
         "Configuração server_name/VirtualHost com wildcard amplo (_ ou *), pode expor vhost padrão indevidamente.",
         "Definir server_name/ServerName explícitos por vhost e configurar um vhost 'catch-all' que recuse a conexão.",
         _r(r"(server_name\s+_\s*;|ServerName\s+\*)"), extensions=[".conf", ".config"]),

    # ---------------------------------------------------------------- Web Cache Deception
    Rule("WCD-001", "Web Cache Deception", "MEDIUM",
         "Regra de cache baseada apenas na extensão do path (ex.: .css/.js) sem considerar a rota real autenticada.",
         "Configurar cache apenas para paths estáticos reais; normalizar path antes de decidir cache "
         "e nunca cachear respostas de rotas autenticadas por extensão aparente.",
         _r(r"location\s*~\*?\s*\\\.[\(a-z|]*\b(css|js|jpg|png)\b", re.IGNORECASE),
         extensions=[".conf", ".config"]),

    # ---------------------------------------------------------------- Web Sockets
    Rule("WS-001", "Web Sockets", "MEDIUM",
         "Servidor WebSocket sem validação aparente do header Origin no handshake de conexão.",
         "Validar o header Origin contra allowlist no evento de conexão/handshake do WebSocket.",
         _r(r"(new\s+WebSocket\.Server|io\.on\s*\(\s*['\"]connection['\"])")),

    # ---------------------------------------------------------------- XPATH Injection
    Rule("XPATHI-001", "XPATH Injection", "CRITICAL",
         "Expressão XPath construída por concatenação com entrada do usuário.",
         "Usar XPath parametrizado (XPathExpression com variáveis) ou validar/escapar rigorosamente a entrada.",
         _r(r"(evaluate|selectNodes|selectSingleNode)\s*\([^\n]*['\"`]\s*\+")),

    # ---------------------------------------------------------------- XS-Leak
    Rule("XSLEAK-001", "XS-Leak", "LOW",
         "Resposta condicional (status/tamanho diferente) baseada em estado de autenticação sem X-Frame-Options/CSP "
         "que impeça embutir em iframe cross-site.",
         "Aplicar Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy e frame-ancestors para reduzir XS-Leaks.",
         _r(r"Cross-Origin-(Opener|Resource)-Policy")),

    # ---------------------------------------------------------------- XSLT Injection
    Rule("XSLT-001", "XSLT Injection", "CRITICAL",
         "Transformação XSLT aplicada sobre folha de estilo controlada pelo usuário (risco de RCE via extensões XSLT).",
         "Nunca aceitar XSL de fontes não confiáveis; desabilitar extensões PHP/Java no processador XSLT.",
         _r(r"(XsltArgumentList|xsltprocessor|Xslt.*Transform\s*\()", re.IGNORECASE)),

    # ---------------------------------------------------------------- XSS Injection
    Rule("XSS-001", "XSS Injection", "CRITICAL",
         "Escrita direta de HTML no DOM a partir de dados dinâmicos (innerHTML/dangerouslySetInnerHTML/document.write) "
         "sem sanitização aparente.",
         "Usar textContent/APIs seguras, ou sanitizar com DOMPurify antes de inserir HTML dinâmico.",
         _r(r"(innerHTML\s*=(?!=)|dangerouslySetInnerHTML|document\.write\s*\(|v-html\s*=)")),
    Rule("XSS-002", "XSS Injection", "HIGH",
         "Saída de template server-side com autoescape desabilitado (|safe, {!! !!}, {% autoescape false %}).",
         "Evitar desabilitar autoescaping; se necessário, sanitizar explicitamente o conteúdo antes de marcar como seguro.",
         _r(r"(\|\s*safe\b|\{!!.*!!\}|autoescape\s+false)")),

    # ---------------------------------------------------------------- XXE Injection
    Rule("XXE-001", "XXE Injection", "CRITICAL",
         "Parser XML sem desabilitar explicitamente DTDs/entidades externas — vulnerável a XXE.",
         "Desabilitar DOCTYPE/entidades externas no parser (ex.: defusedxml, "
         "setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)).",
         _r(r"(lxml\.etree\.parse|xml\.etree\.ElementTree\.parse|DocumentBuilderFactory|"
            r"XMLReader|libxml_disable_entity_loader\(false\))")),

    # ---------------------------------------------------------------- Zip Slip
    Rule("ZIPSLIP-001", "Zip Slip", "CRITICAL",
         "Extração de arquivo ZIP/TAR sem validar que o path de cada entrada permanece dentro do diretório de destino.",
         "Validar/normalizar o path de cada entrada extraída (resolve() e checar prefixo do destino) antes de gravar; "
         "rejeitar entradas com '..'.",
         _r(r"(zipfile\.ZipFile\([^)]*\)\.extractall|"
            r"\.extractall\s*\((?!.*members)|"
            r"unzip\s*\(|new\s+AdmZip\([^)]*\)\.extractAllTo)")),
]


# Categorias que exigem revisão manual/testes dinâmicos — não são
# confiavelmente detectáveis por análise estática de padrões (SAST).
MANUAL_REVIEW_CATEGORIES = [
    ("Business Logic Errors", "HIGH",
     "Fluxos de negócio (descontos, limites, estados de pedido/etapas de checkout, permissões condicionais) "
     "exigem modelagem da regra de negócio real. Revisar manualmente fluxos críticos e cobrir com testes de abuso "
     "(pular etapas, repetir ações, alterar ordem de chamadas)."),
    ("CVE Exploits", "HIGH",
     "Verificar automaticamente via SCA/dependency scanner (ver seção 'Dependências' do relatório) e manter "
     "processo de patch management. Considerar rodar 'npm audit', 'pip-audit', 'safety' ou Trivy/Grype no CI."),
    ("Dependency Confusion", "HIGH",
     "Ver seção 'Dependências'. Confirmar manualmente que todos os pacotes internos/privados estão publicados em "
     "um registry privado com escopo reservado, e que o build não pode resolver acidentalmente um pacote público "
     "de mesmo nome."),
    ("Denial of Service", "MEDIUM",
     "Além dos padrões de ReDoS/limite de upload detectados, avaliar manualmente algoritmos com complexidade "
     "não-linear sobre entrada do usuário e ausência de timeouts/circuit breakers em chamadas externas."),
    ("Encoding Transformations", "LOW",
     "Revisar manualmente pontos onde múltiplas camadas de decodificação (URL, HTML, Unicode) podem ser exploradas "
     "para bypass de filtros de segurança (double encoding)."),
    ("Insecure Management Interface", "HIGH",
     "Confirmar manualmente (via varredura de portas/rotas) que interfaces administrativas detectadas exigem "
     "autenticação forte e não estão expostas à internet pública."),
    ("Methodology and Resources", "INFO",
     "Item de referência metodológica (não é uma classe de vulnerabilidade). Use como checklist de cobertura de "
     "teste manual/pentest complementando este SAST."),
    ("Race Condition", "MEDIUM",
     "Testar manualmente (ou com ferramentas de concorrência, ex.: Turbo Intruder) endpoints financeiros/de "
     "estoque/limite de uso único disparando requisições em paralelo."),
    ("Regular Expression", "MEDIUM",
     "Além do padrão de ReDoS detectado automaticamente, revisar manualmente regexes complexas usadas em validação "
     "de segurança (ex.: validação de e-mail/URL) quanto a bypass."),
    ("Virtual Hosts", "LOW",
     "Revisar manualmente a configuração completa do webserver/DNS quanto a vhosts esquecidos, subdomínios "
     "expostos e certificados wildcard mal escopados."),
    ("Web Cache Deception", "MEDIUM",
     "Testar manualmente rotas autenticadas com sufixos de extensão estática (ex.: /perfil/.css) contra o CDN/cache "
     "em uso."),
    ("XS-Leak", "LOW",
     "Testar manualmente vazamento de estado via timing, tamanho de frame, contagem de erros e "
     "postMessage/window.opener em fluxos autenticados."),
    ("Reverse Proxy Misconfigurations", "MEDIUM",
     "Além dos padrões de configuração detectados, testar manualmente discrepâncias de parsing HTTP entre proxy "
     "e backend (uso de ferramentas como smuggler.py)."),
]
