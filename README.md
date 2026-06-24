# 🛡️ API Attack Simulator & Security Fuzzer

Um simulador de ataques e fuzzer automatizado de APIs robusto e modular escrito em **Python** e **Playwright**. Projetado para profissionais de AppSec e desenvolvedores que buscam validar a resiliência de seus endpoints contra vulnerabilidades clássicas descritas no OWASP API Security Top 10.

---

## 🚀 Funcionalidades Atuais

- **Mapeamento de Rotas Automático**: Analisa especificações OpenAPI/Swagger (JSON/YAML), resolvendo recursivamente referências `$ref` e estruturando parâmetros de rota, query e bodies.
- **Playwright HTTP Engine**: Emprega o `APIRequestContext` do Playwright para disparar requisições de forma assíncrona, simulando o comportamento de clientes legítimos de navegador.
- **Módulos de Varredura Embutidos**:
  - **Falta de Rate Limiting**: Dispara rajadas concorrentes de requisições buscando verificar se o servidor bloqueia requisições abusivas com o status `429 Too Many Requests`.
  - **IDOR (Insecure Direct Object Reference)**: Identifica parâmetros dinâmicos de rota (como IDs ou UUIDs) e adultera seus valores para verificar se o servidor expõe dados restritos sem validação apropriada (HTTP 200).
  - **Logic & Input Breaking Fuzzing**: Injeta payloads clássicos de escape (aspas, SQLi, injeção de comandos, recursividade) e monitora a ocorrência de erros internos não tratados (HTTP 500) ou vazamentos brutos de stack traces.
  - **Mutador Dinâmico de Body JSON**: Reconhece esquemas de body esperados nas rotas POST/PUT e injeta cirurgicamente os payloads de ataque, chave-a-chave, de forma recursiva em estruturas profundas.
- **Relatório Premium Interativo**: Geração de relatórios completos em formato estruturado (JSON) e formato visual premium em HTML, contendo dados detalhados das falhas e orientações de remediação.

---

## 📁 Estrutura do Projeto

```
api_fuzzer/
├── core/
│   ├── parser.py       # Conversor de OpenAPI para objetos de teste
│   ├── client.py       # Gerenciador de requisições Playwright
│   ├── runner.py       # Orquestrador assíncrono de varredura
│   └── reporter.py     # Gerador de relatórios JSON/HTML premium
├── modules/
│   ├── base.py         # Classe abstrata para novos módulos
│   ├── rate_limit.py   # Módulo de testes de taxa limite
│   ├── idor.py         # Módulo de verificação de IDOR
│   └── logic_breaking.py# Fuzzer de injeções e erros não tratados
└── utils/
    └── payloads.py     # Base de dicionários de fuzzing e ataques
```

---

## 🛠️ Instalação e Execução

### Pré-requisitos
- Python 3.8 ou superior
- Pip (gerenciador de pacotes)

### Passos
1. Instale as dependências listadas no `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```
2. Instale o driver do navegador Chromium para o Playwright:
   ```bash
   playwright install chromium
   ```

### Executando a Varredura (Modo Padrão)
Para testar a ferramenta contra uma documentação local e uma API alvo:
```bash
python api_fuzzer/main.py --spec mock_openapi.json --target http://localhost:8000
```

*Nota: Você também pode usar múltiplos cabeçalhos adicionais de autenticação manual, ex:*
```bash
python api_fuzzer/main.py --spec mock_openapi.json --target http://localhost:8000 --header "Authorization: Bearer <SEU_TOKEN>"
```

### 🔒 Autenticação Dinâmica Automatizada (Playwright)
Se a sua API exige login e os tokens expiram rapidamente, o fuzzer pode simular um navegador e fazer o login por você! Ele intercepta a rede e embute o token/cookie capturado nas requisições:
```bash
python api_fuzzer/main.py \
  --spec mock_openapi.json \
  --target http://localhost:8000 \
  --auth-url http://localhost:8000/login \
  --auth-user seu_usuario \
  --auth-pass sua_senha \
  --auth-type bearer
```

---

### 🖥️ Painel de Controle Web Interativo (Dashboard)
Agora você pode gerenciar as varreduras, visualizar logs em tempo real e analisar relatórios gráficos interativos a partir do navegador sem utilizar a linha de comando!

- **NOVIDADE:** Importe especificações OpenAPI diretamente de uma URL no Dashboard, sem precisar baixar o arquivo JSON manualmente!

Para iniciar o Painel de Controle Web:
```bash
python web_app.py
```
Acesse no seu navegador: **`http://localhost:8080`**

---

## 📊 Relatórios de Saída
- **`report.json`**: Formato ideal para consumo em pipelines de CI/CD ou integração com outras ferramentas de segurança.
- **`report.html`**: Painel moderno em dark mode com estatísticas interativas dos problemas de segurança descobertos e as recomendações de mitigação.

---

## 🔒 Hardening de Segurança (Dashboard Web)
Para garantir que a aplicação esteja preparada para ambientes de produção e prevenir vazamento de dados ou acessos indevidos, foram aplicadas as seguintes medidas de segurança:
- **Proteção de Código-Fonte e Source Maps**: Bloqueio de requisições a arquivos `.map`, `.ts`, `.tsx`, `.jsx`, `.vue` e `.svelte` para impedir a exposição da estrutura interna do frontend.
- **CORS Restrito**: Política de Cross-Origin compartilhada restrita apenas às origens locais seguras da aplicação para evitar conexões e requisições não autorizadas por domínios terceiros.
- **Content Security Policy (CSP)**: Cabeçalhos HTTP robustos restringindo a execução de scripts e conexões apenas a origens mapeadas e seguras, mitigando riscos de XSS.
- **Segurança de Sessão**: Nenhum token, credencial de login ou dado sensível é persistido no `localStorage` ou `sessionStorage` do navegador.
- **Headers de Segurança Complementares**: Inclusão de `X-Content-Type-Options: nosniff` (proteção de MIME types), `X-Frame-Options: DENY` (prevenção contra Clickjacking) e `Referrer-Policy: strict-origin-when-cross-origin`.
- **Preparações para Variáveis de Produção**: Pronto para integração com plataformas como Vercel/Render através de variáveis de ambiente do sistema (`os.environ`), eliminando qualquer segredo hardcoded no repositório.
