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

### Executando a Varredura
Para testar a ferramenta contra uma documentação local e uma API alvo:
```bash
python api_fuzzer/main.py --spec mock_openapi.json --target http://localhost:8000
```

*Nota: Você também pode usar múltiplos cabeçalhos adicionais de autenticação, ex:*
```bash
python api_fuzzer/main.py --spec mock_openapi.json --target http://localhost:8000 --header "Authorization: Bearer <SEU_TOKEN>"
```

---

## 📊 Relatórios de Saída
- **`report.json`**: Formato ideal para consumo em pipelines de CI/CD ou integração com outras ferramentas de segurança.
- **`report.html`**: Painel moderno em dark mode com estatísticas interativas dos problemas de segurança descobertos e as recomendações de mitigação.
