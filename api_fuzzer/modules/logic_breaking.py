import asyncio
from typing import Any, Dict, List
from api_fuzzer.core.parser import Endpoint
from api_fuzzer.core.client import PlaywrightClient
from api_fuzzer.modules.base import BaseSecurityModule
from api_fuzzer.utils.payloads import LOGIC_BREAKING_PAYLOADS

class LogicBreakingModule(BaseSecurityModule):
    @property
    def name(self) -> str:
        return "Logic & Input Validation Fuzzing"

    @property
    def description(self) -> str:
        return "Injeta payloads malformados ou de quebra de lógica nos parâmetros para induzir erros de servidor (HTTP 500) ou vazamento de dados."

    async def run_test(
        self, 
        client: PlaywrightClient, 
        endpoints: List[Endpoint]
    ) -> List[Dict[str, Any]]:
        findings = []

        for endpoint in endpoints:
            # We will test fuzzing on query parameters
            query_params = [p for p in endpoint.parameters if p.in_ == "query"]
            if not query_params:
                continue

            for param in query_params:
                for payload in LOGIC_BREAKING_PAYLOADS:
                    # Construct default query dictionary and override the target parameter with payload
                    test_params = {}
                    for p in endpoint.parameters:
                        if p.in_ == "query":
                            test_params[p.name] = payload if p.name == param.name else (p.default or "test")

                    # Handle path values safely
                    url_path = endpoint.path
                    for p in endpoint.parameters:
                        if p.in_ == "path":
                            url_path = url_path.replace(f"{{{p.name}}}", str(p.default or "1"))

                    status, headers, text = await client.send_request(
                        method=endpoint.method,
                        url=url_path,
                        params=test_params
                    )

                    # Vulnerability Indicators:
                    # 1. HTTP 500 (Unhandled Server Crash)
                    # 2. Database leak signatures in response text
                    db_errors = ["sql syntax", "mysql_fetch", "sqlite3", "postgresql", "unhandled exception", "stack trace"]
                    has_db_leak = any(db_err in text.lower() for db_err in db_errors)

                    if status == 500 or has_db_leak:
                        severity = "Alto" if has_db_leak else "Baixo"
                        desc_detail = (
                            f"Vazamento de erro de banco de dados/stack trace" if has_db_leak
                            else "Erro interno de servidor (HTTP 500) não tratado"
                        )
                        
                        findings.append({
                            "module": self.name,
                            "endpoint": f"{endpoint.method} {endpoint.path}",
                            "severity": severity,
                            "description": f"{desc_detail} ao injetar no parâmetro '{param.name}'.",
                            "details": {
                                "parameter": param.name,
                                "payload_used": str(payload),
                                "response_status": status,
                                "response_snippet": text[:250],
                                "recommendation": "Implementar validação estrita do tipo e sanitização do input (input validation) no backend. Nunca expor stack traces ou erros brutos do banco de dados na resposta."
                            }
                        })
                        break # Check next parameter to avoid massive redundant alerts

        return findings
