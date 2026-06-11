import asyncio
from typing import Any, Dict, List
from api_fuzzer.core.parser import Endpoint
from api_fuzzer.core.client import PlaywrightClient
from api_fuzzer.modules.base import BaseSecurityModule
from api_fuzzer.utils.payloads import LOGIC_BREAKING_PAYLOADS
from api_fuzzer.utils.mutator import generate_default_body, mutate_payload

class LogicBreakingModule(BaseSecurityModule):
    @property
    def name(self) -> str:
        return "Logic & Input Validation Fuzzing"

    @property
    def description(self) -> str:
        return "Injeta payloads malformados ou de quebra de lógica nos parâmetros e no corpo JSON para induzir erros de servidor (HTTP 500) ou vazamento de dados."

    async def _check_vulnerability(self, status: int, text: str, endpoint: Endpoint, param_name: str, payload: Any) -> Optional[Dict[str, Any]]:
        db_errors = ["sql syntax", "mysql_fetch", "sqlite3", "postgresql", "unhandled exception", "stack trace"]
        has_db_leak = any(db_err in text.lower() for db_err in db_errors)

        if status == 500 or has_db_leak:
            severity = "Alto" if has_db_leak else "Baixo"
            desc_detail = (
                f"Vazamento de erro de banco de dados/stack trace" if has_db_leak
                else "Erro interno de servidor (HTTP 500) não tratado"
            )
            
            return {
                "module": self.name,
                "endpoint": f"{endpoint.method} {endpoint.path}",
                "severity": severity,
                "description": f"{desc_detail} ao injetar na propriedade '{param_name}'.",
                "details": {
                    "parameter": param_name,
                    "payload_used": str(payload),
                    "response_status": status,
                    "response_snippet": text[:250],
                    "recommendation": "Implementar validação estrita do tipo e sanitização do input (input validation) no backend. Nunca expor stack traces ou erros brutos do banco de dados na resposta."
                }
            }
        return None

    async def run_test(
        self, 
        client: PlaywrightClient, 
        endpoints: List[Endpoint]
    ) -> List[Dict[str, Any]]:
        findings = []

        for endpoint in endpoints:
            # Handle path values safely
            url_path = endpoint.path
            for p in endpoint.parameters:
                if p.in_ == "path":
                    url_path = url_path.replace(f"{{{p.name}}}", str(p.default or "1"))

            # 1. Test Fuzzing on Query Parameters
            query_params = [p for p in endpoint.parameters if p.in_ == "query"]
            for param in query_params:
                for payload in LOGIC_BREAKING_PAYLOADS:
                    test_params = {}
                    for p in endpoint.parameters:
                        if p.in_ == "query":
                            test_params[p.name] = payload if p.name == param.name else (p.default or "test")

                    status, headers, text = await client.send_request(
                        method=endpoint.method,
                        url=url_path,
                        params=test_params
                    )

                    finding = await self._check_vulnerability(status, text, endpoint, f"query:{param.name}", payload)
                    if finding:
                        findings.append(finding)
                        break

            # 2. Test Fuzzing on JSON Body
            if endpoint.body_schema:
                base_body = generate_default_body(endpoint.body_schema)
                for mutated_path, payload, mutated_body in mutate_payload(base_body, LOGIC_BREAKING_PAYLOADS):
                    status, headers, text = await client.send_request(
                        method=endpoint.method,
                        url=url_path,
                        json_data=mutated_body
                    )

                    finding = await self._check_vulnerability(status, text, endpoint, f"body:{mutated_path}", payload)
                    if finding:
                        findings.append(finding)
                        break

        return findings
