import asyncio
from typing import Any, Dict, List, Optional
from api_fuzzer.core.parser import Endpoint
from api_fuzzer.core.client import PlaywrightClient
from api_fuzzer.modules.base import BaseSecurityModule
from api_fuzzer.utils.mutator import generate_default_body, mutate_payload_smart, get_smart_payloads

class LogicBreakingModule(BaseSecurityModule):
    @property
    def name(self) -> str:
        return "Smart Logic & Type-Based Fuzzing"

    @property
    def description(self) -> str:
        return "Injeta payloads inteligentes baseados no tipo do dado esperado (integer, string, boolean) no corpo JSON e nos parâmetros, buscando erros HTTP 500 ou vazamentos de banco de dados."

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
                    "payload_used": str(payload)[:100] + ("..." if len(str(payload)) > 100 else ""),
                    "response_status": status,
                    "response_snippet": text[:250],
                    "recommendation": "Implementar validação estrita de tipo, limite de tamanho e sanitização (input validation) no backend. Nunca expor erros brutos."
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
            url_path = endpoint.path
            for p in endpoint.parameters:
                if p.in_ == "path":
                    url_path = url_path.replace(f"{{{p.name}}}", str(p.default or "1"))

            # 1. Smart Fuzzing on Query Parameters
            query_params = [p for p in endpoint.parameters if p.in_ == "query"]
            for param in query_params:
                param_type = "string" # Default
                # Assuming param schema extraction could be improved in parser, but we fallback to string
                # If param objects have 'schema', we could extract it:
                if hasattr(param, "schema") and isinstance(param.schema, dict):
                    param_type = param.schema.get("type", "string")

                smart_payloads = get_smart_payloads(param_type)
                
                for payload in smart_payloads:
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

            # 2. Smart Fuzzing on JSON Body
            if endpoint.body_schema:
                base_body = generate_default_body(endpoint.body_schema)
                for mutated_path, payload, mutated_body in mutate_payload_smart(endpoint.body_schema, base_body):
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
