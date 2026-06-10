import asyncio
from typing import Any, Dict, List
from api_fuzzer.core.parser import Endpoint
from api_fuzzer.core.client import PlaywrightClient
from api_fuzzer.modules.base import BaseSecurityModule
from api_fuzzer.utils.payloads import IDOR_PATTERNS

class IDORModule(BaseSecurityModule):
    @property
    def name(self) -> str:
        return "Insecure Direct Object Reference (IDOR)"

    @property
    def description(self) -> str:
        return "Modifica parâmetros identificados como IDs nas rotas/parâmetros para validar se há exposição de dados sem autorização apropriada."

    async def run_test(
        self, 
        client: PlaywrightClient, 
        endpoints: List[Endpoint]
    ) -> List[Dict[str, Any]]:
        findings = []

        for endpoint in endpoints:
            # Look for path parameters or query parameters indicating potential IDs
            # Common names for resource identifiers
            id_keywords = ["id", "uuid", "user", "account", "order", "invoice", "file"]
            
            # Step 1: Detect path parameters that are IDs
            path_id_params = [
                p for p in endpoint.parameters 
                if p.in_ == "path" and any(kw in p.name.lower() for kw in id_keywords)
            ]
            
            # Step 2: Detect query parameters that are IDs
            query_id_params = [
                p for p in endpoint.parameters 
                if p.in_ == "query" and any(kw in p.name.lower() for kw in id_keywords)
            ]

            if not path_id_params and not query_id_params:
                continue

            # Let's test ID tampering
            # For each ID parameter found, we try to alter it
            for param in path_id_params:
                original_val = param.default or "2"  # assume base ID = 2 if not defined
                
                for pattern_fn in IDOR_PATTERNS:
                    tampered_val = pattern_fn(original_val)
                    if not tampered_val or tampered_val == str(original_val):
                        continue

                    # Construct URL path with tampered value
                    url_path = endpoint.path
                    for p in endpoint.parameters:
                        if p.in_ == "path":
                            val = tampered_val if p.name == param.name else (p.default or "1")
                            url_path = url_path.replace(f"{{{p.name}}}", str(val))

                    # Send request
                    status, headers, text = await client.send_request(
                        method=endpoint.method,
                        url=url_path,
                    )

                    # If request returns 200 and contains data (meaning it did not block or throw 403/401)
                    # it might be an IDOR vulnerability
                    if status == 200 and len(text) > 10:
                        # Simple heuristics check: response shouldn't be empty or an error message
                        # Verify it's not a generic error/not found screen
                        if "not found" not in text.lower() and "error" not in text.lower():
                            findings.append({
                                "module": self.name,
                                "endpoint": f"{endpoint.method} {endpoint.path}",
                                "severity": "Alto",
                                "description": (
                                    f"Possível IDOR no parâmetro de caminho '{param.name}'. "
                                    f"Substituição de '{original_val}' por '{tampered_val}' retornou HTTP 200."
                                ),
                                "details": {
                                    "parameter": param.name,
                                    "original_value": original_val,
                                    "tampered_value": tampered_val,
                                    "response_status": status,
                                    "response_snippet": text[:200],
                                    "recommendation": "Garantir controle de acesso baseado em nível de objeto (OBAC). Validar se o usuário autenticado tem permissão para visualizar o objeto requisitado."
                                }
                            })
                            break # report once per endpoint for this parameter type to avoid spam

        return findings
