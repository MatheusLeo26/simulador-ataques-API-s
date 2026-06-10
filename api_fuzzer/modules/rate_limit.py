import asyncio
from typing import Any, Dict, List
from api_fuzzer.core.parser import Endpoint
from api_fuzzer.core.client import PlaywrightClient
from api_fuzzer.modules.base import BaseSecurityModule

class RateLimitModule(BaseSecurityModule):
    @property
    def name(self) -> str:
        return "Falta de Rate Limiting"

    @property
    def description(self) -> str:
        return "Simula múltiplas requisições simultâneas para verificar se a API bloqueia abusos com HTTP 429."

    async def run_test(
        self, 
        client: PlaywrightClient, 
        endpoints: List[Endpoint]
    ) -> List[Dict[str, Any]]:
        findings = []
        burst_size = 20  # Number of fast concurrent requests

        for endpoint in endpoints:
            # We skip endpoints that are too risky or complex unless configured,
            # but for our fuzzer we will test all mapped endpoints.
            # To test Rate Limiting, we send a burst of requests to the endpoint path.
            # If path requires parameters, we inject dummy/default values.
            
            url_path = endpoint.path
            # Fill path parameters with simple default/dummy values for testing connectivity
            for param in endpoint.parameters:
                if param.in_ == "path":
                    placeholder = f"{{{param.name}}}"
                    dummy_val = param.default or "1"
                    url_path = url_path.replace(placeholder, str(dummy_val))

            # Build dummy query parameters
            query_params = {}
            for param in endpoint.parameters:
                if param.in_ == "query":
                    query_params[param.name] = param.default or "test"

            # Create body template if needed
            body = None
            if endpoint.body_schema:
                body = {} # simple empty json or could generate basic schema structure

            # Send burst of requests concurrently
            tasks = []
            for _ in range(burst_size):
                tasks.append(
                    client.send_request(
                        method=endpoint.method,
                        url=url_path,
                        params=query_params,
                        json_data=body
                    )
                )

            results = await asyncio.gather(*tasks, return_exceptions=True)

            status_codes = []
            failures = 0
            for r in results:
                if isinstance(r, tuple):
                    status_codes.append(r[0])
                else:
                    failures += 1

            # Check if rate limiting triggered (HTTP 429)
            rate_limited = any(status == 429 for status in status_codes)
            
            # If all or most requests succeeded with 2xx/3xx/4xx (excluding 429/connection issues)
            # and no 429 was seen, rate limiting is likely missing.
            successful_requests = [s for s in status_codes if 200 <= s < 300]
            
            if len(successful_requests) == burst_size and not rate_limited:
                findings.append({
                    "module": self.name,
                    "endpoint": f"{endpoint.method} {endpoint.path}",
                    "severity": "Médio",
                    "description": (
                        f"O endpoint não demonstrou limite de requisições. "
                        f"Enviadas {burst_size} requisições seguidas e todas responderam com sucesso."
                    ),
                    "details": {
                        "burst_size": burst_size,
                        "status_codes_received": status_codes,
                        "recommendation": "Implementar controle de taxa (Rate Limiting) usando regras de IP, API Key ou Tokens (ex: Redis Token Bucket)."
                    }
                })

        return findings
