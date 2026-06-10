import asyncio
from typing import Any, Dict, List, Optional
from api_fuzzer.core.client import PlaywrightClient
from api_fuzzer.core.parser import Endpoint
from api_fuzzer.modules.base import BaseSecurityModule
from api_fuzzer.modules.rate_limit import RateLimitModule
from api_fuzzer.modules.idor import IDORModule
from api_fuzzer.modules.logic_breaking import LogicBreakingModule

class AttackSimulatorRunner:
    def __init__(self, target_url: str, endpoints: List[Endpoint], extra_headers: Optional[Dict[str, str]] = None, auth_token: Optional[str] = None, auth_cookies: Optional[list] = None):
        self.target_url = target_url
        self.endpoints = endpoints
        self.extra_headers = extra_headers or {}
        self.auth_token = auth_token
        self.auth_cookies = auth_cookies
        # Load active modules
        self.modules: List[BaseSecurityModule] = [
            RateLimitModule(),
            IDORModule(),
            LogicBreakingModule()
        ]

    async def run_all(self) -> List[Dict[str, Any]]:
        """Orchestrates test executions across all registered vulnerability modules."""
        all_findings = []
        
        async with PlaywrightClient(base_url=self.target_url, extra_headers=self.extra_headers, auth_token=self.auth_token, auth_cookies=self.auth_cookies) as client:
            for module in self.modules:
                print(f"[+] Iniciando módulo: {module.name}...")
                try:
                    findings = await module.run_test(client, self.endpoints)
                    print(f"[+] Módulo '{module.name}' finalizado com {len(findings)} vulnerabilidades encontradas.")
                    all_findings.extend(findings)
                except Exception as e:
                    print(f"[-] Erro ao executar módulo {module.name}: {str(e)}")
                    
        return all_findings
