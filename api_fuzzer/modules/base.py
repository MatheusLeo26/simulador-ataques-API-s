from abc import ABC, abstractmethod
from typing import Any, Dict, List
from api_fuzzer.core.parser import Endpoint
from api_fuzzer.core.client import PlaywrightClient

class BaseSecurityModule(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the module's name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Returns the module's description."""
        pass

    @abstractmethod
    async def run_test(
        self, 
        client: PlaywrightClient, 
        endpoints: List[Endpoint]
    ) -> List[Dict[str, Any]]:
        """Runs the security test checks on the provided endpoints.
        
        Returns:
            A list of findings. Each finding is a dictionary containing details
            about the vulnerability found (severity, description, request/response payload, etc.)
        """
        pass
