import asyncio
from typing import Any, Dict, Optional, Tuple
from playwright.async_api import async_playwright, APIRequestContext

class PlaywrightClient:
    def __init__(self, base_url: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None, auth_token: Optional[str] = None, auth_cookies: Optional[list] = None):
        self.base_url = base_url
        self.extra_headers = extra_headers or {}
        if auth_token:
            self.extra_headers["Authorization"] = f"Bearer {auth_token}"
        self.auth_cookies = auth_cookies
        self._playwright = None
        self._request_context: Optional[APIRequestContext] = None

    async def __aenter__(self):
        self._playwright = await async_playwright().start()
        self._request_context = await self._playwright.request.new_context(
            base_url=self.base_url,
            extra_http_headers=self.extra_headers
        )
        # Apply cookies if provided
        if self.auth_cookies:
            # Not supported natively without a browser context for storage state,
            # but we can format cookies into the Cookie header or set them in the context
            # Let's map the cookies to the domain or format as header
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.auth_cookies])
            self.extra_headers["Cookie"] = cookie_str
            # Reload context with updated headers
            await self._request_context.dispose()
            self._request_context = await self._playwright.request.new_context(
                base_url=self.base_url,
                extra_http_headers=self.extra_headers
            )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._request_context:
            await self._request_context.dispose()
        if self._playwright:
            await self._playwright.stop()

    async def send_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Any] = None,
        timeout: float = 10000.0  # in ms
    ) -> Tuple[int, Dict[str, str], str]:
        """Sends an HTTP request using Playwright's APIRequestContext."""
        if not self._request_context:
            raise RuntimeError("Client not initialized. Use async context manager 'async with'.")

        options = {}
        if params:
            options["params"] = {k: str(v) for k, v in params.items()}
        if headers:
            options["headers"] = headers
        if json_data is not None:
            options["data"] = json_data
        
        options["timeout"] = timeout

        try:
            # Playwright APIRequestContext methods are lowercased (e.g. context.get, context.post)
            request_fn = getattr(self._request_context, method.lower())
            response = await request_fn(url, **options)
            
            status = response.status
            resp_headers = response.headers
            
            # Retrieve response text safely
            try:
                resp_text = await response.text()
            except Exception:
                resp_text = ""
                
            return status, resp_headers, resp_text
        except Exception as e:
            # Return status code 0 to indicate system/connection error
            return 0, {}, f"Request failed: {str(e)}"
