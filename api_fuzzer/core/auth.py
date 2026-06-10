import asyncio
import json
from typing import Dict, Optional, Tuple
from playwright.async_api import async_playwright

class DynamicAuthenticator:
    def __init__(self, login_url: str, username: str, password: str, auth_type: str = "bearer"):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.auth_type = auth_type.lower() # "bearer" or "cookie"
        self.extracted_token: Optional[str] = None
        self.cookies_state: Optional[list] = None

    async def _intercept_response(self, response):
        """Intercepts responses during login to extract JSON tokens."""
        if self.auth_type == "bearer" and response.status in [200, 201]:
            try:
                # Many APIs return a JSON with token/access_token
                if "application/json" in response.headers.get("content-type", ""):
                    body = await response.json()
                    # Try to extract common token keys
                    for key in ["token", "access_token", "jwt", "bearer"]:
                        if key in body:
                            self.extracted_token = str(body[key])
                            print(f"[+] Token '{key}' capturado com sucesso na resposta de {response.url}!")
                            break
            except Exception:
                pass

    async def execute_login(self) -> Tuple[Optional[str], Optional[list]]:
        """
        Executes an automated browser flow to log in.
        Returns a tuple: (Bearer Token String or None, Playwright Cookie State List or None)
        """
        print(f"[*] Iniciando navegador headless para autenticação em: {self.login_url}")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # Se estivermos procurando um bearer token em respostas de rede
            if self.auth_type == "bearer":
                page.on("response", self._intercept_response)

            try:
                await page.goto(self.login_url, wait_until="networkidle")

                # Try to find user field (text, email or generic input)
                user_selectors = [
                    "input[type='email']", 
                    "input[type='text']", 
                    "input[name='username']", 
                    "input[name='email']", 
                    "input[id='username']"
                ]
                
                # Try to find password field
                pass_selectors = [
                    "input[type='password']", 
                    "input[name='password']", 
                    "input[id='password']"
                ]

                # Fill User
                user_filled = False
                for sel in user_selectors:
                    elements = await page.locator(sel).all()
                    if elements:
                        await elements[0].fill(self.username)
                        user_filled = True
                        break

                # Fill Password
                pass_filled = False
                for sel in pass_selectors:
                    elements = await page.locator(sel).all()
                    if elements:
                        await elements[0].fill(self.password)
                        pass_filled = True
                        break

                if not user_filled or not pass_filled:
                    print("[-] Aviso: Não foi possível localizar os campos de usuário/senha na página.")

                # Try to click Submit/Login Button
                button_selectors = [
                    "button[type='submit']",
                    "input[type='submit']",
                    "button:has-text('Login')",
                    "button:has-text('Entrar')",
                    "button:has-text('Sign In')"
                ]

                for sel in button_selectors:
                    elements = await page.locator(sel).all()
                    if elements:
                        # Wait for navigation/network after click
                        async with page.expect_navigation(wait_until="networkidle", timeout=5000):
                            await elements[0].click()
                        break

                # Fallback: se não tiver navigation event (SPA puras), aguardamos 2 segundos
                await page.wait_for_timeout(2000)

                # Se a extração for baseada em Cookie
                if self.auth_type == "cookie":
                    self.cookies_state = await context.cookies()
                    print(f"[+] Foram capturados {len(self.cookies_state)} cookies da sessão de login.")

                # Fallback para Bearer: ler do LocalStorage
                if self.auth_type == "bearer" and not self.extracted_token:
                    # Execute JS in browser to dump local storage
                    ls_data = await page.evaluate("() => JSON.stringify(localStorage)")
                    ls_dict = json.loads(ls_data)
                    for k, v in ls_dict.items():
                        if "token" in k.lower() or "jwt" in k.lower():
                            # clean up quotes if it's a raw string stored as JSON
                            clean_v = v.strip('"')
                            self.extracted_token = clean_v
                            print(f"[+] Token recuperado do localStorage: chave '{k}'.")
                            break

            except Exception as e:
                print(f"[-] Erro durante a automação do login: {str(e)}")
            finally:
                await browser.close()

        return self.extracted_token, self.cookies_state
