import asyncio
import contextlib
import io
import json
import os
import sys
import uuid
import logging
import jwt
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Depends, Cookie, Header, Response
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from passlib.context import CryptContext

# Ensure path is set
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="API Security Fuzzer Dashboard")

# Configuração restrita de CORS para evitar conexões maliciosas externas
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Middleware de segurança global (Headers de Segurança, CSP e Bloqueio de Source Maps/Arquivos de Origem)
@app.middleware("http")
async def apply_security_policies(request: Request, call_next):
    path = request.url.path.lower()
    # Proteção de Source Maps e códigos fonte de frontend (caso compilados/gerados)
    if any(path.endswith(ext) for ext in [".map", ".ts", ".tsx", ".jsx", ".vue", ".svelte"]):
        raise HTTPException(status_code=403, detail="Acesso restrito a arquivos de código fonte e source maps")

    response = await call_next(request)
    
    # Cabeçalho CSP (Content Security Policy) robusto
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' http://localhost:8080 http://127.0.0.1:8080; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "object-src 'none';"
    )
    # Proteção de tipos mime e frames
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Global storage for scan states
scans: Dict[str, Dict[str, Any]] = {}

# Auth Configuration
SECRET_KEY = os.environ.get("JWT_SECRET", "super-secret-key-dev")
ALGORITHM = "HS256"
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
# bcrypt hash for "admin123" by default
ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH", "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjIQqiRQYq")
API_KEY_SECRET = os.environ.get("API_KEY", "minha-chave-api-secreta")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger = logging.getLogger("api_fuzzer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

class LoginData(BaseModel):
    username: str
    password: str

async def verify_access(
    access_token: Optional[str] = Cookie(None),
    x_api_key: Optional[str] = Header(None)
):
    # 1. Kill Switch
    if os.environ.get("SISTEMA_BLOQUEADO", "false").lower() == "true":
        logger.warning("Acesso negado: SISTEMA_BLOQUEADO está ativo.")
        raise HTTPException(status_code=403, detail="Sistema bloqueado emergencialmente.")

    # 2. API Key para Automações
    if x_api_key and x_api_key == API_KEY_SECRET:
        return "api_key_user"

    # 3. JWT via HttpOnly Cookie para Interface Humana
    if not access_token:
        raise HTTPException(status_code=401, detail="Não autenticado. Faça login.")
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Sessão expirada. Faça login novamente.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Sessão inválida.")

class ScanConfig(BaseModel):
    target_url: str
    openapi_spec: Optional[Dict[str, Any]] = None
    openapi_url: Optional[str] = None
    auth_type: str
    auth_url: Optional[str] = None
    auth_user: Optional[str] = None
    auth_pass: Optional[str] = None

class QueueIO(io.StringIO):
    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self.queue = queue
        self.loop = loop

    def write(self, s: str) -> int:
        if s.strip():
            self.loop.call_soon_threadsafe(
                self.queue.put_nowait,
                {"type": "log", "message": s.strip(), "level": "info"}
            )
        return len(s)

async def run_scan_task(scan_id: str, config: ScanConfig, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    try:
        from api_fuzzer.core.parser import OpenAPIParser
        from api_fuzzer.core.auth import DynamicAuthenticator
        from api_fuzzer.core.runner import AttackSimulatorRunner
        from api_fuzzer.core.client import PlaywrightClient
        
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"type": "log", "message": "[+] Carregando especificação OpenAPI...", "level": "success"}
        )
        
        openapi_data = config.openapi_spec
        if config.openapi_url:
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {"type": "log", "message": f"[*] Baixando especificação OpenAPI de: {config.openapi_url}", "level": "info"}
            )
            import urllib.request
            try:
                req = urllib.request.Request(config.openapi_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req) as response:
                    openapi_data = json.loads(response.read().decode())
            except Exception as e:
                logger.error(f"Erro ao baixar OpenAPI da URL {config.openapi_url}: {e}", exc_info=True)
                raise Exception("Falha ao carregar OpenAPI da URL. Verifique os logs.")
                
        if not openapi_data:
            raise Exception("Nenhuma especificação OpenAPI fornecida (via arquivo ou URL).")
        
        spec_parser = OpenAPIParser(openapi_data)
        endpoints = spec_parser.get_endpoints()
        
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"type": "log", "message": f"[+] Total de endpoints mapeados: {len(endpoints)}", "level": "success"}
        )
        
        for ep in endpoints:
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {"type": "log", "message": f"  - {ep.method} {ep.path}", "level": "info"}
            )

        auth_token = None
        auth_cookies = None
        
        if config.auth_url and config.auth_user and config.auth_pass and config.auth_type != "none":
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {"type": "log", "message": "[*] Iniciando Autenticação Dinâmica via Playwright...", "level": "info"}
            )
            
            q_io = QueueIO(queue, loop)
            with contextlib.redirect_stdout(q_io):
                authenticator = DynamicAuthenticator(
                    config.auth_url, config.auth_user, config.auth_pass, config.auth_type
                )
                auth_token, auth_cookies = await authenticator.execute_login()

        # Initialize the Runner with parameters
        runner = AttackSimulatorRunner(
            target_url=config.target_url,
            endpoints=endpoints,
            auth_token=auth_token,
            auth_cookies=auth_cookies
        )
        
        all_findings = []
        q_io = QueueIO(queue, loop)
        
        with contextlib.redirect_stdout(q_io):
            async with PlaywrightClient(
                base_url=runner.target_url, 
                extra_headers=runner.extra_headers, 
                auth_token=runner.auth_token, 
                auth_cookies=runner.auth_cookies
            ) as client:
                for module in runner.modules:
                    logger.info(f"Iniciando módulo: {module.name}")
                    try:
                        findings = await module.run_test(client, runner.endpoints)
                        logger.info(f"Módulo '{module.name}' finalizado com {len(findings)} vulnerabilidades.")
                        all_findings.extend(findings)
                        
                        # Stream intermediate progress stats and findings
                        loop.call_soon_threadsafe(
                            queue.put_nowait,
                            {
                                "type": "progress",
                                "scanned_endpoints": len(endpoints),
                                "findings": all_findings
                            }
                        )
                    except Exception as e:
                        logger.error(f"Erro ao executar módulo {module.name}: {str(e)}", exc_info=True)

        scans[scan_id] = {
            "status": "complete",
            "findings": all_findings,
            "scanned_endpoints": len(endpoints)
        }
        
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {
                "type": "complete",
                "scanned_endpoints": len(endpoints),
                "findings": all_findings
            }
        )

    except Exception as e:
        logger.error(f"Erro interno no fuzzer: {str(e)}", exc_info=True)
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"type": "error", "message": "Ocorreu um erro interno ao processar a varredura. Consulte os logs."}
        )

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="index.html template not found")
    with open(index_path, "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/auth/login")
async def login(data: LoginData, response: Response):
    if data.username != ADMIN_USER or not pwd_context.verify(data.password, ADMIN_PASS_HASH):
        logger.warning(f"Tentativa de login falha para usuário: {data.username}")
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    
    expires = datetime.utcnow() + timedelta(hours=4)
    token = jwt.encode({"sub": data.username, "exp": expires}, SECRET_KEY, algorithm=ALGORITHM)
    
    # Secure Cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True, # Garante que só viaja em HTTPS (ou localhost no Chrome)
        samesite="lax",
        max_age=14400
    )
    logger.info(f"Usuário {data.username} logado com sucesso.")
    return {"message": "Login efetuado com sucesso"}

@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Sessão encerrada"}

@app.get("/api/auth/me", dependencies=[Depends(verify_access)])
async def me():
    return {"status": "authenticated"}

@app.post("/api/scan/start", dependencies=[Depends(verify_access)])
async def start_scan(config: ScanConfig):
    scan_id = str(uuid.uuid4())
    event_queue = asyncio.Queue()
    loop = asyncio.get_running_loop()
    
    scans[scan_id] = {
        "status": "running",
        "queue": event_queue,
        "config": config,
        "task": asyncio.create_task(run_scan_task(scan_id, config, event_queue, loop))
    }
    return {"scan_id": scan_id}

@app.get("/api/scan/stream/{scan_id}", dependencies=[Depends(verify_access)])
async def stream_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Sessão de varredura não encontrada")
    
    scan_session = scans[scan_id]
    queue = scan_session.get("queue")
    
    if not queue:
        raise HTTPException(status_code=400, detail="Essa varredura já foi concluída ou não possui stream ativo")

    async def event_generator():
        while True:
            try:
                event = await queue.get()
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ["complete", "error"]:
                    # Clean up queue to prevent memory leak
                    if "queue" in scans[scan_id]:
                        del scans[scan_id]["queue"]
                    break
            except asyncio.CancelledError:
                break

    return StreamingResponse(event_generator(), media_type="text/event-stream")

def main():
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    import uvicorn
    print("[+] Iniciando Painel do Fuzzer em http://localhost:8080")
    uvicorn.run(app, host="127.0.0.1", port=8080)

if __name__ == "__main__":
    main()
