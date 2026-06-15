import asyncio
import contextlib
import io
import json
import os
import sys
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Ensure path is set
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(title="API Security Fuzzer Dashboard")

# Global storage for scan states
scans: Dict[str, Dict[str, Any]] = {}

class ScanConfig(BaseModel):
    target_url: str
    openapi_spec: Dict[str, Any]
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
        
        spec_parser = OpenAPIParser(config.openapi_spec)
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
                    print(f"[+] Iniciando módulo: {module.name}...")
                    try:
                        findings = await module.run_test(client, runner.endpoints)
                        print(f"[+] Módulo '{module.name}' finalizado com {len(findings)} vulnerabilidades encontradas.")
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
                        print(f"[-] Erro ao executar módulo {module.name}: {str(e)}")

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
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"type": "error", "message": str(e)}
        )

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="index.html template not found")
    with open(index_path, "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/scan/start")
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

@app.get("/api/scan/stream/{scan_id}")
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
