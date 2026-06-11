from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse
import json

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class MockVulnerableAPI(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress server logging to keep CLI output clean
        return

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        # Rota protegida por autenticação dinâmica
        if path == "/api/protected":
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer MOCK_VALID_TOKEN"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"secret_data": "Este é um dado super secreto protegido por autenticação."}).encode())
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unauthorized. Bearer token ausente ou inválido."}).encode())
            return

        # UI de Login (HTML) para o Playwright preencher
        if path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = """
            <html><body>
                <form method="POST" action="/api/login">
                    <input type="text" name="username" placeholder="Usuário" id="username">
                    <input type="password" name="password" placeholder="Senha" id="password">
                    <button type="submit">Entrar</button>
                </form>
            </body></html>
            """
            self.wfile.write(html.encode())
            return

        # Simulating IDOR & Logic Breaking Fuzzing on /api/users/{id}
        if path.startswith("/api/users/"):
            user_id = path.split("/")[-1]
            
            # Check for logic breaking payloads in query params (like SQL injection characters)
            filter_val = query.get("filter", [""])[0]
            if "'" in filter_val or "OR" in filter_val or "ls" in filter_val:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {
                    "error": "Internal Server Error",
                    "details": "sqlite3.OperationalError: near \"'\": syntax error in SELECT * FROM users WHERE filter = " + filter_val
                }
                self.wfile.write(json.dumps(response).encode())
                return

            # Normal behavior (Vulnerable to IDOR, returns any user without auth validation)
            if user_id.isdigit():
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {
                    "user_id": int(user_id),
                    "username": f"user_profile_{user_id}",
                    "email": f"user{user_id}@example.com",
                    "secret_note": f"Esta e uma nota secreta privada do usuario {user_id}."
                }
                self.wfile.write(json.dumps(response).encode())
                return
            else:
                self.send_response(404)
                self.end_headers()
                return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Simulating Authentication endpoint returning a token
        if path == "/api/login":
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body_data = self.rfile.read(content_length).decode('utf-8')
                try:
                    body_json = json.loads(body_data)
                    # Vulnerability: Crash Se contiver aspa simples no username (simula falha de escape JSON/SQL)
                    if "'" in body_json.get("username", ""):
                        self.send_response(500)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "Internal Server Error", "trace": "SQL syntax error near '''"}).encode())
                        return
                except Exception:
                    pass

            # For simplicity, we just return a valid token unconditionally
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"status": "success", "message": "Logado com sucesso!", "access_token": "MOCK_VALID_TOKEN_123"}
            self.wfile.write(json.dumps(response).encode())
            return

        self.send_response(404)
        self.end_headers()

def run(port=8000):
    server_address = ('', port)
    httpd = ThreadingHTTPServer(server_address, MockVulnerableAPI)
    print(f"[+] Servidor vulneravel de testes rodando na porta {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Parando servidor...")
        httpd.server_close()

if __name__ == "__main__":
    run()
