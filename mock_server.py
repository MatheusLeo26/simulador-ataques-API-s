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

        # Simulating Lack of Rate Limiting on login
        if path == "/api/login":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"status": "success", "message": "Logado com sucesso!"}
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
