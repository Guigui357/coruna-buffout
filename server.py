#!/usr/bin/env python3
import http.server
import socketserver
import json

PORT = 1337

class MyHandler(http.server.SimpleHTTPRequestHandler):
    # Override to suppress default logging
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        if self.path == "/log":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
                message = data.get("message")
                if message:
                    print(f"[LOG] {message}")
                    self.send_response(200)
                    self.end_headers()
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"No 'message' field provided\n")
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid JSON\n")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found\n")

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
        print(f"Serving HTTP on 0.0.0.0 port {PORT} (http://localhost:{PORT}/) ...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")
