# keep_alive.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading


def run_server(port: int = 10000):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Bot is running")

    server = HTTPServer(("0.0.0.0", port), Handler)

    # Run in a separate thread so it doesn’t block your bot
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    print(f"Keep-alive server running on port {port}")
