#!/usr/bin/env python3
"""
Simple HTTP server to capture OAuth callback
Writes the authorization code to a file and exits
"""
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Output file path passed as first argument
OUTPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else '/tmp/oidc-callback.txt'

class CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def do_GET(self):
        # Parse the callback URL
        parsed = urlparse(self.path)

        if parsed.path == '/callback':
            # Extract query parameters
            params = parse_qs(parsed.query)
            code = params.get('code', [None])[0]
            state = params.get('state', [None])[0]

            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>Authentication successful!</h1><p>You can close this window.</p></body></html>')

            # Write code and state to file
            if code and state:
                with open(OUTPUT_FILE, 'w') as f:
                    f.write(f"{code}\n{state}\n")

            # Shutdown server after handling callback
            def shutdown_server():
                self.server.shutdown()

            import threading
            threading.Thread(target=shutdown_server).start()
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    server = HTTPServer(('localhost', 8400), CallbackHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
