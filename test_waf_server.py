"""Local test WAF server that mimics realistic WAF behavior.

Blocks some attacks, passes others, and handles benign traffic correctly.
This gives realistic scan results for report generation.
"""

import re
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse, parse_qs

# Attack patterns the WAF blocks (realistic WAF rules)
BLOCK_PATTERNS = [
    # XSS
    re.compile(r'<script', re.I),
    re.compile(r'onerror\s*=', re.I),
    re.compile(r'onload\s*=', re.I),
    re.compile(r'onmouse', re.I),
    re.compile(r'onfocus', re.I),
    re.compile(r'onclick', re.I),
    re.compile(r'javascript:', re.I),
    re.compile(r'alert\s*\(', re.I),
    re.compile(r'confirm\s*\(', re.I),
    re.compile(r'prompt\s*\(', re.I),
    re.compile(r'document\.domain', re.I),
    re.compile(r'document\.cookie', re.I),
    # SQLi
    re.compile(r'union\s+select', re.I),
    re.compile(r"'\s*or\s+\d+=\d+", re.I),
    re.compile(r'information_schema', re.I),
    re.compile(r'sleep\s*\(', re.I),
    re.compile(r'pg_sleep', re.I),
    re.compile(r'waitfor\s+delay', re.I),
    # RCE
    re.compile(r'/etc/passwd', re.I),
    re.compile(r'/bin/(cat|sh|bash)', re.I),
    re.compile(r'cmd\.exe', re.I),
    re.compile(r'\bping\b.*127\.0\.0\.1', re.I),
    re.compile(r'curl\s+', re.I),
    # LFI/Path Traversal
    re.compile(r'\.\./\.\./\.\./'),
    re.compile(r'\.\.\\\.\.\\'),
    # XXE
    re.compile(r'<!ENTITY', re.I),
    re.compile(r'SYSTEM\s+"file:', re.I),
    # LDAP
    re.compile(r'\(\|', re.I),
    re.compile(r'\)\(\|', re.I),
    # Shell injection
    re.compile(r';\s*(ls|cat|id|whoami|wget|curl)', re.I),
    re.compile(r'\|\s*(ls|cat|id|whoami)', re.I),
    re.compile(r'`.*`'),
    re.compile(r'\$\(.*\)'),
    # SSI
    re.compile(r'<!--#', re.I),
    # SSTI
    re.compile(r'\{\{.*\}\}'),
    re.compile(r'\{%.*%\}'),
]

# Patterns the WAF intentionally does NOT block (bypass scenarios for realism)
BYPASS_PATTERNS = [
    re.compile(r'autof<x>ocus', re.I),  # obfuscated XSS
    re.compile(r'confirm\.call', re.I),  # indirect call
    re.compile(r'alert\.apply', re.I),   # indirect apply
    re.compile(r'__proto__', re.I),      # prototype pollution
    re.compile(r'setInterval', re.I),    # timer-based XSS
]

REQUEST_COUNT = 0

class WAFHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def _handle(self):
        global REQUEST_COUNT
        REQUEST_COUNT += 1

        # Collect all request data for inspection
        full_request = unquote(self.path)
        for header, value in self.headers.items():
            full_request += f" {header}: {value}"

        # Read body if present
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            body = self.rfile.read(content_length).decode('utf-8', errors='replace')
            full_request += f" BODY: {body}"

        # Check for bypass patterns first (WAF weakness simulation)
        for pattern in BYPASS_PATTERNS:
            if pattern.search(full_request):
                self._send_response(200, "OK - Passed through WAF")
                return

        # Check for block patterns
        for pattern in BLOCK_PATTERNS:
            if pattern.search(full_request):
                self._send_response(403, "Forbidden - Blocked by WAF")
                return

        # Normal traffic passes
        self._send_response(200, "OK")

    def _send_response(self, code, message):
        import html as html_mod
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Server', 'TestWAF/1.0')
        self.end_headers()
        body = f"<html><body><h1>{code} {html_mod.escape(message)}</h1></body></html>"
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        # Suppress request logging noise
        pass

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(('127.0.0.1', port), WAFHandler)
    print(f"Test WAF server running on http://127.0.0.1:{port}")
    print(f"Block patterns: {len(BLOCK_PATTERNS)} rules")
    print(f"Known bypass patterns: {len(BYPASS_PATTERNS)} (simulated WAF weaknesses)")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\nTotal requests handled: {REQUEST_COUNT}")
        server.server_close()
