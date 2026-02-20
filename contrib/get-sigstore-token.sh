#!/usr/bin/env bash
# Get a Sigstore OIDC identity token for use with --sigstore-token.
#
# Usage:
#   ./contrib/get-sigstore-token.sh
#   # Opens browser, prints JWT to stdout after auth.
#
# Then:
#   ./target/release/gleisner-tui --sandbox --sigstore \
#     --sigstore-token "$(./contrib/get-sigstore-token.sh)"

set -euo pipefail

# Use the gleisner binary to do a minimal signing run that triggers OIDC.
# The token gets printed to stderr by the tracing output.
# Alternatively, we can use a small Rust helper.

# For now, use Python + requests to do the OAuth2 device flow.
# Sigstore's Dex instance supports the standard OAuth2 code flow.

CLIENT_ID="sigstore"
AUTH_URL="https://oauth2.sigstore.dev/auth"
REDIRECT_URI="http://localhost:19283/auth/callback"

# Start a temporary HTTP server to receive the callback
TOKEN_FILE=$(mktemp)
trap 'rm -f "$TOKEN_FILE"' EXIT

python3 -c "
import http.server, urllib.parse, urllib.request, json, sys, webbrowser, threading

port = 19283
code_holder = [None]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if 'code' in params:
            code_holder[0] = params['code'][0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'<html><body><h2>Authenticated! You can close this tab.</h2></body></html>')
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Missing code parameter')
    def log_message(self, *args): pass

server = http.server.HTTPServer(('127.0.0.1', port), Handler)

# Open browser
auth_url = '${AUTH_URL}/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=openid+email&nonce=gleisner'
webbrowser.open(auth_url)
print('Waiting for browser authentication...', file=sys.stderr)

# Wait for one request
server.handle_request()

if not code_holder[0]:
    print('ERROR: No auth code received', file=sys.stderr)
    sys.exit(1)

# Exchange code for token
data = urllib.parse.urlencode({
    'grant_type': 'authorization_code',
    'code': code_holder[0],
    'client_id': '${CLIENT_ID}',
    'redirect_uri': '${REDIRECT_URI}',
}).encode()
req = urllib.request.Request('${AUTH_URL}/token', data=data)
resp = urllib.request.urlopen(req)
token_data = json.loads(resp.read())
print(token_data['id_token'])
"
