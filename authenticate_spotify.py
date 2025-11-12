#!/usr/bin/env python3
"""
Standalone Spotify Authentication Script

Run this directly to authenticate with Spotify before using the MCP server.
This provides visible feedback during the OAuth flow.

Usage:
    python authenticate_spotify.py
"""

import base64
import http.server
import json
import os
import socketserver
import sys
import threading
import time
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import requests
import yaml

try:
    from cryptography.fernet import Fernet

    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("[WARNING] cryptography not available - tokens will be stored unencrypted")

SPOTIFY_AUTH_URL = "https://accounts.spotify.com/authorize"
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"

_auth_code_received = None
_encryption_key = None


class CallbackHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global _auth_code_received
        if self.path.startswith("/callback"):
            query_params = parse_qs(urlparse(self.path).query)
            if "code" in query_params:
                _auth_code_received = query_params["code"][0]
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                html_response = """
                <html><body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #1DB954;">Authorization Successful!</h1>
                <p>You can now close this window and return to your terminal.</p>
                <script>setTimeout(function(){window.close();}, 3000);</script>
                </body></html>
                """
                self.wfile.write(html_response.encode("utf-8"))
                print("\nAuthorization code received!")
            else:
                self.send_error(400, "Authorization failed")
                print("\nAuthorization failed - no code received")
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass  # Suppress server logs


def load_credentials():
    """Load Spotify credentials from fastagent.secrets.yaml"""
    secrets_file = Path("fastagent.secrets.yaml")
    if not secrets_file.exists():
        print("[ERROR] fastagent.secrets.yaml not found")
        print("\nPlease create it with your Spotify credentials:")
        print("""
spotify:
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  redirect_uri: "http://127.0.0.1:8080/callback"
""")
        sys.exit(1)

    with open(secrets_file, "r", encoding="utf-8") as f:
        secrets = yaml.safe_load(f) or {}

    spotify_config = secrets.get("spotify", {})
    required_keys = ["client_id", "client_secret"]

    for key in required_keys:
        if key not in spotify_config:
            print(f"[ERROR] Missing '{key}' in spotify section of fastagent.secrets.yaml")
            sys.exit(1)

    if "redirect_uri" not in spotify_config:
        spotify_config["redirect_uri"] = "http://127.0.0.1:8080/callback"

    return spotify_config


def get_encryption_key():
    """Get or create encryption key for token storage"""
    global _encryption_key

    if not ENCRYPTION_AVAILABLE:
        return b"dummy_key"

    if _encryption_key:
        return _encryption_key

    key_file = Path(".spotify_key")
    if key_file.exists():
        with open(key_file, "rb") as f:
            _encryption_key = f.read()
            return _encryption_key

    _encryption_key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(_encryption_key)
    os.chmod(key_file, 0o600)

    return _encryption_key


def encrypt_data(data):
    """Encrypt sensitive data"""
    if not ENCRYPTION_AVAILABLE:
        return data

    key = get_encryption_key()
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()


def sanitize_url_for_logging(url):
    """Sanitize URL by redacting sensitive query parameters"""
    try:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            # Redact sensitive parameters
            if 'client_id' in params:
                client_id = params['client_id'][0]
                params['client_id'] = [f"{client_id[:8]}...{client_id[-4:]}"]
            sanitized_query = urlencode({k: v[0] for k, v in params.items()})
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{sanitized_query}"
        return url
    except Exception:
        return "[URL redacted for security]"


def save_tokens(access_token, refresh_token, expires_in):
    """Save tokens to a local cache file"""
    token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)

    token_data = {
        "access_token": encrypt_data(access_token),
        "refresh_token": encrypt_data(refresh_token),
        "expires_at": token_expires_at.isoformat(),
    }

    token_file = Path(".spotify_tokens.json")
    with open(token_file, "w") as f:
        json.dump(token_data, f)
    os.chmod(token_file, 0o600)


def main():
    print("Spotify Authentication Tool")
    print("=" * 50)
    print()

    # Load credentials
    print("Loading credentials...")
    credentials = load_credentials()
    print("[OK] Credentials loaded successfully")
    print()



    # Start local server
    print("Starting local callback server on port 8080...")
    try:
        httpd = socketserver.TCPServer(("127.0.0.1", 8080), CallbackHandler)
    except OSError as e:
        print("[ERROR] Could not start server on port 8080")
        print(f"   {e}")
        print("   Make sure no other process is using this port")
        sys.exit(1)

    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print("[OK] Server started successfully")
    print()

    # Build authorization URL
    scopes = [
        "user-read-playback-state",
        "user-modify-playback-state",
        "user-read-currently-playing",
        "playlist-read-private",
        "playlist-modify-private",
        "playlist-modify-public",
        "user-library-read",
        "user-library-modify",
    ]

    auth_params = {
        "client_id": credentials["client_id"],
        "response_type": "code",
        "redirect_uri": credentials["redirect_uri"],
        "scope": " ".join(scopes),
        "show_dialog": "true",
    }

    auth_url = f"{SPOTIFY_AUTH_URL}?{urlencode(auth_params)}"

    # Open browser
    print("Opening browser for Spotify authorization...")
    print()
    try:
        webbrowser.open(auth_url)
        print("[OK] Browser should open automatically")
    except Exception:
        print("[WARNING] Could not auto-open browser")

    print()
    print("If browser didn't open, please visit:")
    print(f"   {sanitize_url_for_logging(auth_url)}")
    print()
    print("Waiting for authorization (timeout: 120 seconds)...")
    print("   Complete the login in your browser")
    print()

    # Wait for callback
    timeout = 120
    start_time = time.time()

    while _auth_code_received is None and (time.time() - start_time) < timeout:
        elapsed = int(time.time() - start_time)
        if elapsed > 0 and elapsed % 10 == 0:
            remaining = timeout - elapsed
            print(f"   Still waiting... ({remaining}s remaining)")
        time.sleep(1)

    httpd.shutdown()

    if _auth_code_received is None:
        print()
        print("[ERROR] Authentication timed out")
        print()
        print("Please check:")
        print("  1. Browser opened the correct URL")
        print("  2. You completed the login process")
        print("  3. Redirect URI matches in your Spotify app settings")
        sys.exit(1)

    # Exchange code for tokens
    print("Exchanging authorization code for access token...")
    auth_header = base64.b64encode(f"{credentials['client_id']}:{credentials['client_secret']}".encode()).decode()

    headers = {"Authorization": f"Basic {auth_header}", "Content-Type": "application/x-www-form-urlencoded"}

    data = {"grant_type": "authorization_code", "code": _auth_code_received, "redirect_uri": credentials["redirect_uri"]}

    try:
        response = requests.post(SPOTIFY_TOKEN_URL, headers=headers, data=data, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to get access token: {e}")
        sys.exit(1)

    token_data = response.json()
    save_tokens(token_data["access_token"], token_data["refresh_token"], token_data["expires_in"])

    print("[OK] Access token received and saved")
    print()
    print("=" * 50)
    print("Authentication Complete!")
    print()
    print("Your Spotify credentials have been saved and encrypted.")
    print("You can now use the Spotify MCP server in your FastAgent.")
    print()
    print("Available commands:")
    print("  - get_current_track")
    print("  - play_music")
    print("  - pause_music")
    print("  - skip_track")
    print("  - search_music")
    print("  - and more!")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[CANCELLED] Authentication cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
