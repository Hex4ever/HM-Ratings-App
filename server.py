#!/usr/bin/env python3
"""Simple backend for secured Google auth and static page serving.

This server keeps access-control data out of frontend source code.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parent
INDEX_FILE = ROOT_DIR / "index.html"

SESSION_COOKIE_NAME = "hm_session"
DEFAULT_GOOGLE_TOKENINFO_URLS = [
    "https://oauth2.googleapis.com/tokeninfo",
    "https://www.googleapis.com/oauth2/v3/tokeninfo",
]


def normalize_email(value: str | None) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def is_valid_email(value: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value))


def parse_email_list(raw: str) -> list[str]:
    emails = [normalize_email(part) for part in raw.split(",")]
    unique: list[str] = []
    for email in emails:
        if is_valid_email(email) and email not in unique:
            unique.append(email)
    return unique


def parse_url_list(raw: str) -> list[str]:
    values = [part.strip() for part in raw.split(",")]
    cleaned: list[str] = []
    for value in values:
        if value.startswith("https://") and value not in cleaned:
            cleaned.append(value)
    return cleaned


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env_file(ROOT_DIR / ".env")

SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "43200"))  # 12 hours
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
HAPPINESS_MANAGER_EMAIL = normalize_email(os.getenv("HAPPINESS_MANAGER_EMAIL", ""))
TEAM_SIZE = int(os.getenv("TEAM_SIZE", "13"))
GOOGLE_TOKENINFO_URLS = parse_url_list(os.getenv("GOOGLE_TOKENINFO_URLS", ""))
if not GOOGLE_TOKENINFO_URLS:
    GOOGLE_TOKENINFO_URLS = list(DEFAULT_GOOGLE_TOKENINFO_URLS)

_raw_allowed = parse_email_list(os.getenv("ALLOWED_VOTER_EMAILS", ""))
ALLOWED_VOTER_EMAILS = [email for email in _raw_allowed if email != HAPPINESS_MANAGER_EMAIL]

SESSIONS: dict[str, dict[str, Any]] = {}


def resolve_role(email: str) -> str:
    if is_valid_email(HAPPINESS_MANAGER_EMAIL) and email == HAPPINESS_MANAGER_EMAIL:
        return "manager"
    if email in ALLOWED_VOTER_EMAILS:
        return "voter"
    return ""


def build_user_payload(email: str, role: str) -> dict[str, Any]:
    return {
        "email": email,
        "role": role,
        "teamVoterEmails": ALLOWED_VOTER_EMAILS,
        "teamSize": TEAM_SIZE,
    }


def verify_google_id_token(id_token: str) -> tuple[str, str]:
    if not GOOGLE_CLIENT_ID:
        raise RuntimeError("GOOGLE_CLIENT_ID is not configured on server.")

    payload = fetch_google_tokeninfo(id_token)

    audience = str(payload.get("aud", ""))
    authorized_party = str(payload.get("azp", ""))
    if audience != GOOGLE_CLIENT_ID and authorized_party != GOOGLE_CLIENT_ID:
        raise PermissionError("Token audience mismatch.")

    email = normalize_email(payload.get("email"))
    email_verified = str(payload.get("email_verified", "")).lower() == "true"
    if not email_verified or not is_valid_email(email):
        raise PermissionError("Google account email is not verified.")

    exp_raw = payload.get("exp")
    if exp_raw is not None:
        try:
            if int(exp_raw) <= int(time.time()):
                raise PermissionError("Google token has expired.")
        except ValueError:
            raise PermissionError("Google token is invalid.")

    role = resolve_role(email)
    if not role:
        raise PermissionError("This email is not allowed to access this app.")

    return email, role


def fetch_google_tokeninfo(id_token: str) -> dict[str, Any]:
    network_failures: list[str] = []

    for base_url in GOOGLE_TOKENINFO_URLS:
        query = urllib.parse.urlencode({"id_token": id_token})
        url = f"{base_url}?{query}"
        request = urllib.request.Request(url, headers={"Accept": "application/json"})

        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in {400, 401}:
                raise PermissionError("Google rejected this login token.") from exc
            network_failures.append(f"{base_url} responded with HTTP {exc.code}.")
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                network_failures.append(
                    "SSL certificate verification failed when contacting Google. "
                    "If you are on macOS with python.org Python, run Install Certificates.command."
                )
            elif isinstance(reason, ssl.SSLError):
                network_failures.append(f"SSL error from {base_url}: {reason}.")
            else:
                network_failures.append(f"Network error from {base_url}: {reason}.")
        except TimeoutError:
            network_failures.append(f"Timeout while contacting {base_url}.")

    if not network_failures:
        raise RuntimeError("Could not verify Google token due to unknown network failure.")

    raise RuntimeError(
        "Could not reach Google token verification service. "
        + " ".join(network_failures)
    )


def cleanup_sessions() -> None:
    now = time.time()
    expired = [sid for sid, data in SESSIONS.items() if data.get("expires_at", 0) <= now]
    for sid in expired:
        SESSIONS.pop(sid, None)


def create_session(email: str, role: str) -> str:
    cleanup_sessions()
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = {
        "email": email,
        "role": role,
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    return session_id


def get_session(session_id: str) -> dict[str, Any] | None:
    cleanup_sessions()
    data = SESSIONS.get(session_id)
    if not data:
        return None
    if data.get("expires_at", 0) <= time.time():
        SESSIONS.pop(session_id, None)
        return None
    return data


def clear_session(session_id: str) -> None:
    if session_id:
        SESSIONS.pop(session_id, None)


def make_session_cookie(session_id: str) -> str:
    parts = [
        f"{SESSION_COOKIE_NAME}={session_id}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        f"Max-Age={SESSION_TTL_SECONDS}",
    ]
    if COOKIE_SECURE:
        parts.append("Secure")
    return "; ".join(parts)


def make_cleared_session_cookie() -> str:
    parts = [
        f"{SESSION_COOKIE_NAME}=",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=0",
    ]
    if COOKIE_SECURE:
        parts.append("Secure")
    return "; ".join(parts)


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(ROOT_DIR), **kwargs)

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path

        if path == "/":
            self._serve_index()
            return
        if path == "/auth/config":
            self._send_json(
                HTTPStatus.OK,
                {
                    "googleClientId": GOOGLE_CLIENT_ID,
                    "teamSize": TEAM_SIZE,
                },
            )
            return
        if path == "/auth/me":
            user = self._get_authenticated_user()
            if not user:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Not signed in."})
                return
            self._send_json(HTTPStatus.OK, {"user": user})
            return
        if path == "/health":
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        super().do_GET()

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path

        if path == "/auth/google":
            self._handle_google_signin()
            return
        if path == "/auth/logout":
            self._handle_logout()
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def _handle_google_signin(self) -> None:
        payload = self._read_json()
        credential = str(payload.get("credential", "")).strip()
        if not credential:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing Google credential."})
            return

        try:
            email, role = verify_google_id_token(credential)
        except PermissionError as exc:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
            return
        except RuntimeError as exc:
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return

        session_id = create_session(email, role)
        user = build_user_payload(email, role)
        self._send_json(
            HTTPStatus.OK,
            {"user": user},
            extra_headers={"Set-Cookie": make_session_cookie(session_id)},
        )

    def _handle_logout(self) -> None:
        sid = self._read_session_id()
        clear_session(sid)
        self._send_json(
            HTTPStatus.OK,
            {"ok": True},
            extra_headers={"Set-Cookie": make_cleared_session_cookie()},
        )

    def _serve_index(self) -> None:
        try:
            content = INDEX_FILE.read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "index.html not found")
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _get_authenticated_user(self) -> dict[str, Any] | None:
        sid = self._read_session_id()
        if not sid:
            return None
        data = get_session(sid)
        if not data:
            return None
        email = normalize_email(data.get("email"))
        role = str(data.get("role", ""))
        if role not in {"manager", "voter"} or not is_valid_email(email):
            clear_session(sid)
            return None
        return build_user_payload(email, role)

    def _read_session_id(self) -> str:
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return ""
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            return ""
        morsel = cookie.get(SESSION_COOKIE_NAME)
        return morsel.value if morsel else ""

    def _read_json(self) -> dict[str, Any]:
        content_length = self.headers.get("Content-Length")
        if not content_length:
            return {}
        try:
            length = int(content_length)
        except ValueError:
            return {}
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}

    def _send_json(
        self,
        status: HTTPStatus,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    host = os.getenv("HOST", "localhost")
    port = int(os.getenv("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"Serving on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
