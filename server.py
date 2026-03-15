#!/usr/bin/env python3
"""Backend for secured Google auth and static page serving.

This file exports a Flask ``app`` entrypoint for Vercel Python deployments.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request, send_from_directory
from itsdangerous import BadSignature, URLSafeSerializer


ROOT_DIR = Path(__file__).resolve().parent
INDEX_FILE = ROOT_DIR / "index.html"

SESSION_COOKIE_NAME = "hm_session"
SESSION_SIGNING_SALT = "hm-session-v1"
DEFAULT_GOOGLE_TOKENINFO_URLS = [
    "https://oauth2.googleapis.com/tokeninfo",
    "https://www.googleapis.com/oauth2/v3/tokeninfo",
]
ALLOWED_STATIC_EXTENSIONS = {
    ".css",
    ".gif",
    ".html",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".png",
    ".svg",
    ".txt",
    ".webp",
}


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
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()
TEAM_SIZE = int(os.getenv("TEAM_SIZE", "13"))
GOOGLE_TOKENINFO_URLS = parse_url_list(os.getenv("GOOGLE_TOKENINFO_URLS", ""))
if not GOOGLE_TOKENINFO_URLS:
    GOOGLE_TOKENINFO_URLS = list(DEFAULT_GOOGLE_TOKENINFO_URLS)

_raw_allowed = parse_email_list(os.getenv("ALLOWED_VOTER_EMAILS", ""))
ALLOWED_VOTER_EMAILS = [email for email in _raw_allowed if email != HAPPINESS_MANAGER_EMAIL]

SESSION_SERIALIZER = (
    URLSafeSerializer(SESSION_SECRET, salt=SESSION_SIGNING_SALT) if SESSION_SECRET else None
)


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
        tokeninfo_request = urllib.request.Request(url, headers={"Accept": "application/json"})

        try:
            with urllib.request.urlopen(tokeninfo_request, timeout=12) as response:
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


def get_session_serializer() -> URLSafeSerializer:
    if SESSION_SERIALIZER is None:
        raise RuntimeError("SESSION_SECRET is not configured on server.")
    return SESSION_SERIALIZER


def create_session_token(email: str) -> str:
    serializer = get_session_serializer()
    payload = {
        "email": email,
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
    }
    return serializer.dumps(payload)


def read_session_token(session_token: str) -> tuple[str, str] | None:
    if not session_token:
        return None

    serializer = get_session_serializer()
    try:
        payload = serializer.loads(session_token)
    except BadSignature:
        return None

    if not isinstance(payload, dict):
        return None

    email = normalize_email(payload.get("email"))
    exp_raw = payload.get("exp")

    if not is_valid_email(email):
        return None

    try:
        exp = int(exp_raw)
    except (TypeError, ValueError):
        return None

    if exp <= int(time.time()):
        return None

    role = resolve_role(email)
    if not role:
        return None

    return email, role


def build_json_response(payload: dict[str, Any], status_code: int) -> Response:
    response = jsonify(payload)
    response.status_code = status_code
    response.headers["Cache-Control"] = "no-store"
    return response


def get_authenticated_user() -> dict[str, Any] | None:
    session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    if not session_token:
        return None

    session_data = read_session_token(session_token)
    if not session_data:
        return None

    email, role = session_data
    return build_user_payload(email, role)


app = Flask(__name__, static_folder=None)


@app.get("/")
def serve_index() -> Response:
    if not INDEX_FILE.exists():
        return build_json_response({"error": "index.html not found"}, 404)
    response = send_from_directory(str(ROOT_DIR), "index.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health() -> Response:
    return build_json_response({"ok": True}, 200)


@app.get("/auth/config")
def auth_config() -> Response:
    return build_json_response(
        {
            "googleClientId": GOOGLE_CLIENT_ID,
            "teamSize": TEAM_SIZE,
        },
        200,
    )


@app.get("/auth/me")
def auth_me() -> Response:
    try:
        user = get_authenticated_user()
    except RuntimeError as exc:
        return build_json_response({"error": str(exc)}, 503)

    if not user:
        return build_json_response({"error": "Not signed in."}, 401)
    return build_json_response({"user": user}, 200)


@app.post("/auth/google")
def auth_google() -> Response:
    payload = request.get_json(silent=True) or {}
    credential = str(payload.get("credential", "")).strip()
    if not credential:
        return build_json_response({"error": "Missing Google credential."}, 400)

    try:
        email, role = verify_google_id_token(credential)
    except PermissionError as exc:
        return build_json_response({"error": str(exc)}, 403)
    except RuntimeError as exc:
        return build_json_response({"error": str(exc)}, 503)

    try:
        session_token = create_session_token(email)
    except RuntimeError as exc:
        return build_json_response({"error": str(exc)}, 503)

    user = build_user_payload(email, role)
    response = build_json_response({"user": user}, 200)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="Lax",
        secure=COOKIE_SECURE,
        path="/",
    )
    return response


@app.post("/auth/logout")
def auth_logout() -> Response:
    response = build_json_response({"ok": True}, 200)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        "",
        max_age=0,
        httponly=True,
        samesite="Lax",
        secure=COOKIE_SECURE,
        path="/",
    )
    return response


@app.get("/<path:asset_path>")
def serve_asset(asset_path: str) -> Response:
    filename = Path(asset_path).name
    suffix = Path(asset_path).suffix.lower()
    if filename.startswith(".") or suffix not in ALLOWED_STATIC_EXTENSIONS:
        return build_json_response({"error": "Not found."}, 404)

    full_path = (ROOT_DIR / asset_path).resolve()
    if ROOT_DIR not in full_path.parents and full_path != ROOT_DIR:
        return build_json_response({"error": "Not found."}, 404)
    if not full_path.is_file():
        return build_json_response({"error": "Not found."}, 404)
    return send_from_directory(str(ROOT_DIR), asset_path)


def main() -> None:
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
